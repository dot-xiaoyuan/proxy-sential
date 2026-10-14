package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/redis/go-redis/v9"
	"strconv"
	"time"
)

// The field Redis disables scripting. WATCH fences every read used to build the
// transaction; queue movement and its immutable manifest commit together in EXEC.
type batchTransaction string

func (op batchTransaction) Run(ctx context.Context, client *redis.Client, keys []string, args ...interface{}) *redis.Cmd {
	cmd := redis.NewCmd(ctx)
	var result interface{}
	var err error
	for attempt := 0; attempt < 100; attempt++ {
		err = client.Watch(ctx, func(tx *redis.Tx) error {
			value, e := op.run(ctx, tx, keys, args)
			if e == nil {
				result = value
			}
			return e
		}, keys...)
		if !errors.Is(err, redis.TxFailedErr) {
			break
		}
		if err = ctx.Err(); err != nil {
			break
		}
		err = redis.TxFailedErr
	}
	cmd.SetVal(result)
	cmd.SetErr(err)
	return cmd
}
func batchGet(ctx context.Context, tx *redis.Tx, key string) (string, error) {
	v, e := tx.Get(ctx, key).Result()
	if e == redis.Nil {
		return "", nil
	}
	return v, e
}
func batchArgs(values []string) []interface{} {
	out := make([]interface{}, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}
func (op batchTransaction) run(ctx context.Context, tx *redis.Tx, k []string, a []interface{}) (interface{}, error) {
	arg := func(i int) string { return fmt.Sprint(a[i]) }
	switch op {
	case "begin":
		lease, e := batchGet(ctx, tx, k[2])
		if e != nil {
			return nil, e
		}
		if lease != "" {
			return nil, redis.Nil
		}
		epoch, e := tx.Get(ctx, k[3]).Int64()
		if e != nil && e != redis.Nil {
			return nil, e
		}
		epoch++
		token := arg(0) + ":" + strconv.FormatInt(epoch, 10)
		saved, e := batchGet(ctx, tx, k[4])
		if e != nil {
			return nil, e
		}
		size, e := strconv.ParseInt(arg(1), 10, 64)
		if e != nil {
			return nil, e
		}
		moved := false
		var raw []string
		if saved == "" {
			raw, e = tx.LRange(ctx, k[1], 0, size-1).Result()
			if e != nil {
				return nil, e
			}
			if len(raw) == 0 {
				raw, e = tx.LRange(ctx, k[0], 0, size-1).Result()
				moved = true
				if e != nil {
					return nil, e
				}
			}
			if len(raw) > 0 {
				b := reliableBatch{Raw: raw, ObservedAt: arg(2), InstanceID: arg(3), Source: arg(4), SensorID: arg(5), CampusID: arg(6), AccessDomain: arg(7), SourceVersion: arg(8)}
				encoded, e := json.Marshal(b)
				if e != nil {
					return nil, e
				}
				saved = string(encoded)
			}
		}
		_, e = tx.TxPipelined(ctx, func(p redis.Pipeliner) error {
			p.Set(ctx, k[3], epoch, 0)
			if saved != "" {
				p.Set(ctx, k[2], token, 60*time.Second)
				if moved && len(raw) > 0 {
					p.LTrim(ctx, k[0], int64(len(raw)), -1)
					p.RPush(ctx, k[1], batchArgs(raw)...)
				}
				p.Set(ctx, k[4], saved, 0)
			}
			return nil
		})
		return []interface{}{token, saved}, e
	case "release":
		lease, e := batchGet(ctx, tx, k[0])
		if e != nil {
			return nil, e
		}
		if lease != arg(0) {
			return int64(0), nil
		}
		_, e = tx.TxPipelined(ctx, func(p redis.Pipeliner) error { p.Del(ctx, k[0]); return nil })
		return int64(1), e
	case "freeze":
		lease, e := batchGet(ctx, tx, k[0])
		if e != nil {
			return nil, e
		}
		if lease != arg(0) {
			return nil, fmt.Errorf("batch lease expired")
		}
		_, e = tx.TxPipelined(ctx, func(p redis.Pipeliner) error { p.Set(ctx, k[1], arg(1), 0); return nil })
		return int64(1), e
	case "finish":
		lease, e := batchGet(ctx, tx, k[1])
		if e != nil {
			return nil, e
		}
		if lease != arg(0) {
			return nil, fmt.Errorf("batch lease expired")
		}
		saved, e := batchGet(ctx, tx, k[2])
		if e != nil {
			return nil, e
		}
		var b reliableBatch
		if e = json.Unmarshal([]byte(saved), &b); e != nil {
			return nil, e
		}
		if len(b.Raw) == 0 {
			return nil, fmt.Errorf("empty persisted prefix")
		}
		prefix, e := tx.LRange(ctx, k[0], 0, int64(len(b.Raw)-1)).Result()
		if e != nil {
			return nil, e
		}
		if len(prefix) != len(b.Raw) {
			return nil, fmt.Errorf("processing prefix changed")
		}
		for i, v := range prefix {
			if v != b.Raw[i] {
				return nil, fmt.Errorf("processing prefix changed")
			}
		}
		_, e = tx.TxPipelined(ctx, func(p redis.Pipeliner) error {
			if len(a) > 1 {
				p.RPush(ctx, k[3], a[1:]...)
			}
			p.LTrim(ctx, k[0], int64(len(b.Raw)), -1)
			p.Del(ctx, k[1], k[2])
			return nil
		})
		return int64(len(b.Raw)), e
	case "restore":
		pending, e := tx.Exists(ctx, k[2], k[3]).Result()
		if e != nil {
			return nil, e
		}
		if pending > 0 {
			return nil, fmt.Errorf("pending durable batch must be retried without changing its manifest")
		}
		tail, e := tx.LRange(ctx, k[1], -1000, -1).Result()
		if e != nil {
			return nil, e
		}
		if len(tail) == 0 {
			return int64(0), nil
		}
		reversed := make([]interface{}, len(tail))
		for i, v := range tail {
			reversed[len(tail)-1-i] = v
		}
		_, e = tx.TxPipelined(ctx, func(p redis.Pipeliner) error {
			p.LTrim(ctx, k[1], 0, -int64(len(tail))-1)
			p.LPush(ctx, k[0], reversed...)
			return nil
		})
		return int64(len(tail)), e
	}
	return nil, fmt.Errorf("unsupported batch operation")
}
