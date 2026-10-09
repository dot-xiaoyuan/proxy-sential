package legacy4k

import (
	"context"
	"errors"
	"github.com/redis/go-redis/v9"
	"proxy-sentinel/internal/redisguard"
)

const (
	MaxOnlineFieldBytes      = 4096
	MaxOnlineProjectionBytes = 64 << 20
)

// Resource rejection is not evidence that the source is offline.
var ErrOnlineResourceLimit = errors.New("4K在线身份清单超出资源上限")

type RedisOnlineClient struct{ *redisguard.Client }

// The final atomic validation of 100000 sessions has more than 1.6 million
// elements. Catalog limits cannot be reused for this identity projection.
func NewRedisOnlineClient(options *redis.Options) *RedisOnlineClient {
	return &RedisOnlineClient{Client: redisguard.NewClient(options, redisguard.Limits{
		ReadBytes: 256 << 20, ReplyBytes: 128 << 20, BulkBytes: 64 << 10,
		ReadElements: 4000000, ReplyElements: 2000000, ArrayLength: 100003, Depth: 8, Error: ErrOnlineResourceLimit,
	})}
}

func validateOnlineProjection(rows []map[string]string) error {
	return validateOnlineProjectionContext(context.Background(), rows)
}

func validateOnlineProjectionContext(ctx context.Context, rows []map[string]string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(rows) > 100000 {
		return ErrOnlineResourceLimit
	}
	bytes := 0
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(row) > 64 {
			return ErrOnlineResourceLimit
		}
		for field, value := range row {
			if len(field) > 200 || len(value) > MaxOnlineFieldBytes || len(field)+len(value) > MaxOnlineProjectionBytes-bytes {
				return ErrOnlineResourceLimit
			}
			bytes += len(field) + len(value)
		}
	}
	return ctx.Err()
}
