package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"proxy-sentinel/internal/legacy4k"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	redisAddr := flag.String("redis-addr", os.Getenv("LEGACY_4K_REDIS_ADDR"), "legacy cache Redis address")
	redisPasswordFile := flag.String("redis-password-file", os.Getenv("LEGACY_4K_REDIS_PASSWORD_FILE"), "file containing the Redis password")
	eventList := flag.String("event-list", os.Getenv("LEGACY_4K_EVENT_LIST"), "legacy online/offline event list")
	onlineList := flag.String("online-list", "list:rad_online", "legacy authoritative online-user list")
	endpoint := flag.String("endpoint", os.Getenv("PROXY_SENTINEL_URL"), "Proxy Sentinel control-plane URL")
	tokenFile := flag.String("token-file", os.Getenv("PROXY_SENTINEL_IDENTITY_TOKEN_FILE"), "file containing identity integration token")
	sensorID := flag.String("sensor-id", "legacy-4k", "sensor identifier")
	flag.Parse()
	if *redisAddr == "" || *eventList == "" || *endpoint == "" || *tokenFile == "" {
		return fmt.Errorf("redis-addr, event-list, endpoint and token-file are required")
	}
	password, err := readSecret(*redisPasswordFile, false)
	if err != nil {
		return err
	}
	token, err := readSecret(*tokenFile, true)
	if err != nil {
		return err
	}
	client := redis.NewClient(&redis.Options{Addr: *redisAddr, Password: password})
	defer client.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := client.Ping(ctx).Err(); err != nil {
		return err
	}
	sender := legacy4k.Sender{Endpoint: *endpoint, Token: token, SensorID: *sensorID}
	if err := syncOnline(ctx, client, *onlineList, sender); err != nil {
		return err
	}
	processing := *eventList + ":proxy-sentinel-processing"
	pending, err := client.LRange(ctx, processing, 0, -1).Result()
	if err != nil {
		return err
	}
	for _, raw := range pending {
		record, decodeErr := legacy4k.DecodeRecord(raw, time.Now().UTC())
		if decodeErr != nil {
			if err := quarantineBad(ctx, client, processing, *eventList+":proxy-sentinel-dead", raw); err != nil {
				return err
			}
			continue
		}
		if sendErr := sender.Send(ctx, []map[string]string{record}, legacy4k.StableID(raw)); sendErr != nil {
			return sendErr
		}
		if err := client.LRem(ctx, processing, 1, raw).Err(); err != nil {
			return err
		}
	}
	for {
		raw, err := client.BRPopLPush(ctx, *eventList, processing, 30*time.Second).Result()
		if err == redis.Nil {
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			time.Sleep(time.Second)
			continue
		}
		record, err := legacy4k.DecodeRecord(raw, time.Now().UTC())
		if err != nil {
			if err := quarantineBad(ctx, client, processing, *eventList+":proxy-sentinel-dead", raw); err != nil {
				return err
			}
			continue
		}
		err = sender.Send(ctx, []map[string]string{record}, legacy4k.StableID(raw))
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		if err := client.LRem(ctx, processing, 1, raw).Err(); err != nil {
			return err
		}
	}
}

func syncOnline(ctx context.Context, client *redis.Client, list string, sender legacy4k.Sender) error {
	ids, err := client.LRange(ctx, list, 0, -1).Result()
	if err != nil {
		return err
	}
	records := []map[string]string{}
	batchIndex := 0
	for _, id := range ids {
		fields, readErr := client.HGetAll(ctx, "hash:rad_online:"+id).Result()
		if readErr != nil {
			return readErr
		}
		record, mapErr := legacy4k.RecordFromHash(fields, time.Now().UTC())
		if mapErr == nil {
			records = append(records, record)
		}
		if len(records) == 500 {
			if err := sendOnlineBatch(ctx, sender, records, batchIndex); err != nil {
				return err
			}
			records = nil
			batchIndex++
		}
	}
	return sendOnlineBatch(ctx, sender, records, batchIndex)
}

func sendOnlineBatch(ctx context.Context, sender legacy4k.Sender, records []map[string]string, batchIndex int) error {
	if len(records) == 0 {
		return nil
	}
	identity := make([]map[string]string, 0, len(records))
	for _, record := range records {
		copyRecord := make(map[string]string, len(record))
		for key, value := range record {
			if key != "timestamp" {
				copyRecord[key] = value
			}
		}
		identity = append(identity, copyRecord)
	}
	payload, err := json.Marshal(identity)
	if err != nil {
		return err
	}
	return sender.Send(ctx, records, legacy4k.StableID(string(payload)+fmt.Sprint(batchIndex)))
}

func quarantineBad(ctx context.Context, client *redis.Client, processing, dead, raw string) error {
	_, err := client.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.LRem(ctx, processing, 1, raw)
		pipe.LPush(ctx, dead, raw)
		return nil
	})
	return err
}

func readSecret(path string, required bool) (string, error) {
	if path == "" {
		if required {
			return "", fmt.Errorf("secret file is required")
		}
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(data))
	if required && value == "" {
		return "", fmt.Errorf("secret file is empty")
	}
	return value, nil
}
