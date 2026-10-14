package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// All queue mutations are fenced by a unique lease generation. The persisted
// manifest survives crashes and freezes both the raw prefix and normalization time.
var beginBatchScript = batchTransaction("begin")
var finishBatchScript = batchTransaction("finish")
var freezeBatchScript = batchTransaction("freeze")
var restoreBatchScript = batchTransaction("restore")
var releaseBatchScript = batchTransaction("release")

type reliableBatch struct {
	Raw           []string            `json:"raw"`
	ObservedAt    string              `json:"observed_at"`
	InstanceID    string              `json:"instance_id"`
	Source        string              `json:"source"`
	SensorID      string              `json:"sensor_id"`
	CampusID      string              `json:"campus_id"`
	AccessDomain  string              `json:"access_domain"`
	SourceVersion string              `json:"source_version"`
	BatchID       string              `json:"batch_id,omitempty"`
	ContentSHA256 string              `json:"content_sha256,omitempty"`
	RecordCount   int                 `json:"record_count"`
	Records       []map[string]string `json:"records,omitempty"`
	Quarantine    []string            `json:"quarantine,omitempty"`
	Durable       bool                `json:"durable"`
	Frozen        bool                `json:"frozen"`
	token         string
}

func beginReliableBatch(ctx context.Context, client *redis.Client, cfg config, instanceID string, version int64) (reliableBatch, error) {
	var batch reliableBatch
	owner := make([]byte, 16)
	if _, err := rand.Read(owner); err != nil {
		return batch, err
	}
	result, err := beginBatchScript.Run(ctx, client, []string{cfg.eventList, cfg.processingList, cfg.processingList + ":lease", cfg.processingList + ":epoch", cfg.processingList + ":batch"}, hex.EncodeToString(owner), cfg.batchSize, time.Now().UTC().Format(time.RFC3339Nano), instanceID, cfg.source, cfg.sensor, cfg.campus, cfg.domain, version).Slice()
	if err == redis.Nil {
		return batch, nil
	}
	if err != nil {
		return batch, err
	}
	batch.token = result[0].(string)
	if result[1].(string) == "" {
		return batch, nil
	}
	if err = json.Unmarshal([]byte(result[1].(string)), &batch); err != nil {
		return batch, fmt.Errorf("decode persisted batch: %w", err)
	}
	return batch, nil
}

// Switching sources is allowed only after all old queue responsibilities drain.
func eventSourceDrained(ctx context.Context, client *redis.Client, cfg config) (bool, error) {
	pipe := client.TxPipeline()
	source := pipe.LLen(ctx, cfg.eventList)
	processing := pipe.LLen(ctx, cfg.processingList)
	responsibility := pipe.Exists(ctx, cfg.processingList+":batch", cfg.processingList+":lease")
	_, err := pipe.Exec(ctx)
	result := source.Val() + processing.Val() + responsibility.Val()
	return err == nil && result == 0, err
}
