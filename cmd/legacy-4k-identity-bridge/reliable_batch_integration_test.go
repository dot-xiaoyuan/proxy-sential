package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/redis/go-redis/v9"
	"net/http"
	"net/http/httptest"
	"os"
	"proxy-sentinel/internal/identityprotocol"
	"proxy-sentinel/internal/legacy4k"
	"testing"
	"time"
)

func TestReliableBatchFreezesRetryAndFencesAcknowledgement(t *testing.T) {
	addr := os.Getenv("PROXY_SENTINEL_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("isolated Redis required")
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	defer client.Close()
	ctx := context.Background()
	prefix := fmt.Sprintf("identity-test:%d", time.Now().UnixNano())
	cfg := config{eventList: prefix, processingList: prefix + ":processing", deadList: prefix + ":dead", batchSize: 100, source: "ncu-srun4k", sensor: "sensor", campus: "campus", domain: "domain"}
	defer client.Del(ctx, cfg.eventList, cfg.processingList, cfg.processingList+":batch", cfg.processingList+":lease", cfg.processingList+":epoch", cfg.deadList+":quarantine")
	raw := `{"action":1,"session_id":"one","user_name":"student","ip":"192.0.2.1","ip6_1":"2001:db8::1"}`
	if err := client.RPush(ctx, cfg.eventList, raw).Err(); err != nil {
		t.Fatal(err)
	}
	var first identityprotocol.Request
	var firstID string
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request identityprotocol.Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		calls++
		if calls == 1 {
			first = request
			firstID = r.Header.Get("Idempotency-Key")
			_, _ = w.Write([]byte(`{"status":"failed"}`))
			return
		}
		if first.Hash() != request.Hash() || firstID != r.Header.Get("Idempotency-Key") {
			t.Error("retry changed frozen content")
		}
		_ = json.NewEncoder(w).Encode(identityprotocol.Receipt{ProtocolVersion: 2, BatchID: firstID, ContentSHA256: request.Hash(), RecordCount: len(request.Records), DurablyAccepted: true, AcceptedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	}))
	defer server.Close()
	sender := legacy4k.Sender{Endpoint: server.URL, Durable: true}
	state := &runtimeState{}
	if _, err := processBatch(ctx, client, sender, cfg, "instance", state); err == nil {
		t.Fatal("invalid ack cleared batch")
	}
	if client.LLen(ctx, cfg.processingList).Val() != 1 {
		t.Fatal("processing responsibility lost")
	}
	var frozen reliableBatch
	if err := json.Unmarshal([]byte(client.Get(ctx, cfg.processingList+":batch").Val()), &frozen); err != nil || frozen.ContentSHA256 != first.Hash() || frozen.RecordCount != 2 || !frozen.Durable {
		t.Fatalf("request not durably frozen: %v", err)
	}
	if state.processingQueue != 1 {
		t.Fatal("failed send did not sample queue")
	}
	if len(first.Records) != 2 {
		t.Fatal("dual-stack address missing")
	}
	if err := client.RPush(ctx, cfg.eventList, raw).Err(); err != nil {
		t.Fatal(err)
	}
	sender.Durable = false // configuration changes cannot reinterpret a pending retry
	if _, err := processBatch(ctx, client, sender, cfg, "different-instance-after-restart", state); err != nil {
		t.Fatal(err)
	}
	if client.LLen(ctx, cfg.processingList).Val() != 0 || client.LLen(ctx, cfg.eventList).Val() != 1 {
		t.Fatal("retry appended or removed a different prefix")
	}
	batch, err := beginReliableBatch(ctx, client, cfg, "instance", 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := beginReliableBatch(ctx, client, cfg, "instance", 1)
	if err != nil || len(second.Raw) > 0 {
		t.Fatalf("double lease: %v", err)
	}
	client.Del(ctx, cfg.processingList+":lease") // isolated crash/lease-expiry injection
	replacement, err := beginReliableBatch(ctx, client, cfg, "instance", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = finishBatchScript.Run(ctx, client, []string{cfg.processingList, cfg.processingList + ":lease", cfg.processingList + ":batch", cfg.deadList + ":quarantine"}, batch.token).Result(); err == nil {
		t.Fatal("expired lease trimmed messages")
	}
	if replacement.token == batch.token || len(replacement.Raw) != 1 {
		t.Fatal("invalid fenced recovery")
	}
}

func TestQueueFailureRetainsMetricsAndPendingManifest(t *testing.T) {
	addr := os.Getenv("PROXY_SENTINEL_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("isolated Redis required")
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	defer client.Close()
	ctx := context.Background()
	prefix := fmt.Sprintf("identity-metrics:%d", time.Now().UnixNano())
	cfg := config{eventList: prefix, processingList: prefix + ":processing", deadList: prefix + ":dead", batchSize: 1}
	defer client.Del(ctx, cfg.eventList, cfg.processingList, cfg.processingList+":batch", cfg.processingList+":epoch", cfg.processingList+":lease")
	client.RPush(ctx, cfg.eventList, "invalid-json")
	state := &runtimeState{lastSnapshotAt: time.Now()}
	updateQueueMetrics(ctx, client, cfg, state)
	if state.sourceQueue != 1 || state.queueSampleError {
		t.Fatal("successful sample missing")
	}
	old := state.queueSampledAt
	cancelled, stop := context.WithCancel(ctx)
	stop()
	updateQueueMetrics(cancelled, client, cfg, state)
	if state.sourceQueue != 1 || !state.queueSampleError || state.queueSampledAt != old {
		t.Fatal("failed sample invented zero or timestamp")
	}
	batch, err := beginReliableBatch(ctx, client, cfg, "instance", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = restoreProcessing(ctx, client, cfg.eventList, cfg.processingList); err == nil {
		t.Fatal("restore destroyed active manifest")
	}
	releaseBatchScript.Run(ctx, client, []string{cfg.processingList + ":lease"}, batch.token)
	if err = restoreProcessing(ctx, client, cfg.eventList, cfg.processingList); err == nil {
		t.Fatal("restore destroyed retry manifest")
	}
	if drained, err := eventSourceDrained(ctx, client, cfg); err != nil || drained {
		t.Fatal("source switched with pending responsibility")
	}
}

func TestReliableTransactionRestoresPrefixInOriginalOrder(t *testing.T) {
	addr := os.Getenv("PROXY_SENTINEL_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("isolated Redis required")
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	defer client.Close()
	ctx := context.Background()
	prefix := fmt.Sprintf("identity-restore:%d", time.Now().UnixNano())
	cfg := config{eventList: prefix, processingList: prefix + ":processing"}
	defer client.Del(ctx, cfg.eventList, cfg.processingList)
	client.RPush(ctx, cfg.processingList, "first", "second", "third")
	client.RPush(ctx, cfg.eventList, "fourth")
	if err := restoreProcessing(ctx, client, cfg.eventList, cfg.processingList); err != nil {
		t.Fatal(err)
	}
	rows, err := client.LRange(ctx, cfg.eventList, 0, -1).Result()
	if err != nil || fmt.Sprint(rows) != "[first second third fourth]" {
		t.Fatalf("restore order %v: %v", rows, err)
	}
	if client.LLen(ctx, cfg.processingList).Val() != 0 {
		t.Fatal("restore left duplicate processing messages")
	}
}
