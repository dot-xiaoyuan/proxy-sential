package store

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/streamlog"
)

func TestRetryProvenUnsentSearchRequiresTerminalEvidence(t *testing.T) {
	segment := testStreamSegment()
	segment.AcceptedAt = time.Now().UTC().Add(-3 * time.Minute)
	prepared, err := prepareStreamEvents(segment)
	if err != nil {
		t.Fatal(err)
	}
	var present bool
	var tokenSeen bool
	var queueBusy bool
	var inserts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q := string(body)
		switch {
		case strings.Contains(q, "FROM system.asynchronous_inserts"):
			if queueBusy {
				_, _ = io.WriteString(w, "1\n")
			} else {
				_, _ = io.WriteString(w, "0\n")
			}
		case strings.Contains(q, "FROM system.query_log") && strings.Contains(q, "insert_deduplication_token"):
			if tokenSeen {
				_, _ = io.WriteString(w, "1\n")
			} else {
				_, _ = io.WriteString(w, "0\n")
			}
		case strings.Contains(q, "FROM system.query_log"):
			_, _ = io.WriteString(w, "2\n")
		case strings.HasPrefix(q, "SELECT scope_id"):
			if present {
				row, _ := json.Marshal(map[string]any{"scope_id": prepared[0].scope, "event_key": prepared[0].key, "content_sha256": prepared[0].hash, "archive_month": 202610, "retention_class": "evidence"})
				_, _ = w.Write(append(row, '\n'))
			}
		case strings.HasPrefix(q, "INSERT INTO stream_event_search"):
			inserts++
			present = true
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	tokenSeen = true
	if err := ch.RetryProvenUnsentStreamLane(context.Background(), "segment-one", segment, streamlog.Search); err == nil || inserts != 0 {
		t.Fatalf("recorded attempt was replayed: inserts=%d err=%v", inserts, err)
	}
	tokenSeen = false
	queueBusy = true
	if err := ch.RetryProvenUnsentStreamLane(context.Background(), "segment-one", segment, streamlog.Search); err == nil || inserts != 0 {
		t.Fatalf("queued attempt was replayed: inserts=%d err=%v", inserts, err)
	}
	queueBusy = false
	if err := ch.RetryProvenUnsentStreamLane(context.Background(), "segment-one", segment, streamlog.Search); err != nil || inserts != 1 {
		t.Fatalf("proven unsent segment was not restored once: inserts=%d err=%v", inserts, err)
	}
}

func TestRetryProvenUnsentRiskFeatureRequiresScopedProof(t *testing.T) {
	segment := riskFeatureTestSegment()
	segment.AcceptedAt = time.Now().UTC().Add(-3 * time.Minute)
	prepared, err := prepareStreamRiskFeatures(segment)
	if err != nil {
		t.Fatal(err)
	}
	feature := prepared[0]
	var featurePresent, tokenSeen, queueBusy bool
	var inserts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q := string(body)
		switch {
		case strings.Contains(q, "FROM system.asynchronous_inserts"):
			if queueBusy {
				_, _ = io.WriteString(w, "1\n")
			} else {
				_, _ = io.WriteString(w, "0\n")
			}
		case strings.Contains(q, "FROM system.query_log") && strings.Contains(q, "insert_deduplication_token"):
			if tokenSeen {
				_, _ = io.WriteString(w, "1\n")
			} else {
				_, _ = io.WriteString(w, "0\n")
			}
		case strings.Contains(q, "FROM system.query_log"):
			_, _ = io.WriteString(w, "2\n")
		case strings.Contains(q, "FROM stream_event_search"):
			row, _ := json.Marshal(map[string]any{"scope_id": feature.item.scope, "event_key": feature.item.key, "content_sha256": feature.item.hash, "archive_month": 202610, "retention_class": feature.item.retention})
			_, _ = w.Write(append(row, '\n'))
		case strings.Contains(q, "FROM stream_risk_features_v1"):
			if featurePresent {
				row, _ := json.Marshal(map[string]any{"scope_id": feature.item.scope, "event_key": feature.item.key, "content_sha256": feature.item.hash, "feature_sha256": feature.featureHash, "feature_version": "risk-features-v1", "archive_month": 202610})
				_, _ = w.Write(append(row, '\n'))
			}
		case strings.HasPrefix(q, "INSERT INTO stream_risk_features_v1"):
			inserts++
			featurePresent = true
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	tokenSeen = true
	if err := ch.RetryProvenUnsentStreamRiskFeatures(context.Background(), "segment-one", segment); err == nil || inserts != 0 {
		t.Fatalf("received feature insert was replayed: inserts=%d err=%v", inserts, err)
	}
	tokenSeen = false
	queueBusy = true
	if err := ch.RetryProvenUnsentStreamRiskFeatures(context.Background(), "segment-one", segment); err == nil || inserts != 0 {
		t.Fatalf("queued feature insert was replayed: inserts=%d err=%v", inserts, err)
	}
	queueBusy = false
	if err := ch.RetryProvenUnsentStreamRiskFeatures(context.Background(), "segment-one", segment); err != nil || inserts != 1 {
		t.Fatalf("proven unsent feature was not restored once: inserts=%d err=%v", inserts, err)
	}
}
