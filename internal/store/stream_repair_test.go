package store

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/streamlog"
)

func TestRetryProvenUnsentSourceBackedArchiveRequiresRawAndBodyProof(t *testing.T) {
	segment := testStreamSegment()
	segment.AcceptedAt = time.Now().UTC().Add(-3 * time.Minute)
	segment.SourceBackedRaw = true
	segment.Raw = []byte(strings.Repeat("x", 100))
	sum := sha256.Sum256(segment.Raw)
	segment.RawSHA256 = hex.EncodeToString(sum[:])
	prepared, err := prepareStreamEvents(segment)
	if err != nil {
		t.Fatal(err)
	}
	const id = "source-backed-segment"
	rawToken := streamInsertSettings(id, "stream_source_raw")["insert_deduplication_token"]
	var rawPresent, bodyPresent, rawTokenSeen, rawBusy bool
	var rawInserts, bodyInserts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		q := string(data)
		switch {
		case strings.HasPrefix(q, "SELECT raw_sha256,raw_base64"):
			if rawPresent {
				row, _ := json.Marshal(map[string]any{"raw_sha256": segment.RawSHA256, "raw_base64": base64.StdEncoding.EncodeToString(segment.Raw)})
				_, _ = w.Write(append(row, '\n'))
			}
		case strings.HasPrefix(q, "SELECT scope_id,event_key,content_sha256"):
			if bodyPresent {
				row, _ := json.Marshal(map[string]any{"scope_id": prepared[0].scope, "event_key": prepared[0].key, "content_sha256": prepared[0].hash})
				_, _ = w.Write(append(row, '\n'))
			}
		case strings.Contains(q, "FROM system.asynchronous_inserts"):
			if rawBusy && strings.Contains(q, "stream_source_raw") {
				_, _ = io.WriteString(w, "1\n")
			} else {
				_, _ = io.WriteString(w, "0\n")
			}
		case strings.Contains(q, "FROM system.query_log") && strings.Contains(q, "insert_deduplication_token"):
			if rawTokenSeen && strings.Contains(q, rawToken) {
				_, _ = io.WriteString(w, "1\n")
			} else {
				_, _ = io.WriteString(w, "0\n")
			}
		case strings.Contains(q, "FROM system.query_log"):
			_, _ = io.WriteString(w, "2\n")
		case strings.HasPrefix(q, "INSERT INTO stream_source_raw"):
			rawInserts++
			rawPresent = true
		case strings.HasPrefix(q, "INSERT INTO stream_event_body_evidence"):
			bodyInserts++
			bodyPresent = true
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	rawPresent = true
	if err := ch.RetryProvenUnsentStreamLane(context.Background(), id, segment, streamlog.Archive); err == nil {
		t.Fatal("partial source archive was replayed")
	}
	rawPresent = false
	rawTokenSeen = true
	if err := ch.RetryProvenUnsentStreamLane(context.Background(), id, segment, streamlog.Archive); err == nil {
		t.Fatal("original raw token was replayed")
	}
	rawTokenSeen = false
	rawBusy = true
	if err := ch.RetryProvenUnsentStreamLane(context.Background(), id, segment, streamlog.Archive); err == nil {
		t.Fatal("queued raw source was replayed")
	}
	rawBusy = false
	if err := ch.RetryProvenUnsentStreamLane(context.Background(), id, segment, streamlog.Archive); err != nil {
		t.Fatal(err)
	}
	if rawInserts != 1 || bodyInserts != 1 {
		t.Fatalf("expected one raw and body insert, got raw=%d body=%d", rawInserts, bodyInserts)
	}
}

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
