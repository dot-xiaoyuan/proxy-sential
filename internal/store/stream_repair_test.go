package store

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/streamlog"
)

func TestRetryProvenUnsentV2SourceBackedArchiveRequiresRawAndBodyProof(t *testing.T) {
	segment := testStreamSegment()
	segment.BodyLayout = "v2"
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
	var rawPresent, bodyPresent, rawBusy, bodyInsertActive bool
	var rawInserts, bodyInserts int
	var bodyQueueProof, queryLogReads bool
	var repairRawToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		q := string(data)
		if strings.Contains(q, "FROM system.asynchronous_inserts") && strings.Contains(q, "stream_event_body_evidence_v2") {
			bodyQueueProof = true
		}
		if strings.Contains(q, "FROM system.query_log") {
			queryLogReads = true
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
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
		case strings.Contains(q, "FROM system.processes"):
			if bodyInsertActive && strings.Contains(q, "stream_event_body_evidence_v2") {
				_, _ = io.WriteString(w, "1\n")
			} else {
				_, _ = io.WriteString(w, "0\n")
			}
		case strings.HasPrefix(q, "INSERT INTO stream_source_raw"):
			rawInserts++
			repairRawToken = r.URL.Query().Get("insert_deduplication_token")
			rawPresent = true
		case strings.HasPrefix(q, "INSERT INTO stream_event_body_evidence_v2"):
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
	rawBusy = true
	if err := ch.RetryProvenUnsentStreamLane(context.Background(), id, segment, streamlog.Archive); err == nil {
		t.Fatal("queued raw source was replayed")
	}
	rawBusy = false
	bodyInsertActive = true
	if err := ch.RetryProvenUnsentStreamLane(context.Background(), id, segment, streamlog.Archive); err == nil {
		t.Fatal("active body insert was replayed")
	}
	bodyInsertActive = false
	if err := ch.RetryProvenUnsentStreamLane(context.Background(), id, segment, streamlog.Archive); err != nil {
		t.Fatal(err)
	}
	if rawInserts != 1 || bodyInserts != 1 || !bodyQueueProof || queryLogReads || repairRawToken == "" || repairRawToken == rawToken {
		t.Fatalf("v2 repair proof or write missing: raw=%d body=%d queue=%t query_log=%t repair_token=%q", rawInserts, bodyInserts, bodyQueueProof, queryLogReads, repairRawToken)
	}
}

func TestReconcileSettledStreamBodyRequiresQuietQueueAndWritesOnlyMissingBody(t *testing.T) {
	segment := testStreamSegment()
	segment.AcceptedAt = time.Now().UTC().Add(-2 * time.Hour)
	segment.SourceBackedRaw = true
	segment.Raw = []byte("archived source\n")
	sum := sha256.Sum256(segment.Raw)
	segment.RawSHA256 = hex.EncodeToString(sum[:])
	prepared, err := prepareStreamEvents(segment)
	if err != nil {
		t.Fatal(err)
	}
	queued, bodyPresent, bodyInserts := true, false, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		q := string(data)
		switch {
		case strings.Contains(q, "FROM system.asynchronous_inserts"):
			if queued {
				_, _ = io.WriteString(w, "1\n")
			} else {
				_, _ = io.WriteString(w, "0\n")
			}
		case strings.Contains(q, "FROM system.processes"):
			_, _ = io.WriteString(w, "0\n")
		case strings.HasPrefix(q, "SELECT raw_sha256,raw_base64"):
			row, _ := json.Marshal(map[string]string{"raw_sha256": segment.RawSHA256, "raw_base64": base64.StdEncoding.EncodeToString(segment.Raw)})
			_, _ = w.Write(append(row, '\n'))
		case strings.HasPrefix(q, "SELECT scope_id,event_key,content_sha256"):
			if bodyPresent {
				row, _ := json.Marshal(map[string]string{"scope_id": prepared[0].scope, "event_key": prepared[0].key, "content_sha256": prepared[0].hash})
				_, _ = w.Write(append(row, '\n'))
			}
		case strings.HasPrefix(q, "INSERT INTO stream_event_body_"):
			bodyInserts++
			bodyPresent = true
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.ReconcileSettledStreamBody(context.Background(), "segment-one", segment); err == nil || bodyInserts != 0 {
		t.Fatalf("queued archive was replayed: inserts=%d err=%v", bodyInserts, err)
	}
	queued = false
	segment.AcceptedAt = time.Now().UTC().Add(-30 * time.Minute)
	if err := ch.ReconcileSettledStreamBody(context.Background(), "segment-one", segment); err == nil || bodyInserts != 0 {
		t.Fatalf("recent archive was replayed: inserts=%d err=%v", bodyInserts, err)
	}
	segment.AcceptedAt = time.Now().UTC().Add(-2 * time.Hour)
	if err := ch.ReconcileSettledStreamBody(context.Background(), "segment-one", segment); err != nil || bodyInserts != 1 {
		t.Fatalf("settled archive repair: inserts=%d err=%v", bodyInserts, err)
	}
	if err := ch.ReconcileSettledStreamBody(context.Background(), "segment-one", segment); err != nil || bodyInserts != 1 {
		t.Fatalf("present body was duplicated: inserts=%d err=%v", bodyInserts, err)
	}
}

func TestReconcileSettledStandardEventRawRepairsOnlyMissingBody(t *testing.T) {
	segment := testStreamSegment()
	segment.Source = "device-signals"
	segment.SourcePath = "/signals/handshake.jsonl"
	segment.BodyLayout = "v2"
	segment.RawIsStandardEvents = true
	segment.AcceptedAt = time.Now().UTC().Add(-2 * time.Hour)
	segment.Events[0].Source = "handshake-sidecar"
	second := segment.Events[0]
	second.EventID = "e2"
	segment.Events = append(segment.Events, second)
	firstLine, _ := json.Marshal(segment.Events[0])
	secondLine, _ := json.Marshal(segment.Events[1])
	segment.Raw = append(append(append([]byte{}, firstLine...), '\n'), append(secondLine, '\n')...)
	segment.StartOffset = 100
	segment.EndOffset = segment.StartOffset + int64(len(segment.Raw))
	sum := sha256.Sum256(segment.Raw)
	segment.RawSHA256 = hex.EncodeToString(sum[:])
	prepared, err := prepareStreamEvents(segment)
	if err != nil {
		t.Fatal(err)
	}
	queued, present, inserts := true, false, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		query := string(data)
		switch {
		case strings.Contains(query, "FROM system.asynchronous_inserts"):
			if queued {
				_, _ = io.WriteString(w, "1\n")
			} else {
				_, _ = io.WriteString(w, "0\n")
			}
		case strings.Contains(query, "FROM system.processes"):
			_, _ = io.WriteString(w, "0\n")
		case strings.HasPrefix(query, "SELECT scope_id,event_key,content_sha256"):
			_ = json.NewEncoder(w).Encode(map[string]string{"scope_id": prepared[0].scope, "event_key": prepared[0].key, "content_sha256": prepared[0].hash})
			if present {
				_ = json.NewEncoder(w).Encode(map[string]string{"scope_id": prepared[1].scope, "event_key": prepared[1].key, "content_sha256": prepared[1].hash})
			}
		case strings.HasPrefix(query, "INSERT INTO stream_event_body_"):
			if !strings.Contains(query, `"event_key":"`+prepared[1].key+`"`) || strings.Contains(query, `"event_key":"`+prepared[0].key+`"`) {
				t.Errorf("repair inserted the wrong body key")
			}
			inserts++
			present = true
		case strings.Contains(query, "FROM system.query_log") || strings.HasPrefix(query, "INSERT INTO stream_source_raw"):
			t.Errorf("standard-event repair touched unrelated source or diagnostic table")
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.ReconcileSettledStreamBody(context.Background(), "segment-two", segment); err == nil || inserts != 0 {
		t.Fatalf("busy body queue was replayed: inserts=%d err=%v", inserts, err)
	}
	queued = false
	if err := ch.ReconcileSettledStreamBody(context.Background(), "segment-two", segment); err != nil || inserts != 1 {
		t.Fatalf("settled standard-event body repair: inserts=%d err=%v", inserts, err)
	}
	if err := ch.ReconcileSettledStreamBody(context.Background(), "segment-two", segment); err != nil || inserts != 1 {
		t.Fatalf("confirmed standard-event body was duplicated: inserts=%d err=%v", inserts, err)
	}
	segment.RawSHA256 = strings.Repeat("0", 64)
	if err := ch.ReconcileSettledStreamBody(context.Background(), "segment-two", segment); !errors.Is(err, streamlog.ErrUnconfirmed) {
		t.Fatalf("mutated source was accepted: %v", err)
	}
}

func TestMissingStreamBodyEventsReadsBoundedKeyBatches(t *testing.T) {
	segment := testStreamSegment()
	segment.BodyLayout = "v2"
	segment.Events = nil
	for i := 0; i < 205; i++ {
		segment.Events = append(segment.Events, testStreamSegment().Events[0])
		segment.Events[i].EventID = fmt.Sprintf("event-%03d", i)
	}
	queries := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		query := string(data)
		if !strings.HasPrefix(query, "SELECT scope_id,event_key,content_sha256 FROM stream_event_body_evidence_v2") {
			t.Errorf("unexpected body verification query")
			return
		}
		queries++
		if keys := strings.Count(query, "'scope'"); keys > 100 {
			t.Errorf("body verification requested %d keys in one read", keys)
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	missing, err := ch.missingStreamBodyEvents(context.Background(), segment)
	if err != nil || len(missing) != 205 || queries != 3 {
		t.Fatalf("bounded body lookup failed: missing=%d queries=%d err=%v", len(missing), queries, err)
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
	var queryLogReads bool
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
		case strings.Contains(q, "FROM system.processes"):
			_, _ = io.WriteString(w, "0\n")
		case strings.Contains(q, "FROM system.query_log"):
			queryLogReads = true
			w.WriteHeader(http.StatusInternalServerError)
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
	queueBusy = true
	if err := ch.RetryProvenUnsentStreamLane(context.Background(), "segment-one", segment, streamlog.Search); err == nil || inserts != 0 {
		t.Fatalf("queued attempt was replayed: inserts=%d err=%v", inserts, err)
	}
	queueBusy = false
	if err := ch.RetryProvenUnsentStreamLane(context.Background(), "segment-one", segment, streamlog.Search); err != nil || inserts != 1 || queryLogReads {
		t.Fatalf("scoped missing segment was not restored once: inserts=%d query_log=%t err=%v", inserts, queryLogReads, err)
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
	var featurePresent, queryLogReads, queueBusy bool
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
		case strings.Contains(q, "FROM system.processes"):
			_, _ = io.WriteString(w, "0\n")
		case strings.Contains(q, "FROM system.query_log"):
			queryLogReads = true
			w.WriteHeader(http.StatusInternalServerError)
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
	queueBusy = true
	if err := ch.RetryProvenUnsentStreamRiskFeatures(context.Background(), "segment-one", segment); err == nil || inserts != 0 {
		t.Fatalf("queued feature insert was replayed: inserts=%d err=%v", inserts, err)
	}
	queueBusy = false
	if err := ch.RetryProvenUnsentStreamRiskFeatures(context.Background(), "segment-one", segment); err != nil || inserts != 1 || queryLogReads {
		t.Fatalf("scoped missing feature was not restored once: inserts=%d query_log=%t err=%v", inserts, queryLogReads, err)
	}
}

func TestStreamRepairRejectsInsertStartingDuringQuietInterval(t *testing.T) {
	processChecks := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "FROM system.processes") {
			processChecks++
			if processChecks == 2 {
				_, _ = io.WriteString(w, "1\n")
				return
			}
		}
		_, _ = io.WriteString(w, "0\n")
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.requireQuietStreamRepair(context.Background(), []string{"stream_event_search"}); !errors.Is(err, streamlog.ErrUnconfirmed) || processChecks != 2 {
		t.Fatalf("in-flight insert must stop repair: checks=%d err=%v", processChecks, err)
	}
}
