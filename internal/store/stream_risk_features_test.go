package store

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"proxy-sentinel/internal/streamlog"
)

func riskFeatureTestSegment() streamlog.Segment {
	segment := testStreamSegment()
	segment.RiskFeaturesRequired = true
	segment.Events[0].Type = "device"
	segment.Events[0].Subject = map[string]any{"ip": "192.0.2.8", "account_id": "account-a"}
	segment.Events[0].Payload = map[string]any{"origin": "dhcp", "ttl": 62, "unrelated_full_body": "must not be copied"}
	segment.Events[0].Observer["sensor_id"] = "sensor-a"
	return segment
}

// Replay the incident: ClickHouse commits the search insert but its response
// is lost. Recovery must confirm search, then send the still-unsent feature
// insert, without replaying search or acknowledging an ambiguous feature write.
func TestSplitSearchRecoveryContinuesUnsentRiskFeatures(t *testing.T) {
	segment := riskFeatureTestSegment()
	segment.NeedsProjection = false
	segment.SplitRiskFeatures = true
	features, err := prepareStreamRiskFeatures(segment)
	if err != nil {
		t.Fatal(err)
	}
	searchWrites, featureWrites, lookups := 0, 0, 0
	featureVisible := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		query := string(body)
		switch {
		case strings.HasPrefix(query, "INSERT INTO stream_event_search"):
			searchWrites++
			http.Error(w, "response lost after commit", http.StatusGatewayTimeout)
		case strings.HasPrefix(query, "INSERT INTO stream_risk_features_v1"):
			featureWrites++
			http.Error(w, "feature outcome remains ambiguous", http.StatusGatewayTimeout)
		case strings.HasPrefix(query, "SELECT"):
			lookups++
			item := features[0].item
			row := map[string]any{"scope_id": item.scope, "event_key": item.key, "content_sha256": item.hash, "archive_month": 202610, "retention_class": item.retention}
			if strings.Contains(query, "FROM stream_risk_features_v1") {
				if !featureVisible {
					return
				}
				row["feature_sha256"], row["feature_version"] = features[0].featureHash, "risk-features-v1"
			}
			encoded, _ := json.Marshal(row)
			_, _ = w.Write(append(encoded, '\n'))
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	queue := &recordingRiskQueue{}
	j, err := streamlog.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: segment.Epoch, Source: segment.Source, Path: segment.SourcePath, FileID: segment.PreviousFileID, Offset: segment.PreviousOffset, ParserVersion: segment.ParserVersion}); err != nil {
		t.Fatal(err)
	}
	id, err := j.Append(segment)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CommitSource(segment.Source, segment.SourcePath, id); err != nil {
		t.Fatal(err)
	}
	p := streamlog.Processor{Journal: j, Writer: StreamLaneWriter{ClickHouse: ch, RiskQueue: queue}}
	if err := p.Drain(context.Background(), id); err == nil || searchWrites != 1 || featureWrites != 0 || lookups != 0 {
		t.Fatalf("search failure advanced features: search=%d features=%d lookups=%d err=%v", searchWrites, featureWrites, lookups, err)
	}
	// Restart between the two inserts. Pending features have never been sent.
	j, err = streamlog.Open(j.Directory())
	if err != nil {
		t.Fatal(err)
	}
	p.Journal = j
	if err := p.DrainLane(context.Background(), id, streamlog.Search); err == nil || searchWrites != 1 || featureWrites != 1 {
		t.Fatalf("recovery failed to continue unsent feature write: search=%d features=%d err=%v", searchWrites, featureWrites, err)
	}
	state, err := j.Load(id)
	if err != nil || state.Acks[streamlog.Search] != streamlog.Acked || state.Acks[streamlog.RiskFeatures] != streamlog.Attempted {
		t.Fatalf("independent durable checkpoints lost: %+v %v", state.Acks, err)
	}
	lanes, err := j.PendingLanes(id)
	if err != nil || len(lanes) != 1 || lanes[0] != streamlog.Search {
		t.Fatalf("feature recovery was not queued: %v %v", lanes, err)
	}
	if err := p.DrainLane(context.Background(), id, streamlog.Search); !errors.Is(err, streamlog.ErrUnconfirmed) || featureWrites != 1 || queue.calls != 0 {
		t.Fatalf("ambiguous feature insert replayed or acknowledged: writes=%d wake=%d err=%v", featureWrites, queue.calls, err)
	}
	if err := j.Release(id); !errors.Is(err, streamlog.ErrUnconfirmed) {
		t.Fatalf("unconfirmed features released the source: %v", err)
	}
	featureVisible = true
	if err := p.Drain(context.Background(), id); err != nil || featureWrites != 1 || searchWrites != 1 || queue.calls == 0 {
		t.Fatalf("late feature confirmation failed: search=%d features=%d wake=%d err=%v", searchWrites, featureWrites, queue.calls, err)
	}
	if _, err := j.Load(id); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("confirmed source was not released: %v", err)
	}
}

func TestSharedOnlySignalsDoNotScheduleGenericRisk(t *testing.T) {
	for _, tc := range []struct {
		source, protocol string
		want             int
	}{
		{"handshake-sidecar", "handshake", 0},
		{"packet-sidecar", "ssdp", 0},
		{"packet-sidecar", "ieee1905_topology", 0},
		{"packet-sidecar", "ttl", 1},
	} {
		segment := riskFeatureTestSegment()
		segment.Events[0].Source = tc.source
		segment.Events[0].SourceEventType = tc.protocol
		features, err := prepareStreamRiskFeatures(segment)
		if err != nil || len(features) != tc.want {
			t.Fatalf("%s/%s: %d features, %v", tc.source, tc.protocol, len(features), err)
		}
	}
}

func TestSplitSearchSuccessfulWritesNeedNoConfirmationQueries(t *testing.T) {
	s := riskFeatureTestSegment()
	s.NeedsProjection, s.SplitRiskFeatures = false, true
	search, risk, reads := 0, 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch query := string(body); {
		case strings.HasPrefix(query, "INSERT INTO stream_event_search"):
			search++
		case strings.HasPrefix(query, "INSERT INTO stream_risk_features_v1"):
			risk++
		case strings.HasPrefix(query, "SELECT"):
			reads++
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	j, err := streamlog.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := j.StartFreshSource(streamlog.SourceCursor{Epoch: s.Epoch, Source: s.Source, Path: s.SourcePath, FileID: s.PreviousFileID, Offset: s.PreviousOffset, ParserVersion: s.ParserVersion}); err != nil {
		t.Fatal(err)
	}
	id, err := j.Append(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.CommitSource(s.Source, s.SourcePath, id); err != nil {
		t.Fatal(err)
	}
	queue := &recordingRiskQueue{}
	p := streamlog.Processor{Journal: j, Writer: StreamLaneWriter{ClickHouse: ch, RiskQueue: queue}}
	if err := p.Drain(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if search != 1 || risk != 1 || reads != 0 || queue.calls != 1 {
		t.Fatalf("normal path added reads or duplicate writes: search=%d risk=%d reads=%d wake=%d", search, risk, reads, queue.calls)
	}
}

func TestStreamRiskFeatureWriteAndReconcileRequireIndependentConfirmation(t *testing.T) {
	segment := riskFeatureTestSegment()
	features, err := prepareStreamRiskFeatures(segment)
	if err != nil || len(features) != 1 {
		t.Fatalf("prepare risk feature: %d %v", len(features), err)
	}
	if strings.Contains(features[0].featureJSON, "unrelated_full_body") || strings.Contains(features[0].featureJSON, "capture_scope_id") {
		t.Fatalf("feature contains unneeded original data: %s", features[0].featureJSON)
	}
	var inserts []string
	searchPresent, featurePresent, featureConflict := true, false, false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		query := string(body)
		if strings.HasPrefix(query, "INSERT") {
			inserts = append(inserts, query)
			return
		}
		item := features[0].item
		switch {
		case strings.Contains(query, "FROM stream_event_search") && searchPresent:
			encoded, _ := json.Marshal(map[string]any{"scope_id": item.scope, "event_key": item.key, "content_sha256": item.hash, "archive_month": 202610, "retention_class": item.retention})
			_, _ = w.Write(append(encoded, '\n'))
		case strings.Contains(query, "FROM stream_risk_features_v1") && featurePresent:
			hash := features[0].featureHash
			if featureConflict {
				hash = strings.Repeat("f", 64)
			}
			encoded, _ := json.Marshal(map[string]any{"scope_id": item.scope, "event_key": item.key, "content_sha256": item.hash, "feature_sha256": hash, "feature_version": "risk-features-v1", "archive_month": 202610})
			_, _ = w.Write(append(encoded, '\n'))
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	queue := &recordingRiskQueue{}
	writer := StreamLaneWriter{ClickHouse: ch, RiskQueue: queue}
	if err := writer.WriteSearch(context.Background(), "segment-a", segment); err != nil {
		t.Fatal(err)
	}
	if len(inserts) != 2 || !strings.HasPrefix(inserts[0], "INSERT INTO stream_event_search") || !strings.HasPrefix(inserts[1], "INSERT INTO stream_risk_features_v1") {
		t.Fatalf("search and feature inserts were not both issued: %v", inserts)
	}
	if queue.calls != 1 {
		t.Fatalf("confirmed risk input still waits for projection/finalization: calls=%d", queue.calls)
	}
	if err := writer.ReconcileSearch(context.Background(), "segment-a", segment); !errors.Is(err, streamlog.ErrUnconfirmed) {
		t.Fatalf("missing risk feature was acknowledged: %v", err)
	}
	if queue.calls != 1 {
		t.Fatal("unconfirmed features scheduled risk work")
	}
	featurePresent = true
	if err := writer.ReconcileSearch(context.Background(), "segment-a", segment); err != nil {
		t.Fatalf("late feature flush not confirmed: %v", err)
	}
	if queue.calls != 2 {
		t.Fatal("confirmed retry did not recover the risk wake")
	}
	featureConflict = true
	if err := writer.ReconcileSearch(context.Background(), "segment-a", segment); !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("same-key feature conflict accepted: %v", err)
	}
	if queue.calls != 2 {
		t.Fatal("conflicting features scheduled risk work")
	}
}
