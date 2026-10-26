package store

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
