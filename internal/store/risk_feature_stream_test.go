package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

func TestRiskFeatureStreamPagesSingleHotSubjectWithoutDroppingBoundaryDuplicates(t *testing.T) {
	segment := riskFeatureTestSegment()
	features, err := prepareStreamRiskFeatures(segment)
	if err != nil {
		t.Fatal(err)
	}
	feature := features[0]
	base := map[string]any{"scope_id": feature.item.scope, "event_key": feature.item.key,
		"content_sha256": feature.item.hash, "feature_sha256": feature.featureHash,
		"feature_version": "risk-features-v1", "feature_json": feature.featureJSON,
		"sensor_id": "sensor-a", "subject_ip": "192.0.2.8", "account_id": "account-a",
		"observed_at": segment.AcceptedAt.UTC().Format("2006-01-02 15:04:05.000000")}
	queries := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		query := string(body)
		queries = append(queries, query)
		if strings.Contains(query, "tuple(observed_at,event_key,scope_id") {
			return
		}
		for range 2 { // same physical row may straddle a page boundary
			encoded, _ := json.Marshal(base)
			_, _ = w.Write(append(encoded, '\n'))
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	claims := []RiskSubjectClaim{{SensorID: "sensor-a", Type: "ip", ID: "192.0.2.8"}}
	seen := 0
	count, err := ch.StreamRiskFeatureEvents(context.Background(), "sensor-a", claims,
		segment.AcceptedAt.Add(-time.Minute), segment.AcceptedAt.Add(time.Minute), segment.AcceptedAt.Add(-time.Minute), 2,
		func(event normalized.Event) error { seen++; return nil })
	if err != nil || count != 1 || seen != 1 || len(queries) != 2 {
		t.Fatalf("keyset page lost or repeated an event: count=%d seen=%d queries=%d err=%v", count, seen, len(queries), err)
	}
	for _, query := range queries {
		if strings.Contains(query, "stream_event_body") || !strings.Contains(query, "LIMIT 2") || !strings.Contains(query, "accepted_at<=") {
			t.Fatalf("unbounded or non-frozen risk page: %s", query)
		}
	}
}

func TestRiskFeatureStreamRejectsConflictAcrossPages(t *testing.T) {
	segment := riskFeatureTestSegment()
	features, err := prepareStreamRiskFeatures(segment)
	if err != nil {
		t.Fatal(err)
	}
	feature := features[0]
	base := map[string]any{"scope_id": feature.item.scope, "event_key": feature.item.key,
		"content_sha256": feature.item.hash, "feature_sha256": feature.featureHash,
		"feature_version": "risk-features-v1", "feature_json": feature.featureJSON,
		"sensor_id": "sensor-a", "subject_ip": "192.0.2.8", "account_id": "account-a",
		"observed_at": segment.AcceptedAt.UTC().Format("2006-01-02 15:04:05.000000")}
	pages := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pages++
		row := map[string]any{}
		for key, value := range base {
			row[key] = value
		}
		if pages == 2 {
			row["content_sha256"] = strings.Repeat("f", 64)
		}
		encoded, _ := json.Marshal(row)
		_, _ = fmt.Fprintln(w, string(encoded))
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	claims := []RiskSubjectClaim{{SensorID: "sensor-a", Type: "ip", ID: "192.0.2.8"}}
	_, err = ch.StreamRiskFeatureEvents(context.Background(), "sensor-a", claims,
		segment.AcceptedAt.Add(-time.Minute), segment.AcceptedAt.Add(time.Minute), segment.AcceptedAt.Add(-time.Minute), 1,
		func(normalized.Event) error { return nil })
	if err != streamlog.ErrContentConflict {
		t.Fatalf("cross-page same-key conflict not rejected: %v", err)
	}
}
