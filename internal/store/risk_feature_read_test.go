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
	"time"

	"proxy-sentinel/internal/streamlog"
)

func TestRiskFeatureReadRejectsConflictsAndNeverSelectsBody(t *testing.T) {
	segment := riskFeatureTestSegment()
	features, err := prepareStreamRiskFeatures(segment)
	if err != nil {
		t.Fatal(err)
	}
	feature := features[0]
	row := map[string]any{"scope_id": feature.item.scope, "event_key": feature.item.key,
		"content_sha256": feature.item.hash, "feature_sha256": feature.featureHash,
		"feature_version": "risk-features-v1", "feature_json": feature.featureJSON,
		"sensor_id": "sensor-a", "subject_ip": "192.0.2.8", "account_id": "account-a"}
	queryText := ""
	conflict := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		queryText = string(body)
		for index := 0; index < 2; index++ {
			copy := map[string]any{}
			for key, value := range row {
				copy[key] = value
			}
			if conflict && index == 1 {
				copy["feature_sha256"] = strings.Repeat("f", 64)
			}
			encoded, _ := json.Marshal(copy)
			_, _ = w.Write(append(encoded, '\n'))
		}
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	claims := []RiskSubjectClaim{{SensorID: "sensor-a", Type: "ip", ID: "192.0.2.8"}}
	from := segment.AcceptedAt.Add(-time.Minute)
	to := segment.AcceptedAt.Add(time.Minute)
	events, err := ch.ListStreamRiskFeatureEvents(context.Background(), "sensor-a", claims, from, to, from, 2)
	if err != nil || len(events) != 1 || events[0].EventID != "e1" {
		t.Fatalf("same-content physical duplicate changed risk input: count=%d err=%v", len(events), err)
	}
	if strings.Contains(queryText, "stream_event_body") || strings.Contains(queryText, "normalized_events") || !strings.Contains(queryText, "stream_risk_features_v1") {
		t.Fatalf("risk reader selected authoritative full body: %s", queryText)
	}
	if !strings.Contains(queryText, "accepted_at>=") {
		t.Fatalf("risk reader omitted the audited acceptance cutoff: %s", queryText)
	}
	conflict = true
	if _, err := ch.ListStreamRiskFeatureEvents(context.Background(), "sensor-a", claims, from, to, from, 2); !errors.Is(err, streamlog.ErrContentConflict) {
		t.Fatalf("same-key conflicting feature accepted: %v", err)
	}
}

func TestRiskFeatureReadSeparatesIPAndAccountIndexPaths(t *testing.T) {
	segment := riskFeatureTestSegment()
	features, err := prepareStreamRiskFeatures(segment)
	if err != nil {
		t.Fatal(err)
	}
	feature := features[0]
	row := map[string]any{"scope_id": feature.item.scope, "event_key": feature.item.key,
		"content_sha256": feature.item.hash, "feature_sha256": feature.featureHash,
		"feature_version": "risk-features-v1", "feature_json": feature.featureJSON,
		"sensor_id": "sensor-a", "subject_ip": "192.0.2.8", "account_id": "account-a"}
	queries := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		queries = append(queries, string(body))
		encoded, _ := json.Marshal(row)
		_, _ = w.Write(append(encoded, '\n'))
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	claims := []RiskSubjectClaim{{SensorID: "sensor-a", Type: "ip", ID: "192.0.2.8"}, {SensorID: "sensor-a", Type: "account", ID: "account-a"}}
	events, err := ch.ListStreamRiskFeatureEvents(context.Background(), "sensor-a", claims, segment.AcceptedAt.Add(-time.Minute), segment.AcceptedAt.Add(time.Minute), segment.AcceptedAt.Add(-time.Minute), 1)
	if err != nil || len(events) != 1 || len(queries) != 2 || !strings.Contains(queries[0], "subject_ip IN") || !strings.Contains(queries[1], "account_id IN") || strings.Contains(queries[0], " OR ") || strings.Contains(queries[1], " OR ") {
		t.Fatalf("affected claims did not use two narrow lookups: events=%d queries=%v err=%v", len(events), queries, err)
	}
}
