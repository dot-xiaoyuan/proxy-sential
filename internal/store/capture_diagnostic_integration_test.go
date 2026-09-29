package store

import (
	"context"
	"fmt"
	"os"
	"proxy-sentinel/internal/ingest"
	"testing"
	"time"
)

func TestClickHouseCaptureDiagnosticsIsolateSensorKindAndTime(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("isolated ClickHouse required")
	}
	s, err := NewClickHouseStore(ClickHouseOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	sensor := fmt.Sprintf("capture-health-replay-%d", time.Now().UnixNano())
	other := sensor + "-other"
	now := time.Now().UTC()
	t.Cleanup(func() {
		cleanup, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		if err := s.exec(cleanup, "ALTER TABLE ingest_diagnostics DELETE WHERE sensor_id IN ("+chQuote(sensor)+","+chQuote(other)+") SETTINGS mutations_sync=2"); err != nil {
			t.Error(err)
		}
	})
	items := []ingest.Diagnostic{}
	for _, row := range []struct {
		id, sensor, stage, kind string
		at                      time.Time
	}{{"healthy", sensor, "capture_health", "capture_coverage", now}, {"other", other, "capture_health", "capture_coverage", now}, {"ingest", sensor, "realtime_ingest", "capture_coverage", now}, {"old", sensor, "capture_health", "capture_coverage", now.Add(-time.Hour)}, {"different-kind", sensor, "capture_health", "capture_warning", now}} {
		items = append(items, ingest.Diagnostic{SchemaVersion: "1.0", DiagnosticID: sensor + row.id, Timestamp: row.at.Format(time.RFC3339Nano), SensorID: row.sensor, Collector: ingest.Collector{Kind: "suricata"}, Stage: row.stage, Type: row.kind, Severity: "info", Summary: "isolated coverage replay", Details: map[string]any{"complete": true}})
	}
	if err := s.WriteIngestDiagnostics(ctx, items); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListIngestDiagnostics(ctx, Query{SensorID: sensor, DiagnosticStage: "capture_health", DiagnosticType: "capture_coverage", From: now.Add(-time.Minute).Format(time.RFC3339Nano), Limit: 100})
	if err != nil || len(got) != 1 || got[0].DiagnosticID != sensor+"healthy" {
		t.Fatal("cross-sensor/history diagnostics contaminated capture coverage", got, err)
	}
	if _, err := s.ListIngestDiagnostics(ctx, Query{From: "invalid time"}); err == nil {
		t.Fatal("invalid time accepted")
	}
}
