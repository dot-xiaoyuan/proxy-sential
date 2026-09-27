package store

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestCanonicalEventsAndActivityRollupAreIdempotent(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN is not set")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Query().Get("database") == "" || parsed.Query().Get("database") == "proxy_sentinel" {
		t.Skip("requires an isolated ClickHouse test database")
	}
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sensor := fmt.Sprintf("t11-idempotence-%d", time.Now().UnixNano())
	when := time.Now().UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
	base := normalized.Event{SchemaVersion: "v1", Source: "suricata", Type: "dns", Timestamp: when, Observer: map[string]any{"sensor_id": sensor}, Subject: map[string]any{"ip": "192.0.2.10"}, Flow: map[string]any{"src_ip": "192.0.2.10", "dst_ip": "203.0.113.10", "proto": "udp"}, Payload: map[string]any{"query": "t11.example"}, Confidence: 1}
	first, second := base, base
	first.EventID, second.EventID = "suricata-100-0123456789abcdef", "suricata-200-0123456789abcdef"
	if err := ch.WriteNormalizedEvents(ctx, []normalized.Event{first}); err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteNormalizedEvents(ctx, []normalized.Event{second}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		for _, table := range []string{"normalized_events", "normalized_events_canonical", "activity_rollup_10m"} {
			_ = ch.exec(cleanup, "ALTER TABLE "+table+" DELETE WHERE sensor_id="+chQuote(sensor)+" SETTINGS mutations_sync=2")
		}
	})
	data, err := ch.query(ctx, "SELECT count() AS count FROM normalized_events_canonical FINAL WHERE sensor_id="+chQuote(sensor)+" FORMAT JSONEachRow")
	if err != nil {
		t.Fatal(err)
	}
	count, err := decodeSingleCount(data)
	if err != nil || count != 1 {
		t.Fatalf("canonical count=%d err=%v", count, err)
	}
	day := clickHouseTimestamp(when)[:10]
	for range 2 {
		if err := ch.RefreshActivityRollupDay(ctx, day); err != nil {
			t.Fatal(err)
		}
		report, err := ch.QueryActivityReport(ctx, ActivityReportQuery{ActivityQuery: ActivityQuery{SensorID: sensor, Window: "24h"}, Dimension: "domain", Limit: 10})
		if err != nil || report.Total != 1 || len(report.Items) != 1 || report.Items[0].Key != "t11.example" {
			t.Fatalf("rollup changed after replay: %+v err=%v", report, err)
		}
	}
	// An event just before the 24-hour boundary shares a 10-minute bucket
	// with in-window events. The hybrid read must keep the exact time boundary.
	anchor, err := time.Parse(time.RFC3339Nano, when)
	if err != nil {
		t.Fatal(err)
	}
	outside := base
	outside.EventID = "suricata-300-fedcba9876543210"
	outside.Timestamp = anchor.Add(-24*time.Hour - time.Minute).Format(time.RFC3339Nano)
	if err := ch.WriteNormalizedEvents(ctx, []normalized.Event{outside}); err != nil {
		t.Fatal(err)
	}
	if err := ch.RefreshActivityRollupDay(ctx, clickHouseTimestamp(outside.Timestamp)[:10]); err != nil {
		t.Fatal(err)
	}
	if err := ch.RefreshActivityRollupDay(ctx, day); err != nil {
		t.Fatal(err)
	}
	report, err := ch.QueryActivityReport(ctx, ActivityReportQuery{ActivityQuery: ActivityQuery{SensorID: sensor, Window: "24h", AsOf: when}, Dimension: "domain", Limit: 10})
	if err != nil || report.Total != 1 {
		t.Fatalf("hybrid report crossed time boundary: %+v err=%v", report, err)
	}
	if err := ch.RefreshActivityRollupDay(ctx, "2026-09-01"); err != nil {
		t.Fatalf("empty rollup partition refresh: %v", err)
	}
}

func TestAttributionDiagnosticsAndVersionComparison(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN is not set")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Query().Get("database") == "" || parsed.Query().Get("database") == "proxy_sentinel" {
		t.Skip("requires an isolated ClickHouse test database")
	}
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	sensor := fmt.Sprintf("t11-attribution-%d", time.Now().UnixNano())
	when := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		_ = ch.exec(cleanup, "ALTER TABLE domain_ecosystem_observations DELETE WHERE sensor_id="+chQuote(sensor)+" SETTINGS mutations_sync=2")
	})
	base := DomainEcosystemObservation{DomainObservation: DomainObservation{Timestamp: when, SensorID: sensor, IP: "192.0.2.60", Domain: "t11.example", EventSource: "dns"}, Ecosystem: "Apple", Category: "telemetry", RuleSource: "test", Confidence: .55}
	beforeA, beforeB, afterA, afterB := base, base, base, base
	beforeA.EventID, beforeA.RuleVersion, beforeA.AttributionReason = "t11-before-a", "t11-before", "identity_conflict"
	beforeB.EventID, beforeB.RuleVersion, beforeB.AttributionReason, beforeB.Attributed, beforeB.EndpointID = "t11-before-b", "t11-before", "attributed", true, "endpoint-1"
	afterA.EventID, afterA.RuleVersion, afterA.AttributionReason, afterA.Attributed, afterA.EndpointID = "t11-before-a", "t11-after", "attributed", true, "endpoint-1"
	afterB.EventID, afterB.RuleVersion, afterB.AttributionReason, afterB.Attributed, afterB.EndpointID = "t11-before-b", "t11-after", "attributed", true, "endpoint-2"
	if err := ch.WriteDomainEcosystemObservations(ctx, []DomainEcosystemObservation{beforeA, beforeB, afterA, afterB}); err != nil {
		t.Fatal(err)
	}
	from, to := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	page, err := ch.ListAttributionDiagnostics(ctx, AttributionDiagnosticQuery{From: from, To: to, SensorID: sensor, Status: "unattributed", Reason: "identity_conflict", Limit: 1})
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].EventID != "t11-before-a" {
		t.Fatalf("diagnostics: %+v err=%v", page, err)
	}
	comparison, err := ch.CompareAttributionVersions(ctx, from, to, sensor, "t11-before", "t11-after")
	if err != nil || comparison.Before.Rate != .5 || comparison.After.Rate != 1 || comparison.Before.Conflicts != 1 || comparison.After.Conflicts != 0 {
		t.Fatalf("comparison: %+v err=%v", comparison, err)
	}
}
