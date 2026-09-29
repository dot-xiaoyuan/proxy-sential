package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestClickHouseAggregatesOneHundredThousandEventsWithoutRawReads(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	clickhouse, err := NewClickHouseStore(ClickHouseOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	sensorID := fmt.Sprintf("t7-large-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		cleanup, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = clickhouse.exec(cleanup, "ALTER TABLE normalized_events DELETE WHERE sensor_id="+chQuote(sensorID)+" SETTINGS mutations_sync=2")
		_ = clickhouse.exec(cleanup, "ALTER TABLE ingest_diagnostics DELETE WHERE sensor_id="+chQuote(sensorID)+" SETTINGS mutations_sync=2")
	})
	insert := fmt.Sprintf(`INSERT INTO normalized_events (timestamp,event_id,schema_version,source,source_event_type,type,sensor_id,subject_ip,src_ip,dst_ip,src_port,dst_port,proto,direction,observer_json,payload_json,flow_json,raw_ref_json,confidence,campus_id) WITH concat('10.88.',toString(intDiv(number%%1000,250)),'.',toString((number%%250)+1)) AS test_ip,['dns','http','tls','quic'][(number%%4)+1] AS event_type SELECT now64(6)-toIntervalSecond(number%%3600),concat('t7-',toString(number)),'1.0','integration','generated',event_type,%s,test_ip,test_ip,'203.0.113.10',40000+(number%%1000),if(event_type='dns',53,443),'tcp','egress','{}',concat('{"user_agent":"UA-',toString(intDiv(number,1000)%%2),'","query":"service.example","host":"service.example","sni":"service.example"}'),concat('{"ttl":',toString(64+intDiv(number,1000)%%2),'}'),'{}',0.95,'campus-t7' FROM numbers(100000)`, chQuote(sensorID))
	if err := clickhouse.exec(ctx, insert); err != nil {
		t.Fatal(err)
	}
	if err := clickhouse.exec(ctx, fmt.Sprintf(`INSERT INTO normalized_events (timestamp,event_id,schema_version,source,source_event_type,type,sensor_id,subject_ip,src_ip,dst_ip,src_port,dst_port,proto,direction,observer_json,payload_json,flow_json,raw_ref_json,confidence,campus_id) VALUES (now64(6),'t7-other-campus','1.0','integration','generated','dns',%s,'192.0.2.1','192.0.2.1','203.0.113.10',40000,53,'udp','egress','{}','{}','{}','{}',0.9,'campus-other')`, chQuote(sensorID))); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	overview, err := clickhouse.QueryDPIOverview(ctx, ActivityQuery{SensorID: sensorID, CampusID: "campus-t7", Window: "24h"})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("DPI overview TTFB target exceeded: %s", elapsed)
	}
	if overview.EventCount != 100000 || overview.FlowSampleCount != 100000 || overview.ActiveIPCount != 1000 || overview.ProtocolFlowCount != 4 {
		t.Fatalf("unexpected aggregate overview: %+v", overview)
	}
	if overview.FingerprintConflictCount != 1000 {
		t.Fatalf("expected only the high-confidence TLS conflict for 1000 IPs; UA diversity is not a device conflict: got %d", overview.FingerprintConflictCount)
	}
	flows, err := clickhouse.QueryDPIProtocolFlows(ctx, ActivityQuery{SensorID: sensorID, CampusID: "campus-t7", Window: "24h"})
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 4 {
		t.Fatalf("expected four server-side protocol groups, got %d", len(flows))
	}
	total := 0
	for _, flow := range flows {
		total += flow.EventCount
	}
	if total != 100000 {
		t.Fatalf("protocol aggregation dropped rows: %d", total)
	}
	reportStarted := time.Now()
	report, err := clickhouse.QueryActivityReport(ctx, ActivityReportQuery{ActivityQuery: ActivityQuery{SensorID: sensorID, CampusID: "campus-t7", Window: "24h"}, Dimension: "domain", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(reportStarted); elapsed >= time.Second {
		t.Fatalf("activity TOP report TTFB target exceeded: %s", elapsed)
	}
	if report.Total != 100000 || report.ClassifiedCount != 100000 || len(report.Items) != 1 || report.Items[0].Key != "service.example" {
		t.Fatalf("activity TOP report must aggregate all events in ClickHouse: %+v", report)
	}
	page, err := clickhouse.ListEvents(ctx, Query{SensorID: sensorID, CampusID: "campus-t7", Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 20 || page.Page.Limit != 20 || page.Page.Total != 100000 || page.Page.NextCursor == nil {
		t.Fatalf("unexpected paginated event response: items=%d page=%+v", len(page.Items), page.Page)
	}
	encodedPage, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	if len(encodedPage) > 250*1024 {
		t.Fatalf("default event page exceeds 250KB: %d bytes", len(encodedPage))
	}
	domainPage, err := clickhouse.ListDomainEventsAfter(ctx, sensorID, time.Now().Add(-24*time.Hour).Format(time.RFC3339Nano), "", "", 10000)
	if err != nil {
		t.Fatal(err)
	}
	if len(domainPage) != 10000 {
		t.Fatalf("domain backfill must read a bounded 10000-row batch, got %d", len(domainPage))
	}
	firstIDs := make(map[string]struct{}, len(domainPage))
	for _, event := range domainPage {
		firstIDs[event.EventID] = struct{}{}
	}
	lastDomainEvent := domainPage[len(domainPage)-1]
	nextDomainPage, err := clickhouse.ListDomainEventsAfter(ctx, sensorID, time.Now().Add(-24*time.Hour).Format(time.RFC3339Nano), lastDomainEvent.Timestamp, lastDomainEvent.EventID, 10000)
	if err != nil {
		t.Fatal(err)
	}
	if len(nextDomainPage) != 10000 {
		t.Fatalf("domain backfill second batch must remain bounded, got %d", len(nextDomainPage))
	}
	for _, event := range nextDomainPage {
		if _, duplicated := firstIDs[event.EventID]; duplicated {
			t.Fatalf("cursor batch repeated event %s", event.EventID)
		}
	}
	reviewStarted := time.Now()
	reviewRows, err := clickhouse.ListProxyReviewEvents(ctx, sensorID, 24*time.Hour, 5000)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(reviewStarted); elapsed >= time.Second {
		t.Fatalf("proxy review aggregation TTFB target exceeded: %s", elapsed)
	}
	aggregatedEvents := 0
	for _, event := range reviewRows {
		aggregatedEvents += intFromMap(event.Payload, "_aggregate_count")
	}
	if len(reviewRows) != 500 || aggregatedEvents != 50000 {
		t.Fatalf("proxy review must return grouped rows instead of 100k details: rows=%d events=%d", len(reviewRows), aggregatedEvents)
	}
	diagnosticInsert := fmt.Sprintf(`INSERT INTO ingest_diagnostics (timestamp,diagnostic_id,schema_version,sensor_id,collector_kind,collector_version,interface_name,stage,type,severity,summary,counters_json,by_type_json,raw_ref_json,details_json) SELECT now64(6)-toIntervalSecond(number),concat('t7-diagnostic-',toString(number)),'1.0',%s,'suricata','1.0','ens1f1','normalize','decode',if(number%%3=0,'error','info'),concat('batch ',toString(number)),'{}','{}','{}','{}' FROM numbers(55)`, chQuote(sensorID))
	if err := clickhouse.exec(ctx, diagnosticInsert); err != nil {
		t.Fatal(err)
	}
	diagnostics, diagnosticPage, err := clickhouse.ListIngestDiagnosticsPage(ctx, Query{Limit: 20}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(diagnostics) != 20 || diagnosticPage.Limit != 20 || diagnosticPage.NextCursor == nil || diagnosticPage.Total < 55 {
		t.Fatalf("unexpected diagnostic page: items=%d page=%+v", len(diagnostics), diagnosticPage)
	}
	errors, _, err := clickhouse.ListIngestDiagnosticsPage(ctx, Query{Limit: 20, Q: "batch"}, true)
	if err != nil || len(errors) == 0 {
		t.Fatalf("error diagnostic filtering failed: items=%d err=%v", len(errors), err)
	}
}

func TestClickHouseEventPageCounterBoundariesMatchRaw(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("isolated ClickHouse required")
	}
	ctx := context.Background()
	if _, err := ApplyClickHouseMigrations(ctx, dsn, "../../migrations/clickhouse"); err != nil {
		t.Fatal(err)
	}
	s, err := NewClickHouseStore(ClickHouseOptions{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	sensor := fmt.Sprintf("event-count-replay-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		for _, table := range []string{"normalized_events", "normalized_event_features", "collector_event_counts_10m", "activity_chart_dirty_log", "activity_chart_bucket_facts_v2", "activity_chart_hour_facts", "activity_chart_day_facts"} {
			s.exec(ctx, "ALTER TABLE "+table+" DELETE WHERE sensor_id="+chQuote(sensor)+" SETTINGS mutations_sync=2")
		}
	})
	base := time.Now().UTC().Add(-time.Hour).Truncate(10 * time.Minute)
	query := fmt.Sprintf(`INSERT INTO normalized_events(timestamp,event_id,schema_version,source,source_event_type,type,sensor_id,subject_ip,observer_json,payload_json,flow_json,raw_ref_json) SELECT parseDateTime64BestEffort(%s,6)+toIntervalSecond(number),concat('count-event-',toString(number)),'v1','fixture','dns',if(number%%2=0,'dns','tls'),%s,'10.0.0.1','{}','{}','{}','{}' FROM numbers(1801)`, chQuote(base.Format(time.RFC3339Nano)), chQuote(sensor))
	if err = s.exec(ctx, query); err != nil {
		t.Fatal(err)
	}
	if err = s.exec(ctx, fmt.Sprintf(`INSERT INTO normalized_events(timestamp,event_id,type,sensor_id) SELECT parseDateTime64BestEffort(%s,6),concat('tied-event-',toString(number)),'tls',%s FROM numbers(3)`, chQuote(base.Add(599*time.Second).Format(time.RFC3339Nano)), chQuote(sensor))); err != nil {
		t.Fatal(err)
	}

	for _, bounds := range [][2]int{{0, 1800}, {20, 45}, {599, 600}, {600, 601}, {350, 1550}} {
		for _, level := range []string{"", "dns"} {
			q := Query{SensorID: sensor, Level: level, From: base.Add(time.Duration(bounds[0]) * time.Second).Format(time.RFC3339Nano), To: base.Add(time.Duration(bounds[1]) * time.Second).Format(time.RFC3339Nano)}
			where, err := eventWhereSQL(q)
			if err != nil {
				t.Fatal(err)
			}
			want, err := s.eventCount(ctx, where)
			if err != nil {
				t.Fatal(err)
			}
			got, err := s.eventPageCount(ctx, q, where)
			if err != nil || got != want {
				t.Fatalf("bounds %v level %s: got=%d want=%d err=%v", bounds, level, got, want, err)
			}
			for _, offset := range []int{0, 3, 100, 2000} {
				q.Limit = 3
				q.Cursor = offset
				page, err := s.ListEvents(ctx, q)
				if err != nil {
					t.Fatal(err)
				}
				data, err := s.query(ctx, fmt.Sprintf("SELECT event_id FROM normalized_events%s ORDER BY timestamp DESC,event_id DESC,sensor_id DESC LIMIT 3 OFFSET %d FORMAT JSONEachRow", where, offset))
				if err != nil {
					t.Fatal(err)
				}
				var reference []struct {
					EventID string `json:"event_id"`
				}
				if err = decodeJSONEachRow(data, &reference); err != nil {
					t.Fatal(err)
				}
				if page.Page.Total != want || len(reference) != len(page.Items) {
					t.Fatalf("page total=%d want=%d size=%d want=%d", page.Page.Total, want, len(page.Items), len(reference))
				}
				for i, row := range reference {
					if row.EventID != page.Items[i].EventID {
						t.Fatalf("unstable page offset=%d position=%d got=%s want=%s", offset, i, page.Items[i].EventID, row.EventID)
					}
				}
			}

		}
	}
}
