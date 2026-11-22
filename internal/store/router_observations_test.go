package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/evidence"
)

func TestRouterObservationPageAlwaysSerializesHasMore(t *testing.T) {
	raw, err := json.Marshal(RouterAssessmentPage{Items: []evidence.RouterAssessment{}, Page: RouterAssessmentPageInfo{Limit: 20}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"has_more":false`) {
		t.Fatalf("last page must explicitly report has_more=false: %s", raw)
	}
}

func TestRouterObservationReportCountsDeviceWinners(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	mock.ExpectQuery(`SELECT now\(\).*DISTINCT ON \(device_key\).*expires_at>now\(\).*ip IS NOT NULL.*active_router_fact.*role=\$1.*ORDER BY device_key,status_rank DESC`).
		WithArgs("router").
		WillReturnRows(sqlmock.NewRows([]string{"now", "candidate", "likely", "confirmed"}).AddRow(now, 12, 3, 0))
	report, err := (&PostgresStore{db: db}).GetRouterObservationReport(context.Background())
	if err != nil || report != (RouterObservationReport{AsOf: now, Candidate: 12, Likely: 3}) {
		t.Fatalf("unexpected report: %+v err=%v", report, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRouterObservationListUsesSeekAndLookahead(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherFunc(func(_, actual string) error {
		if !strings.Contains(actual, "WITH filtered AS NOT MATERIALIZED") || !strings.Contains(actual, "LIMIT 1") || strings.Contains(actual, "OVER(") || strings.Contains(actual, "count(*)") || strings.Contains(actual, " OFFSET ") {
			return fmt.Errorf("router list is not a seek query: %s", actual)
		}
		return nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 11, 16, 1, 2, 3, 0, time.UTC)
	columns := []string{"assessment", "confidence", "assessment_id", "first_seen", "last_seen", "expires_at"}
	mock.ExpectQuery("list").WithArgs(2).WillReturnRows(sqlmock.NewRows(columns).
		AddRow([]byte(`{"assessment_id":"a","confidence":90}`), 90, "a", now.Add(-time.Hour), now, now.Add(time.Hour)).
		AddRow([]byte(`{"assessment_id":"b","confidence":80}`), 80, "b", now.Add(-time.Hour), now.Add(-time.Minute), now.Add(time.Hour)))
	store := &PostgresStore{db: db}
	query := RouterQuery{Role: "network", IncludeCandidates: true, Limit: 1}
	first, err := store.ListRouterObservations(context.Background(), query)
	if err != nil || len(first.Items) != 1 || first.Items[0].AssessmentID != "a" || !first.Page.HasMore || first.Page.NextCursor == nil || first.Page.Total != 0 {
		t.Fatalf("first seek page: %+v err=%v", first, err)
	}
	query.SeekCursor = *first.Page.NextCursor
	mock.ExpectQuery("list").WithArgs(90, now, "a", 2).WillReturnRows(sqlmock.NewRows(columns).
		AddRow([]byte(`{"assessment_id":"b","confidence":80}`), 80, "b", now.Add(-time.Hour), now.Add(-time.Minute), now.Add(time.Hour)))
	second, err := store.ListRouterObservations(context.Background(), query)
	if err != nil || len(second.Items) != 1 || second.Items[0].AssessmentID != "b" || second.Page.HasMore || second.Page.NextCursor != nil {
		t.Fatalf("second seek page: %+v err=%v", second, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRouterObservationSeekCursorScopesFilters(t *testing.T) {
	base := RouterQuery{Role: "router", Limit: 20}
	cursor := routerObservationCursor{Confidence: 82, LastSeen: time.Date(2026, 11, 16, 1, 2, 3, 0, time.UTC), AssessmentID: "router-a", Scope: routerObservationCursorScope(base)}
	encoded := encodeRouterObservationCursor(cursor)
	decoded, err := decodeRouterObservationCursor(encoded, routerObservationCursorScope(RouterQuery{Role: "router", Limit: 50}))
	if err != nil || decoded != cursor {
		t.Fatalf("same filters should accept cursor: cursor=%+v err=%v", decoded, err)
	}
	if _, err := decodeRouterObservationCursor(encoded, routerObservationCursorScope(RouterQuery{Role: "ap", Limit: 20})); err == nil {
		t.Fatal("cursor must reject another filter scope")
	}
	if _, err := decodeRouterObservationCursor("bad-cursor", cursor.Scope); err == nil {
		t.Fatal("malformed cursor must be rejected")
	}
}

func TestRouterWhereIncludesServerFilters(t *testing.T) {
	minimum, maximum, infrastructure := 60, 80, true
	where, args, err := routerWhere(RouterQuery{Keyword: "MSR", IP: "192.0.2.10", MAC: "AA:BB:CC:DD:EE:FF", VLAN: "120", Brand: "H3C", Model: "MSR3600", Role: "router", Status: "likely", Source: "software", ConfidenceMin: &minimum, ConfidenceMax: &maximum, FirstSeenFrom: "2026-09-24T00:00:00Z", FirstSeenTo: "2026-09-24T12:00:00Z", LastSeenFrom: "2026-09-24T01:00:00Z", LastSeenTo: "2026-09-24T13:00:00Z", Infrastructure: &infrastructure})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"expires_at>now()", "ip IS NOT NULL", "brand_reference_only=false", "assessment_id ILIKE", "ip=", "lower(mac)", "ANY(vlans)", "lower(brand)", "lower(model)", "role=", "status=", "ANY(sources)", "confidence >=", "confidence <=", "infrastructure=", "first_seen >=", "last_seen <="} {
		if !strings.Contains(where, fragment) {
			t.Fatalf("missing %q in %s", fragment, where)
		}
	}
	if len(args) != 16 {
		t.Fatalf("unexpected args: %#v", args)
	}
}

func TestRouterWhereDefaultsToAddressedRoutersOnly(t *testing.T) {
	where, args, err := routerWhere(RouterQuery{})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"ip IS NOT NULL", "brand_reference_only=false", "role='router'", "status IN('likely','confirmed')", "active_router_fact.expires_at>now()", "COALESCE(active_router_fact.data->>'brand_reference_only','false')='false'", "active_router_fact.data->>'role'='router'"} {
		if !strings.Contains(where, fragment) {
			t.Fatalf("missing default precision filter %q in %s", fragment, where)
		}
	}
	if len(args) != 0 {
		t.Fatalf("unexpected default args: %#v", args)
	}
}

func TestRouterWhereAllowsExplicitAccessPointRole(t *testing.T) {
	where, args, err := routerWhere(RouterQuery{Role: "ap"})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"role=", "active_router_fact.data->>'role'='ap'", "status IN('likely','confirmed')"} {
		if !strings.Contains(where, fragment) {
			t.Fatalf("missing explicit AP filter %q in %s", fragment, where)
		}
	}
	if len(args) != 1 || args[0] != "ap" {
		t.Fatalf("unexpected AP args: %#v", args)
	}
}

func TestRouterWhereCanIncludeCurrentCandidates(t *testing.T) {
	where, _, err := routerWhere(RouterQuery{Role: "router", IncludeCandidates: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(where, "status IN('likely','confirmed')") {
		t.Fatalf("candidate-inclusive query must not hide candidates: %s", where)
	}
}

func TestRouterWhereFiltersCurrentExactAuthenticationBindings(t *testing.T) {
	value := true
	where, args, err := routerWhere(RouterQuery{HasAuthBinding: &value})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"account_identity_session_projection", "account_identity_projection_sources", "account_sessions", "router_assessments.endpoint_id IN", "regexp_replace(lower(router_assessments.mac)", "auth_session.ended_at IS NULL"} {
		if !strings.Contains(where, fragment) {
			t.Fatalf("missing exact authentication binding predicate %q in %s", fragment, where)
		}
	}
	if len(args) != 0 {
		t.Fatalf("authentication filter must not change positional arguments: %#v", args)
	}
}

func TestRouterWhereRejectsInvalidTime(t *testing.T) {
	if _, _, err := routerWhere(RouterQuery{FirstSeenFrom: "yesterday"}); err == nil {
		t.Fatal("expected invalid RFC3339 time to fail")
	}
}

func TestRouterObservationMigrationIsAdditiveAndIndexed(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "postgres", "059_router_observations.sql")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sql := string(body)
	for _, fragment := range []string{"CREATE TABLE IF NOT EXISTS router_rule_versions", "CREATE TABLE IF NOT EXISTS router_evidence_facts", "CREATE TABLE IF NOT EXISTS router_assessments", "CREATE TABLE IF NOT EXISTS router_assessment_history", "router_assessment_status_score", "router_assessment_sources", "router_assessment_vlans"} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("migration missing %q", fragment)
		}
	}
	for _, destructive := range []string{"DROP TABLE", "TRUNCATE", "DELETE FROM"} {
		if strings.Contains(strings.ToUpper(sql), destructive) {
			t.Fatalf("router observation migration must stay additive: found %s", destructive)
		}
	}
}

func TestRouterObservationSeekMigrationRejectsInvalidPrebuiltIndex(t *testing.T) {
	raw, err := os.ReadFile("../../migrations/postgres/252_router_assessment_list_seek.sql")
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, required := range []string{"router_assessment_list_seek", "IF EXISTS (SELECT 1 FROM public.router_assessments LIMIT 1)", "i.indisvalid", "i.indisready", "i.indislive", "i.indoption::text='3 3 0'", "i.indnkeyatts=3", "predicate IN", "RAISE EXCEPTION"} {
		if !strings.Contains(body, required) {
			t.Fatalf("seek migration does not validate %q", required)
		}
	}
}

func TestRouterSNMPSignalMigrationKeepsBoundedStreamAndBackfills(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "clickhouse", "033_router_snmp_signal.sql")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sql := string(body)
	for _, fragment := range []string{"router_signal_events_v1_mv", "source_event_type IN ('dhcp','software','lldp','cdp','ssdp','snmp')", "timestamp>=now()-INTERVAL 24 HOUR", "source_event_type='snmp'"} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("SNMP router stream migration missing %q", fragment)
		}
	}
	for _, destructive := range []string{"DROP TABLE", "TRUNCATE", "DELETE FROM"} {
		if strings.Contains(strings.ToUpper(sql), destructive) {
			t.Fatalf("SNMP router stream migration must not alter table data: found %s", destructive)
		}
	}
}

func TestRouterSNMPReplayMigrationOnlyRewindsRecognitionCursor(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "postgres", "085_router_snmp_replay.sql")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToUpper(string(body))
	for _, fragment := range []string{"UPDATE ROUTER_RECOGNITION_STATE", "INTERVAL '24 HOURS'", "CURSOR_EVENT_ID=''", "LEASE_UNTIL='-INFINITY'", "NOT EXISTS", "SOURCE_FAMILY='SNMP_MANAGEMENT'"} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("SNMP replay migration missing %q", fragment)
		}
	}
	for _, destructive := range []string{"DELETE FROM", "DROP TABLE", "TRUNCATE"} {
		if strings.Contains(sql, destructive) {
			t.Fatalf("SNMP replay migration must preserve observations: found %s", destructive)
		}
	}
}
