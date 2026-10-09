package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
