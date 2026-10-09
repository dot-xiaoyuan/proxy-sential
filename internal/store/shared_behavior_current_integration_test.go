package store

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"os"
	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/sharedaccess"
	"testing"
	"time"
)

func TestSharedBehaviorCurrentWindowRetiresFalsePositivesPostgres(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin := stdlib.OpenDB(*cfg)
	defer admin.Close()
	schema := fmt.Sprintf("shared_discovery_%d", time.Now().UnixNano())
	if _, err = admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec("DROP SCHEMA " + schema + " CASCADE")
	cfg.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*cfg)
	defer db.Close()
	for _, name := range []string{"059_router_observations.sql", "066_shared_behavior_observations.sql", "067_shared_behavior_rule_history.sql", "075_shared_behavior_current_discovery.sql"} {
		raw, readErr := os.ReadFile("../../migrations/postgres/" + name)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if _, err = db.Exec(string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	s := &DBStore{pg: &PostgresStore{db: db}}
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	item := sharedaccess.BehaviorAssessment{ObservationID: "old-phone", SensorID: "office", IP: "192.0.2.82", RuleVersion: "shared-behavior/v8", Status: "confirmed", Confidence: 100, CoverageState: "verified", FirstSeen: now.Add(-time.Hour), LastSeen: now.Add(-time.Hour), WindowStart: now.Add(-70 * time.Minute), WindowEnd: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour), SignalGroups: []string{"tcp_stack", "tls_stack", "ua_os"}}
	if err = s.persistSharedBehavior(ctx, item); err != nil {
		t.Fatal(err)
	}
	item.ObservationID = "new-router"
	item.IP = "192.0.2.63"
	item.RuleVersion = sharedaccess.BehaviorRuleVersion
	item.StrongAnchor = "coexisting_device_models"
	item.DeviceLowerBound = 2
	item.LastSeen = now
	item.WindowStart = now.Add(-10 * time.Minute)
	item.WindowEnd = now
	if err = s.persistSharedBehavior(ctx, item); err != nil {
		t.Fatal(err)
	}
	item.ObservationID = "weak-phone"
	item.IP = "192.0.2.82"
	item.Status = "candidate"
	item.Confidence = 59
	item.StrongAnchor = ""
	item.DeviceLowerBound = 0
	if err = s.persistSharedBehavior(ctx, item); err != nil {
		t.Fatal(err)
	}
	if err = s.publishSharedBehaviorCurrent(ctx, "office", []string{"new-router", "weak-phone"}); err != nil {
		t.Fatal(err)
	}
	page, err := s.ListSharedBehavior(ctx, SharedBehaviorQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].IP != "192.0.2.63" || page.Page.Total != 1 {
		t.Fatalf("false positive appeared in default discovery: %+v", page)
	}
	page, err = s.ListSharedBehavior(ctx, SharedBehaviorQuery{Status: "candidate"})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("explicit weak-evidence review failed: %+v %v", page, err)
	}
	if err = s.publishSharedBehaviorCurrent(ctx, "office", nil); err != nil {
		t.Fatal(err)
	}
	page, err = s.ListSharedBehavior(ctx, SharedBehaviorQuery{})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("old confirmation revived after empty complete window: %+v %v", page, err)
	}
	var observations, history int
	if err = db.QueryRow("SELECT count(*) FROM shared_behavior_observations").Scan(&observations); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow("SELECT count(*) FROM shared_behavior_observation_history").Scan(&history); err != nil {
		t.Fatal(err)
	}
	if observations != 3 || history != 3 {
		t.Fatalf("retiring current flags removed audit evidence: observations=%d history=%d", observations, history)
	}
}

func TestSharedGatewayRouterProjectionRetiresWithItsWindowPostgres(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin := stdlib.OpenDB(*cfg)
	defer admin.Close()
	schema := fmt.Sprintf("shared_router_%d", time.Now().UnixNano())
	if _, err = admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec("DROP SCHEMA " + schema + " CASCADE")
	cfg.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*cfg)
	defer db.Close()
	for _, name := range []string{"059_router_observations.sql", "066_shared_behavior_observations.sql", "067_shared_behavior_rule_history.sql", "075_shared_behavior_current_discovery.sql"} {
		raw, readErr := os.ReadFile("../../migrations/postgres/" + name)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if _, err = db.Exec(string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	s := &DBStore{pg: &PostgresStore{db: db}}
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	legacy := sharedaccess.BehaviorAssessment{ObservationID: "legacy-phone", SensorID: "office", IP: "192.0.2.82", EndpointID: "phone", RuleVersion: "shared-behavior/v8", Status: "confirmed", Confidence: 100, CoverageState: "verified", FirstSeen: now.Add(-time.Hour), LastSeen: now.Add(-time.Hour), WindowStart: now.Add(-70 * time.Minute), WindowEnd: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), SignalGroups: []string{"tcp_stack", "tls_stack", "ua_os"}}
	if err = s.persistSharedBehavior(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	fact := evidence.RouterEvidence{EvidenceID: "legacy-role", AssessmentID: "phone-router", EndpointID: "phone", IP: legacy.IP, Kind: "router_signal", Role: "router", Source: "shared-behavior-materializer", SourceFamily: "shared_gateway_behavior", Strength: "strong", Score: 85, RuleID: "verified-shared-gateway-role", RuleVersion: fingerprint.DefaultRouterRuleSet().Version, FirstSeen: legacy.FirstSeen.Format(time.RFC3339Nano), LastSeen: legacy.LastSeen.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)}
	if err = s.WriteRouterObservations(ctx, evidence.RouterResult{RuleVersion: fact.RuleVersion, Evidence: []evidence.RouterEvidence{fact}}); err != nil {
		t.Fatal(err)
	}
	current := legacy
	current.ObservationID = "current-router"
	current.EndpointID = "gateway"
	current.IP = "192.0.2.63"
	current.RuleVersion = sharedaccess.BehaviorRuleVersion
	current.StrongAnchor = "coexisting_device_models"
	current.DeviceLowerBound = 2
	current.SignalGroups = []string{"tcp_stack", "tls_stack", "device_model"}
	current.FirstSeen = now.Add(-10 * time.Minute)
	current.LastSeen = now
	current.WindowStart = current.FirstSeen
	current.WindowEnd = now
	if err = s.persistSharedBehavior(ctx, current); err != nil {
		t.Fatal(err)
	}
	if err = s.writeSharedGatewayRouterEvidence(ctx, current); err != nil {
		t.Fatal(err)
	}
	// Refreshing an old 24-hour bridge must adopt the current window TTL.
	if _, err = db.Exec("UPDATE router_evidence_facts SET expires_at=$1 WHERE ip=$2::inet", now.Add(24*time.Hour), current.IP); err != nil {
		t.Fatal(err)
	}
	if err = s.writeSharedGatewayRouterEvidence(ctx, current); err != nil {
		t.Fatal(err)
	}
	var bridgeExpiry time.Time
	if err = db.QueryRow("SELECT expires_at FROM router_evidence_facts WHERE ip=$1::inet", current.IP).Scan(&bridgeExpiry); err != nil {
		t.Fatal(err)
	}
	if !bridgeExpiry.Equal(current.WindowEnd.Add(20 * time.Minute)) {
		t.Fatalf("bridge retained legacy TTL: %v", bridgeExpiry)
	}
	// A mixed assessment must be recomputed from its independent hardware fact,
	// rather than retaining the revoked behavioral score.
	mixed := legacy
	mixed.ObservationID = "legacy-mixed"
	mixed.IP = "192.0.2.22"
	mixed.EndpointID = "mesh"
	if err = s.persistSharedBehavior(ctx, mixed); err != nil {
		t.Fatal(err)
	}
	stale := fact
	stale.EvidenceID = "mixed-stale"
	stale.AssessmentID = "mesh-router"
	stale.EndpointID = "mesh"
	stale.IP = mixed.IP
	hardware := stale
	hardware.EvidenceID = "mesh-hardware"
	hardware.Source = "packet-sidecar"
	hardware.SourceFamily = "ieee1905"
	hardware.Score = 70
	if err = s.WriteRouterObservations(ctx, evidence.RouterResult{RuleVersion: fact.RuleVersion, Evidence: []evidence.RouterEvidence{stale, hardware}}); err != nil {
		t.Fatal(err)
	}
	if err = s.publishSharedBehaviorCurrent(ctx, "office", []string{current.ObservationID}); err != nil {
		t.Fatal(err)
	}
	page, err := s.ListRouterObservations(ctx, RouterQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("legacy behavioral-only router remained visible: %+v", page)
	}
	for _, item := range page.Items {
		if item.IP == legacy.IP {
			t.Fatalf("phone retained router identity: %+v", item)
		}
		if item.IP == mixed.IP && item.Confidence != 70 {
			t.Fatalf("independent hardware assessment retained stale score: %+v", item)
		}
	}
	summaries, err := s.RouterObservationSummaries(ctx, []string{"phone", "gateway", "mesh"})
	if err != nil {
		t.Fatal(err)
	}
	if _, present := summaries["phone"]; present {
		t.Fatal("endpoint summary revived legacy router")
	}
	if len(summaries) != 2 {
		t.Fatalf("current or independent router lost: %+v", summaries)
	}
	if err = s.publishSharedBehaviorCurrent(ctx, "office", nil); err != nil {
		t.Fatal(err)
	}
	page, err = s.ListRouterObservations(ctx, RouterQuery{})
	if err != nil || len(page.Items) != 1 || page.Items[0].IP != mixed.IP {
		t.Fatalf("empty current window retained derived role or removed hardware: %+v %v", page, err)
	}
	var count int
	if err = db.QueryRow("SELECT count(*) FROM router_evidence_facts").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Fatalf("retirement deleted historical router evidence: %d", count)
	}
	detail, found, err := s.GetRouterObservation(ctx, "phone-router")
	if err != nil || !found {
		t.Fatalf("retired history could not be opened: %v", err)
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err = json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if document["current"] != false {
		t.Fatalf("expired route detail still appears current: %s", raw)
	}
	// Partial expiry must remove the old strong score even if another weak
	// role fact keeps the projection's overall expiry in the future.
	aux := hardware
	aux.EvidenceID = "mesh-auxiliary"
	aux.SourceFamily = "software"
	aux.Strength = "medium"
	aux.Score = 30
	aux.LastSeen = now.Format(time.RFC3339Nano)
	if err = s.WriteRouterObservations(ctx, evidence.RouterResult{RuleVersion: aux.RuleVersion, Evidence: []evidence.RouterEvidence{aux}}); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE router_evidence_facts SET expires_at=now()-interval '1 second' WHERE evidence_id=$1", hardware.EvidenceID); err != nil {
		t.Fatal(err)
	}
	if n, refreshErr := s.pg.refreshExpiredRouterAssessments(ctx, 50); refreshErr != nil || n != 1 {
		t.Fatalf("partial expiry was not refreshed: count=%d err=%v", n, refreshErr)
	}
	detail, found, err = s.GetRouterObservation(ctx, "mesh-router")
	if err != nil || !found || detail.Confidence != 30 || detail.Status != "candidate" {
		t.Fatalf("expired strong score survived a weak role fact: %+v %v", detail, err)
	}
	if n, refreshErr := s.pg.refreshExpiredRouterAssessments(ctx, 50); refreshErr != nil || n != 0 {
		t.Fatalf("expiry repair was not idempotent: %d %v", n, refreshErr)
	}
	// Canonical SQL eligibility must change together with the JSON evidence;
	// an out-of-order old positive must not replace the newer conflict.
	newer := hardware
	newer.LastSeen = now.Format(time.RFC3339Nano)
	newer.Score = -40
	newer.Conflict = true
	newer.Exclusion = true
	newer.Role = "endpoint"
	if err = s.WriteRouterObservations(ctx, evidence.RouterResult{RuleVersion: newer.RuleVersion, Evidence: []evidence.RouterEvidence{newer}}); err != nil {
		t.Fatal(err)
	}
	if err = s.WriteRouterObservations(ctx, evidence.RouterResult{RuleVersion: hardware.RuleVersion, Evidence: []evidence.RouterEvidence{hardware}}); err != nil {
		t.Fatal(err)
	}
	var canonicalScore int
	var conflict, exclusion bool
	if err = db.QueryRow("SELECT score,conflict,exclusion FROM router_evidence_facts WHERE evidence_id=$1", hardware.EvidenceID).Scan(&canonicalScore, &conflict, &exclusion); err != nil {
		t.Fatal(err)
	}
	if canonicalScore != -40 || !conflict || !exclusion {
		t.Fatalf("new conflict was inconsistent or overwritten by an old positive: %d %t %t", canonicalScore, conflict, exclusion)
	}
}
