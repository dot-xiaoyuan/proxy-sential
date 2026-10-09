package store

import (
	"net/http"
	"net/http/httptest"
	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/sharedaccess"
	"testing"
	"time"
)

func TestSharedDeviceArchiveHolidayAndIPReassignmentReplay(t *testing.T) {
	s, ctx := ownedRiskFreshnessReplayStore(t)
	s.sensorID = "archive-office"
	now := time.Now().UTC().Truncate(time.Microsecond)
	mac := "00:11:22:33:44:22"
	owner := "mac:" + mac
	ip := "192.0.2.122"
	fact := evidence.RouterEvidence{EvidenceID: "archive-router-dhcp", AssessmentID: "archive-router", EndpointID: owner, SensorID: s.sensorID, IP: ip, MAC: mac, Brand: "ZTE", Model: "SR7410-20", Role: "router", Kind: "router_signal", Source: "zeek", SourceFamily: "dhcp", Strength: "strong", Score: 60, RuleID: "model", RuleVersion: "fixture", FirstSeen: now.Add(-7 * 24 * time.Hour).Format(time.RFC3339Nano), LastSeen: now.Add(-7 * 24 * time.Hour).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)}
	if err := s.WriteRouterObservations(ctx, evidence.RouterResult{Evidence: []evidence.RouterEvidence{fact}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE router_evidence_facts SET expires_at=$2 WHERE evidence_id=$1`, fact.EvidenceID, now.Add(-6*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	behavior := sharedaccess.BehaviorAssessment{ObservationID: "archive-shared-old", SensorID: s.sensorID, EndpointID: owner, IP: ip, RuleVersion: sharedaccess.BehaviorRuleVersion, SignalGroups: []string{"coexisting_device_models"}, Status: "confirmed", Confidence: 90, CoverageState: "verified", StrongAnchor: "coexisting_device_models", DeviceLowerBound: 2, FirstSeen: now.Add(-7 * 24 * time.Hour), LastSeen: now.Add(-7 * 24 * time.Hour), WindowStart: now.Add(-7*24*time.Hour - time.Minute*10), WindowEnd: now.Add(-7 * 24 * time.Hour), ExpiresAt: now.Add(-6 * 24 * time.Hour)}
	dbs := &DBStore{pg: s}
	if err := dbs.persistSharedBehavior(ctx, behavior); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO device_address_leases(sensor_id,campus_id,event_id,ip,endpoint_id,action,observed_at,valid_until) VALUES($1,'','archive-lease',$2::inet,$3,'ack',$4,$5)`, s.sensorID, ip, owner, now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO account_sessions(session_id,account_id,endpoint_id,ip,mac,source,started_at,identity_confidence,raw_ref,vlan,nas_ip)
VALUES('archive-auth-exact','archive-account',$1,'198.51.100.122',$2,'ncu-srun4k',$3,.99,'{}','120','192.0.2.1'),
('archive-auth-ip-only','must-not-bind','mac:00:11:22:33:44:99',$4::inet,'00:11:22:33:44:99','ncu-srun4k',$3,.99,'{}','120','192.0.2.1')`, owner, mac, now.Add(-time.Minute), ip); err != nil {
		t.Fatal(err)
	}
	page, err := s.ListSharedDeviceProfiles(ctx, SharedDeviceProfileQuery{Keyword: ip})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("archive page: %+v %v", page, err)
	}
	p := page.Items[0]
	if p.IdentityCurrent || p.IdentityState != "historical" || p.Role != "router" || p.AddressState != "verified" || p.CurrentShared || p.LastSharedAt == nil || !p.LastSharedAt.Equal(behavior.LastSeen) {
		t.Fatalf("holiday conflated identity, activity or sharing: %+v", p)
	}
	if len(p.AuthBindings) != 1 || p.AuthBindings[0].AccountID != "archive-account" || p.AuthBindings[0].MatchBasis != "exact_endpoint" || len(p.AuthBindings[0].AssignedIPs) != 1 || p.AuthBindings[0].AssignedIPs[0] != "198.51.100.122" {
		t.Fatalf("shared device profile did not preserve exact authentication binding: %+v", p.AuthBindings)
	}
	weakMAC := "00:11:22:33:44:77"
	weakOwner := "mac:" + weakMAC
	weakFact := evidence.RouterEvidence{EvidenceID: "archive-router-ssdp", AssessmentID: "archive-router-weak", EndpointID: weakOwner, SensorID: s.sensorID, IP: "192.168.1.1", MAC: weakMAC, Role: "router", Kind: "router_signal", Source: "zeek", SourceFamily: "ssdp_upnp", Strength: "weak", Score: 20, RuleID: "ssdp", RuleVersion: "fixture", Explanation: "UPnP gateway advertisement", FirstSeen: now.Add(-time.Minute).Format(time.RFC3339Nano), LastSeen: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)}
	if err = s.WriteRouterObservations(ctx, evidence.RouterResult{Evidence: []evidence.RouterEvidence{weakFact}}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO account_sessions(session_id,account_id,endpoint_id,ip,mac,source,started_at,identity_confidence,raw_ref)
VALUES('archive-auth-weak','archive-weak-account',$1,'198.51.100.177',$2,'ncu-srun4k',$3,.99,'{}')`, weakOwner, weakMAC, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	weakPage, err := s.ListSharedDeviceProfiles(ctx, SharedDeviceProfileQuery{Keyword: weakMAC})
	if err != nil || len(weakPage.Items) != 1 || weakPage.Items[0].IdentityState != "reference" || weakPage.Items[0].IdentityCurrent || len(weakPage.Items[0].AuthBindings) != 1 || weakPage.Items[0].AuthBindings[0].AccountID != "archive-weak-account" {
		t.Fatalf("auth-backed router lead missing or promoted: %+v %v", weakPage, err)
	}
	current, err := s.ListSharedBehavior(ctx, SharedBehaviorQuery{IP: ip})
	if err != nil || len(current.Items) != 0 {
		t.Fatalf("historical sharing revived: %+v %v", current, err)
	}
	history, err := s.ListSharedBehavior(ctx, SharedBehaviorQuery{IP: ip, View: "history"})
	if err != nil || len(history.Items) != 1 || history.Items[0].Current {
		t.Fatalf("historical archive missing or promoted: %+v %v", history, err)
	}
	behavior.ObservationID = "archive-shared-current"
	behavior.LastSeen = now
	behavior.WindowStart = now.Add(-10 * time.Minute)
	behavior.WindowEnd = now
	behavior.ExpiresAt = now.Add(time.Hour)
	if err = dbs.persistSharedBehavior(ctx, behavior); err != nil {
		t.Fatal(err)
	}
	if err = dbs.publishSharedBehaviorCurrent(ctx, s.sensorID, []string{behavior.ObservationID}); err != nil {
		t.Fatal(err)
	}
	page, err = s.ListSharedDeviceProfiles(ctx, SharedDeviceProfileQuery{Keyword: ip})
	if err != nil || !page.Items[0].CurrentShared {
		t.Fatalf("fresh independent sharing not shown: %+v %v", page, err)
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO device_address_leases(sensor_id,campus_id,event_id,ip,endpoint_id,action,observed_at,valid_until) VALUES($1,'','archive-reassigned',$2::inet,'mac:00:11:22:33:44:99','ack',$3,$4)`, s.sensorID, ip, now.Add(-30*time.Second), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	page, err = s.ListSharedDeviceProfiles(ctx, SharedDeviceProfileQuery{Keyword: ip})
	if err != nil || page.Items[0].AddressState != "reassigned" || page.Items[0].CurrentShared {
		t.Fatalf("reassigned IP attributed fresh sharing to old hardware: %+v %v", page, err)
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO device_address_leases(sensor_id,campus_id,event_id,ip,endpoint_id,action,observed_at,valid_until) VALUES($1,'','archive-moved','192.0.2.123',$2,'ack',$3,$4)`, s.sensorID, owner, now.Add(-15*time.Second), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "collection unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	ch, err := NewClickHouseStore(ClickHouseOptions{DSN: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	degraded, err := (&DBStore{pg: s, ch: ch}).ListSharedDeviceProfiles(ctx, SharedDeviceProfileQuery{Keyword: ip})
	if err != nil || len(degraded.Items) != 1 || degraded.ActivityState != "unavailable" || degraded.Items[0].Role != "router" {
		t.Fatalf("activity failure hid durable identity: %+v %v", degraded, err)
	}
	var factsCount int
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM router_evidence_facts WHERE evidence_id=$1`, fact.EvidenceID).Scan(&factsCount); err != nil || factsCount != 1 {
		t.Fatal("archive reads changed original evidence", factsCount, err)
	}
}
