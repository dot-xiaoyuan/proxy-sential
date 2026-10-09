package store

import (
	"proxy-sentinel/internal/evidence"
	"testing"
	"time"
)

func TestSharedDeviceProfileMaterializesIdentityAccountAndAddressChanges(t *testing.T) {
	s, ctx := ownedRiskFreshnessReplayStore(t)
	s.sensorID = "archive-office"
	now := time.Now().UTC().Add(time.Second).Truncate(time.Microsecond)
	mac := "00:11:22:33:44:22"
	owner := "mac:" + mac
	ip := "192.0.2.122"
	if _, err := s.db.ExecContext(ctx, `INSERT INTO endpoint_entities(endpoint_id,primary_mac,entity_role,first_seen,last_seen) VALUES($1,$2,'endpoint',$3,$3)`, owner, mac, now); err != nil {
		t.Fatal(err)
	}
	fact := evidence.RouterEvidence{EvidenceID: "archive-router-dhcp", AssessmentID: "archive-router", EndpointID: owner, SensorID: s.sensorID, IP: ip, MAC: mac, Brand: "ZTE", Model: "SR7410-20", Role: "router", Kind: "router_signal", Source: "zeek", SourceFamily: "dhcp", Strength: "strong", Score: 70, RuleID: "model", RuleVersion: "fixture", FirstSeen: now.Format(time.RFC3339Nano), LastSeen: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)}
	if err := s.WriteRouterObservations(ctx, evidence.RouterResult{Evidence: []evidence.RouterEvidence{fact}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO device_address_leases(sensor_id,campus_id,event_id,ip,endpoint_id,action,observed_at,valid_until) VALUES($1,'','archive-lease',$2::inet,$3,'ack',$4,$5)`, s.sensorID, ip, owner, now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO account_sessions(session_id,account_id,endpoint_id,ip,mac,source,started_at,identity_confidence,raw_ref,vlan,nas_ip)
VALUES('archive-auth-exact','archive-account',$1,'198.51.100.122',$2,'ncu-srun4k',$3,.99,'{}','120','192.0.2.1')`, owner, mac, now); err != nil {
		t.Fatal(err)
	}
	dbs := &DBStore{pg: s}
	for index := 0; index < 20; index++ {
		found, err := dbs.processSharedDeviceProfileJob(ctx, "test")
		if err != nil {
			t.Fatal(err)
		}
		if !found {
			break
		}
	}
	page, err := s.ListSharedDeviceProfiles(ctx, SharedDeviceProfileQuery{Keyword: ip})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("materialized page: %+v %v", page, err)
	}
	p := page.Items[0]
	if !p.IdentityCurrent || p.IdentityState != "supported" || p.Role != "router" || p.AddressState != "verified" {
		t.Fatalf("identity or address projection missing: %+v", p)
	}
	if len(p.AuthBindings) != 1 || p.AuthBindings[0].AccountID != "archive-account" || p.AuthBindings[0].MatchBasis != "exact_endpoint" || len(p.AuthBindings[0].AssignedIPs) != 1 || p.AuthBindings[0].AssignedIPs[0] != "198.51.100.122" {
		t.Fatalf("exact authentication binding missing: %+v", p.AuthBindings)
	}
	profileID := p.ProfileID
	if _, err = s.db.ExecContext(ctx, `UPDATE account_sessions SET ended_at=$1,updated_at=$1 WHERE session_id='archive-auth-exact'`, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO account_sessions(session_id,account_id,endpoint_id,ip,mac,source,started_at,identity_confidence,raw_ref,updated_at)
VALUES('archive-auth-new','archive-account-new',$1,'198.51.100.123',$2,'ncu-srun4k',$3,.99,'{}',$3)`, owner, mac, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 20; index++ {
		found, processErr := dbs.processSharedDeviceProfileJob(ctx, "test-update")
		if processErr != nil {
			t.Fatal(processErr)
		}
		if !found {
			break
		}
	}
	page, err = (&DBStore{pg: s}).ListSharedDeviceProfiles(ctx, SharedDeviceProfileQuery{Keyword: mac})
	if err != nil || len(page.Items) != 1 || page.Items[0].ProfileID != profileID || page.Items[0].LatestAccountID != "archive-account-new" || page.Items[0].AccountConflict {
		t.Fatalf("latest account did not replace display while retaining profile: %+v %v", page, err)
	}
	if _, err = s.db.ExecContext(ctx, `UPDATE account_sessions SET ended_at=$1,updated_at=$1 WHERE session_id='archive-auth-new'`, now.Add(150*time.Second)); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 10; index++ {
		found, processErr := dbs.processSharedDeviceProfileJob(ctx, "test-session-ended")
		if processErr != nil {
			t.Fatal(processErr)
		}
		if !found {
			break
		}
	}
	page, err = s.ListSharedDeviceProfiles(ctx, SharedDeviceProfileQuery{Keyword: mac})
	if err != nil || len(page.Items) != 1 || page.Items[0].LatestAccountID != "archive-account-new" || page.Items[0].LatestAccountActive {
		t.Fatalf("ended session did not retain the latest reliable account: %+v %v", page, err)
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO device_address_leases(sensor_id,campus_id,event_id,ip,endpoint_id,action,observed_at,valid_until)
VALUES($1,'','archive-lease-new','192.0.2.123',$2,'ack',$3,$4)`, s.sensorID, owner, now.Add(3*time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 10; index++ {
		found, processErr := dbs.processSharedDeviceProfileJob(ctx, "test-address")
		if processErr != nil {
			t.Fatal(processErr)
		}
		if !found {
			break
		}
	}
	page, err = s.ListSharedDeviceProfiles(ctx, SharedDeviceProfileQuery{Keyword: mac})
	if err != nil || len(page.Items) != 1 || page.Items[0].ProfileID != profileID || page.Items[0].IP != "192.0.2.123" {
		t.Fatalf("address change did not update the same physical profile: %+v %v", page, err)
	}
	newOwner := "mac:00:11:22:33:44:99"
	if _, err = s.db.ExecContext(ctx, `INSERT INTO endpoint_entities(endpoint_id,primary_mac,entity_role,first_seen,last_seen) VALUES($1,'00:11:22:33:44:99','endpoint',$2,$2)`, newOwner, now.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO device_address_leases(sensor_id,campus_id,event_id,ip,endpoint_id,action,observed_at,valid_until)
VALUES($1,'','archive-lease-reused','192.0.2.123',$2,'ack',$3,$4)`, s.sensorID, newOwner, now.Add(4*time.Minute), now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 10; index++ {
		found, processErr := dbs.processSharedDeviceProfileJob(ctx, "test-reuse")
		if processErr != nil {
			t.Fatal(processErr)
		}
		if !found {
			break
		}
	}
	page, err = s.ListSharedDeviceProfiles(ctx, SharedDeviceProfileQuery{Keyword: mac})
	if err != nil || len(page.Items) != 1 || page.Items[0].ProfileID != profileID || page.Items[0].AddressState != "reassigned" {
		t.Fatalf("IP reuse merged hardware or kept stale ownership: %+v %v", page, err)
	}
	var history int
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM shared_device_profile_history WHERE profile_id=$1`, profileID).Scan(&history); err != nil || history < 2 {
		t.Fatalf("profile history missing: %d %v", history, err)
	}
	if _, err = s.db.ExecContext(ctx, `SELECT enqueue_shared_device_profile_job($1,'',$2,$3,$4::inet,'',$5)`, s.sensorID, owner, mac, "192.0.2.123", now.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 5; index++ {
		found, processErr := dbs.processSharedDeviceProfileJob(ctx, "test-idempotent-restart")
		if processErr != nil {
			t.Fatal(processErr)
		}
		if !found {
			break
		}
	}
	var afterReplay int
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM shared_device_profile_history WHERE profile_id=$1`, profileID).Scan(&afterReplay); err != nil || afterReplay != history {
		t.Fatalf("idempotent replay appended duplicate history: before=%d after=%d err=%v", history, afterReplay, err)
	}
}

func TestSharedDeviceProfileDoesNotBackfillPreCutoverEvidence(t *testing.T) {
	s, ctx := ownedRiskFreshnessReplayStore(t)
	s.sensorID = "cutover-office"
	var cutover time.Time
	if err := s.db.QueryRowContext(ctx, `SELECT cutover_at FROM shared_device_profile_runtime WHERE singleton`).Scan(&cutover); err != nil {
		t.Fatal(err)
	}
	mac := "00:11:22:33:55:66"
	endpoint := "mac:" + mac
	if _, err := s.db.ExecContext(ctx, `INSERT INTO endpoint_entities(endpoint_id,primary_mac,entity_role,first_seen,last_seen) VALUES($1,$2,'endpoint',$3,$3) ON CONFLICT DO NOTHING`, endpoint, mac, cutover.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	fact := evidence.RouterEvidence{EvidenceID: "pre-cutover-router", AssessmentID: "pre-cutover-assessment", EndpointID: endpoint, SensorID: s.sensorID, IP: "192.0.2.166", MAC: mac, Brand: "Example", Model: "Old", Role: "router", Kind: "router_signal", Source: "zeek", SourceFamily: "dhcp", Strength: "strong", Score: 70, RuleID: "model", RuleVersion: "fixture", FirstSeen: cutover.Add(-time.Hour).Format(time.RFC3339Nano), LastSeen: cutover.Add(-time.Hour).Format(time.RFC3339Nano), ExpiresAt: cutover.Add(time.Hour).Format(time.RFC3339Nano)}
	if err := s.WriteRouterObservations(ctx, evidence.RouterResult{Evidence: []evidence.RouterEvidence{fact}}); err != nil {
		t.Fatal(err)
	}
	var jobs int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM shared_device_profile_jobs WHERE endpoint_id=$1`, endpoint).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if jobs != 0 {
		t.Fatalf("pre-cutover evidence unexpectedly enqueued %d profile jobs", jobs)
	}
}

func TestSharedDeviceProfileRandomMACRequiresEventTimeDHCPBinding(t *testing.T) {
	s, ctx := ownedRiskFreshnessReplayStore(t)
	s.sensorID = "random-mac-office"
	now := time.Now().UTC().Add(time.Second).Truncate(time.Microsecond)
	mac, endpoint, ip := "02:11:22:33:44:88", "mac:02:11:22:33:44:88", "192.0.2.188"
	fact := evidence.RouterEvidence{EvidenceID: "random-mac-router", AssessmentID: "random-mac-assessment", EndpointID: endpoint, SensorID: s.sensorID, IP: ip, MAC: mac, Brand: "Example", Model: "Router", Role: "router", Kind: "router_signal", Source: "zeek", SourceFamily: "dhcp", Strength: "strong", Score: 70, RuleID: "model", RuleVersion: "fixture", FirstSeen: now.Format(time.RFC3339Nano), LastSeen: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)}
	if err := s.WriteRouterObservations(ctx, evidence.RouterResult{Evidence: []evidence.RouterEvidence{fact}}); err != nil {
		t.Fatal(err)
	}
	dbs := &DBStore{pg: s}
	for index := 0; index < 10; index++ {
		found, err := dbs.processSharedDeviceProfileJob(ctx, "random-without-dhcp")
		if err != nil {
			t.Fatal(err)
		}
		if !found {
			break
		}
	}
	page, err := s.ListSharedDeviceProfiles(ctx, SharedDeviceProfileQuery{Keyword: ip})
	if err != nil || len(page.Items) != 1 || page.Items[0].EndpointID != "" || page.Items[0].MAC != "" || !page.Items[0].AddressOnly {
		t.Fatalf("random MAC was treated as reliable without DHCP: %+v %v", page, err)
	}
	profileID := page.Items[0].ProfileID
	dhcpAt := now.Add(time.Second)
	if _, err = s.db.ExecContext(ctx, `INSERT INTO device_address_leases(sensor_id,campus_id,event_id,ip,endpoint_id,action,observed_at,valid_until)
VALUES($1,'','random-mac-lease',$2::inet,$3,'ack',$4,$5)`, s.sensorID, ip, endpoint, dhcpAt, dhcpAt.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 10; index++ {
		found, processErr := dbs.processSharedDeviceProfileJob(ctx, "random-with-dhcp")
		if processErr != nil {
			t.Fatal(processErr)
		}
		if !found {
			break
		}
	}
	page, err = s.ListSharedDeviceProfiles(ctx, SharedDeviceProfileQuery{Keyword: ip})
	if err != nil || len(page.Items) != 1 || page.Items[0].ProfileID != profileID || page.Items[0].EndpointID != endpoint || page.Items[0].MAC != mac || page.Items[0].AddressOnly {
		t.Fatalf("DHCP-confirmed random MAC did not upgrade the weak profile: %+v %v", page, err)
	}
}
