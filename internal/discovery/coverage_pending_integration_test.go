package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestCoveragePendingPostgresSeparatesProfileAndProtocolEvidence(t *testing.T) {
	db := hardwareIntegrationDB(t)
	ctx := context.Background()
	at := time.Now().UTC()
	for i, fixture := range []struct {
		ip, origin, status, kind, profile string
	}{
		{"192.0.2.1", "dhcp", "candidate", "", "mobile"},
		{"192.0.2.2", "arp", "candidate", "", ""},
		{"192.0.2.3", "dns_sd", "candidate", "", ""},
		{"192.0.2.4", "snmp", "", "", ""},
		{"192.0.2.5", "arp", "revoked", "printer", ""},
		{"192.0.2.6", "dns_sd", "conflict", "", ""},
		{"192.0.2.7", "arp", "identified", "printer", ""},
		{"192.0.2.7", "dhcp", "candidate", "", "desktop"},
	} {
		o := hardwareTestObservation(at.Add(-time.Minute))
		o.ID = fmt.Sprintf("pending-%d", i)
		o.MAC = fmt.Sprintf("00:11:22:33:44:%02x", i)
		o.IP, o.Origin, o.ModelName = fixture.ip, fixture.origin, ""
		o.ValidUntil = at.Add(time.Hour)
		o.Evidence = normalized.Event{Payload: map[string]any{"dhcp_candidate_type": fixture.profile}}
		raw, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO discovery_observation_latest VALUES($1,$2,$3,$4,$5,false,$6)`,
			o.ID, o.Key(), o.Origin, o.ObservedAt, o.ValidUntil, raw); err != nil {
			t.Fatal(err)
		}
		if fixture.status == "" {
			continue
		}
		if _, err := db.Exec(`INSERT INTO passive_hardware_current
 (identity_key,scope_key,device_key,sensor_id,campus_id,access_domain,vlan,mac,hardware_type,hardware_type_status,
  hardware_model,hardware_model_status,first_seen,last_seen,active_until,data)
 VALUES($1,'scope',$2,$3,$4,$5,$6,$7,$8,$9,'','',$10,$10,$11,'{}')`,
			HardwareIdentityKey(o.Node, o.Site, o.Domain, o.VLAN, o.VRF, o.MAC), o.Key(), o.Node, o.Site, o.Domain,
			o.VLAN, o.MAC, fixture.kind, fixture.status, o.ObservedAt, o.ValidUntil); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var baseline, report CoverageReport
	if err := coverageEvidenceCounts(ctx, tx, "sensor", at.Add(-24*time.Hour), at, &baseline); err != nil {
		t.Fatal(err)
	}
	if err := coverageIdentityAndPendingCounts(ctx, tx, "sensor", 24*time.Hour, at, &report); err != nil {
		t.Fatal(err)
	}
	if report.IdentityNoTypeIPv4 != baseline.IdentityNoTypeIPv4 || report.NoIdentityIPv4 != baseline.NoIdentityIPv4 ||
		report.TypedIPv4 != baseline.TypedIPv4 || !reflect.DeepEqual(report.IPv4TypeReview, baseline.IPv4TypeReview) {
		t.Fatal("IPv4 evidence counts differ from the basic coverage query")
	}
	got := map[string]CoverageIPv4PendingRow{}
	for _, row := range report.IPv4Pending {
		got[row.Status] = row
	}
	want := map[string]CoverageIPv4PendingRow{
		"with_profile":           {Status: "with_profile", DHCPOnly: 1},
		"without_profile":        {Status: "without_profile", NetworkOnly: 1, DeviceProtocol: 1},
		"withdrawn_confirmation": {Status: "withdrawn_confirmation", NetworkOnly: 1},
		"conflict":               {Status: "conflict", DeviceProtocol: 1},
		"unlinked":               {Status: "unlinked", DeviceProtocol: 1},
	}
	if !reflect.DeepEqual(got, want) || report.TypedIPv4 != 1 || *report.DumbTerminals != 1 || *report.ProfileCandidates != 2 {
		t.Fatalf("pending counts=%+v, confirmed=%d, dumb=%d, profile=%d", got, report.TypedIPv4, *report.DumbTerminals, *report.ProfileCandidates)
	}
}
