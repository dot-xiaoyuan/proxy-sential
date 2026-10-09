package policy

import (
	"testing"
	"time"
)

func TestWhitelistLegacyMatchingReplay(t *testing.T) {
	now := time.Now().UTC()
	subject := WhitelistSubject{AccountID: "student", IP: "192.0.2.10", MAC: "AA-BB-CC-DD-EE-FF", GroupID: "7", CampusID: "ncu", AccessDomain: "wired"}
	for _, tc := range []struct{ kind, value string }{{"ip", "::ffff:192.0.2.10"}, {"account", "student"}, {"mac", "aabb.ccdd.eeff"}, {"network", "192.0.2.3/24"}, {"network", "192.0.2.10 - 192.0.2.20"}, {"group", "7"}} {
		e := WhitelistEntry{ID: "test", Type: tc.kind, Value: tc.value, Reason: "测试豁免", Enabled: true, ValidFrom: now.Add(-time.Minute)}
		if err := NormalizeWhitelist(&e); err != nil {
			t.Fatal(err)
		}
		if MatchWhitelist([]WhitelistEntry{e}, subject, now) == nil {
			t.Fatalf("legacy matching lost %+v", tc)
		}
		e.CampusID = "other"
		if MatchWhitelist([]WhitelistEntry{e}, subject, now) != nil {
			t.Fatal("cross-campus exemption")
		}
	}
	e := WhitelistEntry{ID: "group", Type: "group", Value: "student", Reason: "类型隔离", Enabled: true, ValidFrom: now.Add(-time.Minute)}
	if MatchWhitelist([]WhitelistEntry{e}, subject, now) != nil {
		t.Fatal("group identifier matched username")
	}
	for _, value := range []string{"192.0.2.20-192.0.2.10", "192.0.2.10-2001:db8::1", "bad/24"} {
		e.Type = "network"
		e.Value = value
		if NormalizeWhitelist(&e) == nil {
			t.Fatal("invalid network admitted", value)
		}
	}
	e.Type = "ip"
	e.Value = "192.0.2.10"
	e.Enabled = false
	if MatchWhitelist([]WhitelistEntry{e}, subject, now) != nil {
		t.Fatal("disabled entry matched")
	}
	e.Enabled = true
	e.ExpiresAt = &now
	if MatchWhitelist([]WhitelistEntry{e}, subject, now) != nil {
		t.Fatal("expired entry matched")
	}
}

func TestWhitelistSuppressesPolicyWithoutDiscardingEvidence(t *testing.T) {
	now := time.Now().UTC()
	p := Definition{ID: "p", CooldownSeconds: 60}
	in := Input{AccountID: "student", Known: true, Violated: true, EvidenceIDs: []string{"proof"}}
	e := Execution{ID: "e", AccountID: in.AccountID, Definition: p, State: "awaiting_approval", StartedAt: now.Add(-time.Minute), Stages: []StageState{{Status: "pending_action", ApprovedSessionBindings: []string{"old"}}}}
	e = SuppressWhitelist(p, e, in, WhitelistEntry{ID: "vip"}, now)
	if e.State != "whitelist_suppressed" || e.Stages[0].Status != "cancelled" || len(e.Stages[0].ApprovedSessionBindings) != 0 || len(e.EvidenceIDs) != 1 || !e.StartedAt.IsZero() {
		t.Fatalf("unsafe suppression %+v", e)
	}
	before := e.CooldownUntil
	e = SuppressWhitelist(p, e, in, WhitelistEntry{ID: "vip"}, now.Add(time.Second))
	if !e.CooldownUntil.Equal(before) {
		t.Fatal("whitelist extended cooldown repeatedly")
	}
}
