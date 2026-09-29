package policy

import (
	"fmt"
	"testing"
	"time"
)

func sessions(now time.Time) []Session {
	return []Session{{ID: "s1", AccountID: "a", EndpointID: "d1", IP: "10.0.0.1", CampusID: "c", AccessDomain: "nas", Source: "radius", StartedAt: now.Add(-time.Hour), ConfirmedAt: now, HeartbeatSeconds: 60, DeviceClass: "mobile"}, {ID: "s2", AccountID: "a", EndpointID: "d1", IP: "10.0.0.2", CampusID: "c", AccessDomain: "nas", Source: "radius", StartedAt: now.Add(-time.Hour), ConfirmedAt: now, HeartbeatSeconds: 60, DeviceClass: "mobile"}}
}
func TestQuotaAndAttribution(t *testing.T) {
	now := time.Now()
	ss := sessions(now)
	q := EvaluateQuota("a", ss, Limits{Total: intp(1)}, now)
	if q.Total != 1 || q.State != "compliant" {
		t.Fatal(q)
	}
	ss[1].EndpointID = "d2"
	q = EvaluateQuota("a", ss, Limits{Total: intp(1)}, now)
	if q.State != "exceeded" {
		t.Fatal(q)
	}
	ss[1].ConfirmedAt = now.Add(-4 * time.Minute)
	q = EvaluateQuota("a", ss, Limits{Total: intp(1)}, now)
	if q.State != "unknown" {
		t.Fatal(q)
	}
	ss = sessions(now)
	other := ss[0]
	other.ID = "conflict"
	other.AccountID = "b"
	ss = append(ss, other)
	if a := Attribute(ss, "c", "nas", "10.0.0.1", now); a.State != "conflict" {
		t.Fatal(a)
	}
}
func TestStateMachineNoDuplicateAndUnknownFreeze(t *testing.T) {
	now := time.Now().UTC()
	p := Definition{ID: "p", Name: "p", Enabled: true, Mode: "automatic", Trigger: "quota_exceeded", WindowSeconds: 3600, RecoverySeconds: 60, CooldownSeconds: 60, Stages: []Stage{{Action: "notify", ConnectorID: "c"}, {Action: "disconnect", ConnectorID: "c", AfterSeconds: 60, MinEpisodes: 2}}}
	in := Input{AccountID: "a", Known: true, Violated: true}
	ex := Execution{}
	d := Advance(p, ex, in, now)
	if d.Intent == nil {
		t.Fatal(d)
	}
	ex = d.Execution
	d = Advance(p, ex, in, now.Add(time.Second))
	if d.Intent != nil {
		t.Fatal("duplicate stage")
	}
	ex.Stages[0].Status = "succeeded"
	in.Known = false
	d = Advance(p, ex, in, now.Add(2*time.Minute))
	if d.Intent != nil || d.Execution.State != "waiting_data" {
		t.Fatal(d)
	}
	in.Known = true
	in.Violated = false
	d = Advance(p, d.Execution, in, now.Add(3*time.Minute))
	d = Advance(p, d.Execution, in, now.Add(5*time.Minute))
	if d.Execution.State != "recovered" {
		t.Fatal(d)
	}
}
func intp(n int) *int { return &n }

func TestUnknownResetsSustainedViolation(t *testing.T) {
	now := time.Now()
	p := Definition{ID: "p", Name: "p", Mode: "observe", Trigger: "quota_exceeded", SustainSeconds: 60}
	in := Input{AccountID: "a", Known: true, Violated: true}
	e := Advance(p, Execution{}, in, now).Execution
	in.Known = false
	e = Advance(p, e, in, now.Add(30*time.Second)).Execution
	in.Known = true
	e = Advance(p, e, in, now.Add(2*time.Minute)).Execution
	if e.Episode != 0 {
		t.Fatal("unknown interval satisfied sustained condition")
	}
	e = Advance(p, e, in, now.Add(3*time.Minute)).Execution
	if e.Episode != 1 {
		t.Fatal(e)
	}
}
func TestQuotaRandomMACAndLowerBound(t *testing.T) {
	now := time.Now()
	ss := sessions(now)
	ss[1].EndpointID = "mac:02:00:00:00:00:01"
	ss[1].MAC = "02:00:00:00:00:01"
	q := EvaluateQuota("a", ss, Limits{Total: intp(1)}, now)
	if q.Total != 1 || q.UncertainSessions != 1 || q.State != "unknown" {
		t.Fatal(q)
	}
	q = EvaluateQuota("a", ss, Limits{Total: intp(0)}, now)
	if q.State != "exceeded" {
		t.Fatal(q)
	}
}
func TestSelectionPriorityAndScopeConjunction(t *testing.T) {
	now := time.Now()
	ss := sessions(now)
	ss[0].GroupID = "staff"
	ss[1].ProductID = "fiber"
	defs := []Definition{{ID: "b", Enabled: true, Trigger: "quota_exceeded"}, {ID: "a", Enabled: true, Trigger: "quota_exceeded"}, {ID: "cross", Enabled: true, Priority: 2, Trigger: "quota_exceeded", Scope: Scope{Groups: []string{"staff"}, Products: []string{"fiber"}}}}
	chosen, _ := Select(defs, "a", ss, now)
	if len(chosen) != 1 || chosen[0].ID != "a" {
		t.Fatal(chosen)
	}
}

func BenchmarkQuotaInventory(b *testing.B) {
	for _, n := range []int{100000, 1000000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			now := time.Now()
			ss := make([]Session, n)
			for i := range ss {
				ss[i] = Session{ID: fmt.Sprint(i), AccountID: "a", EndpointID: fmt.Sprint(i), CampusID: "c", AccessDomain: "nas", IP: fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256), Source: "auth", StartedAt: now, ConfirmedAt: now, HeartbeatSeconds: 60}
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				q := EvaluateQuota("a", ss, Limits{}, now)
				if q.Total != n {
					b.Fatal(q.Total)
				}
			}
		})
	}
}

func TestUnknownPausesStageDelay(t *testing.T) {
	now := time.Now()
	p := Definition{ID: "pause", Name: "pause", Mode: "observe", Trigger: "quota_exceeded", WindowSeconds: 3600, Stages: []Stage{{Action: "notify"}, {Action: "disconnect", AfterSeconds: 60}}}
	in := Input{AccountID: "a", Known: true, Violated: true}
	e := Advance(p, Execution{}, in, now).Execution
	in.Known = false
	e = Advance(p, e, in, now.Add(10*time.Second)).Execution
	in.Known = true
	d := Advance(p, e, in, now.Add(10*time.Minute))
	if d.Intent != nil {
		t.Fatal("unknown time advanced the next stage")
	}
	d = Advance(p, d.Execution, in, now.Add(11*time.Minute))
	if d.Intent == nil {
		t.Fatal("stage never resumed")
	}
}

func TestRepeatedRevokePreservesOriginalCooldown(t *testing.T) {
	now := time.Now().UTC()
	e := Execution{State: "executing", Definition: Definition{CooldownSeconds: 60}}
	first := Revoke(e, now)
	again := Revoke(first, now.Add(30*time.Second))
	if !again.CooldownUntil.Equal(first.CooldownUntil) {
		t.Fatal("retry extended cooldown")
	}
}
