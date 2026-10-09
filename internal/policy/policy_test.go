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

func TestManagedSessionAttributionDoesNotRequireInventedAccessScope(t *testing.T) {
	now := time.Now().UTC()
	sessions := []Session{{ID: "session-1", AccountID: "student", IP: "192.0.2.8", Source: "srun4k:office", SensorID: "srun4k-direct:office", StartedAt: now.Add(-time.Minute), ConfirmedAt: now, ReconcileSeconds: 21600, MAC: "02:00:00:00:00:08"}}
	if got := AttributeForSession(sessions, sessions[0], now); got.State != "resolved" || got.AccountID != "student" {
		t.Fatalf("managed 4K session should resolve without campus/access domain: %+v", got)
	}
	if got := Attribute(sessions, "", "", sessions[0].IP, now); got.State != "unknown" {
		t.Fatalf("legacy network attribution must retain scoped contract: %+v", got)
	}
}

func TestProductScopeAlsoIsolatesManagedSource(t *testing.T) {
	now := time.Now().UTC()
	base := Session{AccountID: "student", ProductID: "1", IP: "192.0.2.9", StartedAt: now.Add(-time.Minute), ConfirmedAt: now, ReconcileSeconds: 21600, DeviceClass: "pc"}
	a := base
	a.ID, a.Source, a.SensorID, a.EndpointID = "a", "srun4k:a", "sensor-a", "device-a"
	b := base
	b.ID, b.Source, b.SensorID, b.EndpointID, b.IP = "b", "srun4k:b", "sensor-b", "device-b", "192.0.2.10"
	quota := EvaluateQuotaForScope("student", []Session{a, b}, Scope{Sources: []string{"srun4k:a"}, Products: []string{"1"}}, Limits{Total: intp(1)}, now)
	if quota.Total != 1 || quota.State != "compliant" {
		t.Fatalf("same product ID from another 4K source leaked into quota: %+v", quota)
	}
}

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

func TestSessionQuotaDeduplicatesDualStackAndIsolatesProduct(t *testing.T) {
	now := time.Now().UTC()
	limit := 0
	sessions := []Session{
		{ID: "login-1", AccountID: "a", IP: "192.0.2.1", ProductID: "office", CampusID: "office-test", AccessDomain: "office-lan", Source: "srun", StartedAt: now.Add(-time.Minute), ConfirmedAt: now, HeartbeatSeconds: 5},
		{ID: "login-1", AccountID: "a", IP: "2001:db8::1", ProductID: "office", CampusID: "office-test", AccessDomain: "office-lan", Source: "srun", StartedAt: now.Add(-time.Minute), ConfirmedAt: now, HeartbeatSeconds: 5},
		{ID: "login-2", AccountID: "a", IP: "192.0.2.2", ProductID: "guest", CampusID: "office-test", AccessDomain: "office-lan", Source: "srun", StartedAt: now.Add(-time.Minute), ConfirmedAt: now, HeartbeatSeconds: 5},
	}
	q := EvaluateSessionQuota("a", sessions, Scope{Products: []string{"office"}}, &limit, now)
	if q.State != "exceeded" || q.Sessions != 1 || len(q.SessionIDs) != 1 {
		t.Fatalf("unexpected product-scoped session quota: %+v", q)
	}
}

func TestQuotaDoesNotCountDevicesFromOtherProducts(t *testing.T) {
	now := time.Now().UTC()
	zero := 0
	sessions := []Session{
		{ID: "login-office", AccountID: "a", EndpointID: "office-device", IP: "192.0.2.10", ProductID: "office", CampusID: "office-test", AccessDomain: "office-lan", Source: "srun", StartedAt: now.Add(-time.Minute), ConfirmedAt: now, HeartbeatSeconds: 5},
		{ID: "login-guest", AccountID: "a", EndpointID: "guest-device", IP: "192.0.2.11", ProductID: "guest", CampusID: "office-test", AccessDomain: "office-lan", Source: "srun", StartedAt: now.Add(-time.Minute), ConfirmedAt: now, HeartbeatSeconds: 5},
	}
	q := EvaluateQuotaForScope("a", sessions, Scope{Products: []string{"office"}}, Limits{Total: &zero}, now)
	if q.Total != 1 || q.State != "exceeded" {
		t.Fatalf("unexpected product-scoped device quota: %+v", q)
	}
}

func TestObserveRecordStageRequiresNoConnector(t *testing.T) {
	p := Definition{ID: "p", Name: "影子记录", Enabled: true, Mode: "observe", Trigger: "session_quota_exceeded", Limits: Limits{Sessions: intp(0)}, Stages: []Stage{{Action: "record"}}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.Mode = "automatic"
	if err := p.Validate(); err == nil {
		t.Fatal("record stage must remain observe-only")
	}
}

func TestStrategyActionMetadataValidation(t *testing.T) {
	limit := 2
	valid := Definition{ID: "dpi-style", Name: "DPI式策略", Trigger: "quota_exceeded", Mode: "observe", ActionModel: "dpi-strategy/v1", Limits: Limits{Total: &limit}, Stages: []Stage{
		{Action: "notify", Template: "代理提醒", AfterSeconds: 60, IntervalSeconds: 300},
		{Action: "disconnect", DependsOn: []string{"notify"}, MinEpisodes: 2, SyncNotify: true},
	}}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.Stages = []Stage{{Action: "disconnect", DependsOn: []string{"disconnect"}}}
	if err := invalid.Validate(); err == nil {
		t.Fatal("self dependency accepted")
	}
}

func TestDPIActionModelUsesIndependentTimersAndDependencyCounts(t *testing.T) {
	now := time.Now().UTC()
	limit := 0
	p := Definition{
		ID: "dpi-independent", Name: "DPI动作模型", Enabled: true, Mode: "observe", Trigger: "quota_exceeded", ActionModel: "dpi-strategy/v1",
		Limits: Limits{Total: &limit},
		Stages: []Stage{
			{Action: "notify", IntervalSeconds: 5},
			{Action: "disconnect", DependsOn: []string{"notify"}, MinEpisodes: 2},
		},
	}
	in := Input{AccountID: "a", Known: true, Violated: true}

	first := Advance(p, Execution{}, in, now)
	if first.Intent == nil || first.Intent.StageIndex != 0 || first.Execution.Stages[0].ExecuteCount != 1 {
		t.Fatalf("first notification was not executed: %+v", first)
	}
	second := Advance(p, first.Execution, in, now.Add(5*time.Second))
	if second.Intent == nil || second.Intent.StageIndex != 0 || second.Execution.Stages[0].ExecuteCount != 2 {
		t.Fatalf("interval notification was not repeated: %+v", second)
	}
	dependent := Advance(p, second.Execution, in, now.Add(6*time.Second))
	if dependent.Intent == nil || dependent.Intent.StageIndex != 1 || dependent.Execution.Stages[1].ExecuteCount != 1 {
		t.Fatalf("dependent action did not wait for two notification executions: %+v", dependent)
	}
}

func TestDPIActionModelDoesNotSerializeIndependentActions(t *testing.T) {
	now := time.Now().UTC()
	limit := 0
	p := Definition{
		ID: "dpi-parallel", Name: "DPI独立动作", Enabled: true, Mode: "observe", Trigger: "quota_exceeded", ActionModel: "dpi-strategy/v1",
		Limits: Limits{Total: &limit},
		Stages: []Stage{
			{Action: "notify", AfterSeconds: 60},
			{Action: "disconnect", AfterSeconds: 10},
		},
	}
	in := Input{AccountID: "a", Known: true, Violated: true}

	started := Advance(p, Execution{}, in, now)
	if started.Intent != nil {
		t.Fatalf("an action ran before its own delay: %+v", started)
	}
	disconnect := Advance(p, started.Execution, in, now.Add(10*time.Second))
	if disconnect.Intent == nil || disconnect.Intent.StageIndex != 1 {
		t.Fatalf("later action was serialized behind notification: %+v", disconnect)
	}
}
