package poison

import (
	"testing"
	"time"
)

func at(minute int) time.Time {
	return time.Date(2026, 10, 1, 12, minute, 0, 0, time.UTC)
}

func configuredRule() Rule {
	return Rule{
		RuleID:        "rule-sensitive",
		Name:          "敏感网段访问",
		Enabled:       true,
		BehaviorType:  BehaviorConfiguredRange,
		TargetType:    "cidr",
		Targets:       []string{"10.155.32.0/24", "10.155.40.10"},
		WindowSeconds: 3600,
		Threshold:     3,
		Direction:     DirectionAny,
	}
}

func TestConfiguredRangeFindsSensitiveDestinationAccess(t *testing.T) {
	observations := []Observation{
		{SubjectIP: "10.155.9.9", DstIP: "10.155.32.11", Direction: "outbound", At: at(0)},
		{SubjectIP: "10.155.9.9", DstIP: "10.155.32.12", Direction: "outbound", At: at(1)},
		{SubjectIP: "10.155.9.9", DstIP: "10.155.40.10", Direction: "outbound", At: at(2)},
		{SubjectIP: "10.155.9.9", DstIP: "203.0.113.5", Direction: "outbound", At: at(3)},
	}
	findings := Evaluate(configuredRule(), observations)
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %+v", findings)
	}
	finding := findings[0]
	if finding.SubjectIP != "10.155.9.9" || finding.HitCount != 3 || finding.UniqueDestinations != 3 {
		t.Fatalf("unexpected finding: %+v", finding)
	}
	if len(finding.MatchedTargets) != 2 {
		t.Fatalf("matched targets must be reported: %+v", finding.MatchedTargets)
	}
}

func TestThresholdIsRespected(t *testing.T) {
	observations := []Observation{
		{SubjectIP: "10.155.9.9", DstIP: "10.155.32.11", At: at(0)},
		{SubjectIP: "10.155.9.9", DstIP: "10.155.32.12", At: at(1)},
	}
	if findings := Evaluate(configuredRule(), observations); len(findings) != 0 {
		t.Fatalf("below-threshold access must not fire: %+v", findings)
	}
}

func TestDisabledRuleNeverFires(t *testing.T) {
	rule := configuredRule()
	rule.Enabled = false
	observations := []Observation{
		{SubjectIP: "10.155.9.9", DstIP: "10.155.32.11", At: at(0)},
		{SubjectIP: "10.155.9.9", DstIP: "10.155.32.12", At: at(1)},
		{SubjectIP: "10.155.9.9", DstIP: "10.155.40.10", At: at(2)},
	}
	if findings := Evaluate(rule, observations); len(findings) != 0 {
		t.Fatalf("disabled rule fired: %+v", findings)
	}
}

func TestNegativeCasesDoNotFire(t *testing.T) {
	rule := configuredRule()
	cases := map[string][]Observation{
		"自身地址":   {{SubjectIP: "10.155.32.11", DstIP: "10.155.32.11", At: at(0)}, {SubjectIP: "10.155.32.11", DstIP: "10.155.32.11", At: at(1)}, {SubjectIP: "10.155.32.11", DstIP: "10.155.32.11", At: at(2)}},
		"组播广播":   {{SubjectIP: "10.155.9.9", DstIP: "224.0.0.1", At: at(0)}, {SubjectIP: "10.155.9.9", DstIP: "255.255.255.255", At: at(1)}, {SubjectIP: "10.155.9.9", DstIP: "239.1.1.1", At: at(2)}},
		"环回链路本地": {{SubjectIP: "10.155.9.9", DstIP: "127.0.0.1", At: at(0)}, {SubjectIP: "10.155.9.9", DstIP: "169.254.1.1", At: at(1)}, {SubjectIP: "10.155.9.9", DstIP: "0.0.0.0", At: at(2)}},
		"目标之外":   {{SubjectIP: "10.155.9.9", DstIP: "10.155.33.1", At: at(0)}, {SubjectIP: "10.155.9.9", DstIP: "10.155.33.2", At: at(1)}, {SubjectIP: "10.155.9.9", DstIP: "10.155.33.3", At: at(2)}},
	}
	for name, observations := range cases {
		if findings := Evaluate(rule, observations); len(findings) != 0 {
			t.Fatalf("%s must not fire: %+v", name, findings)
		}
	}
}

func TestDirectionFilterIsApplied(t *testing.T) {
	rule := configuredRule()
	rule.Direction = DirectionUp
	outbound := []Observation{
		{SubjectIP: "10.155.9.9", DstIP: "10.155.32.11", Direction: "outbound", At: at(0)},
		{SubjectIP: "10.155.9.9", DstIP: "10.155.32.12", Direction: "outbound", At: at(1)},
		{SubjectIP: "10.155.9.9", DstIP: "10.155.32.13", Direction: "outbound", At: at(2)},
	}
	if findings := Evaluate(rule, outbound); len(findings) != 1 || findings[0].Direction != "outbound" {
		t.Fatalf("outbound access must fire: %+v", findings)
	}
	inbound := []Observation{
		{SubjectIP: "10.155.9.9", DstIP: "10.155.32.11", Direction: "inbound", At: at(0)},
		{SubjectIP: "10.155.9.9", DstIP: "10.155.32.12", Direction: "inbound", At: at(1)},
		{SubjectIP: "10.155.9.9", DstIP: "10.155.32.13", Direction: "inbound", At: at(2)},
	}
	if findings := Evaluate(rule, inbound); len(findings) != 0 {
		t.Fatalf("inbound access must be filtered out: %+v", findings)
	}
}

func TestHighFrequencyInternalCountsDistinctDestinations(t *testing.T) {
	rule := Rule{RuleID: "rule-internal", Name: "高频内网访问", Enabled: true, BehaviorType: BehaviorHighFrequency, TargetType: "cidr", WindowSeconds: 3600, Threshold: 4}
	observations := []Observation{
		{SubjectIP: "10.155.9.9", DstIP: "10.155.20.1", At: at(0)},
		{SubjectIP: "10.155.9.9", DstIP: "10.155.20.1", At: at(1)},
		{SubjectIP: "10.155.9.9", DstIP: "10.155.20.2", At: at(2)},
		{SubjectIP: "10.155.9.9", DstIP: "10.155.20.3", At: at(3)},
		{SubjectIP: "10.155.9.9", DstIP: "203.0.113.9", At: at(4)},
	}
	findings := Evaluate(rule, observations)
	if len(findings) != 1 || findings[0].HitCount != 4 || findings[0].UniqueDestinations != 3 {
		t.Fatalf("unexpected high-frequency finding: %+v", findings)
	}
}

func TestHighFrequencyIgnoresPublicDestinationsOnly(t *testing.T) {
	rule := Rule{RuleID: "rule-internal", Name: "高频内网访问", Enabled: true, BehaviorType: BehaviorHighFrequency, WindowSeconds: 3600, Threshold: 3}
	observations := []Observation{
		{SubjectIP: "10.155.9.9", DstIP: "203.0.113.1", At: at(0)},
		{SubjectIP: "10.155.9.9", DstIP: "203.0.113.2", At: at(1)},
		{SubjectIP: "10.155.9.9", DstIP: "203.0.113.3", At: at(2)},
	}
	if findings := Evaluate(rule, observations); len(findings) != 0 {
		t.Fatalf("public-only access must not fire: %+v", findings)
	}
}

func TestFindingIDIsStableWithinTheSameMinute(t *testing.T) {
	first := FindingID("rule", "10.0.0.1", at(0))
	second := FindingID("rule", "10.0.0.1", at(0).Add(30*time.Second))
	if first != second {
		t.Fatalf("finding id must be stable within a minute: %q %q", first, second)
	}
	if first == FindingID("rule", "10.0.0.1", at(1)) {
		t.Fatal("finding id must change across minutes")
	}
}

func TestValidateRuleRejectsBadTargets(t *testing.T) {
	base := func() Rule {
		return Rule{RuleID: "r", Name: "n", Enabled: true, BehaviorType: BehaviorConfiguredRange, TargetType: "cidr", Targets: []string{"10.0.0.0/8"}, WindowSeconds: 3600, Threshold: 1}
	}
	valid := base()
	if err := ValidateRule(&valid); err != nil {
		t.Fatalf("valid rule rejected: %v", err)
	}
	bad := []Rule{
		func() Rule { r := base(); r.Targets = nil; return r }(),
		func() Rule { r := base(); r.Targets = []string{"not-a-cidr"}; return r }(),
		func() Rule { r := base(); r.Direction = "sideways"; return r }(),
		func() Rule { r := base(); r.WindowSeconds = 5; return r }(),
		func() Rule { r := base(); r.BehaviorType = "other"; return r }(),
	}
	for _, rule := range bad {
		candidate := rule
		if err := ValidateRule(&candidate); err == nil {
			t.Fatalf("invalid rule accepted: %+v", rule)
		}
	}
	// Out-of-range thresholds are normalised to the conservative default rather
	// than silently allowing a zero-hit rule to fire.
	zero := base()
	zero.Threshold = 0
	if err := ValidateRule(&zero); err != nil || zero.Threshold != 1 {
		t.Fatalf("threshold must normalise to 1: %+v %v", zero, err)
	}
	// high_frequency_internal needs no explicit targets.
	frequency := base()
	frequency.BehaviorType = BehaviorHighFrequency
	frequency.Targets = nil
	if err := ValidateRule(&frequency); err != nil {
		t.Fatalf("high frequency rule rejected: %v", err)
	}
}
