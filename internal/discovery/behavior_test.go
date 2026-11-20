package discovery

import (
	"testing"
	"time"
)

func TestPassiveBehaviorRequiresCorroboratedScopedOwner(t *testing.T) {
	at := time.Date(2026, 11, 20, 2, 0, 0, 0, time.UTC)
	values := []PassiveBehaviorEvidence{
		{Kind: "vendor_domain", Value: "hikvision.com", BucketAt: at, ObservedAt: at, EventID: "domain"},
		{Kind: "port_attempt", Value: "tcp/554", BucketAt: at, ObservedAt: at, EventID: "syn"},
	}
	if result := SummarizePassiveBehavior(values, true, at.Add(time.Minute)); result.CandidateType != "" {
		t.Fatal("connection attempt promoted to candidate", result)
	}
	values[1].Kind = "port_response"
	if result := SummarizePassiveBehavior(values, false, at.Add(time.Minute)); result.CandidateType != "" {
		t.Fatal("IP-only behavior promoted to hardware candidate", result)
	}
	if result := SummarizePassiveBehavior(values, true, at.Add(time.Minute)); result.CandidateType != "video_device" {
		t.Fatal("corroborated observed behavior was lost", result)
	}
	values = append(values, PassiveBehaviorEvidence{Kind: "vendor_domain", Value: "canon.com", BucketAt: at, ObservedAt: at, EventID: "domain2"},
		PassiveBehaviorEvidence{Kind: "port_response", Value: "tcp/9100", BucketAt: at, ObservedAt: at, EventID: "reply"})
	if result := SummarizePassiveBehavior(values, true, at.Add(time.Minute)); result.CandidateType != "" {
		t.Fatal("conflicting behavior was promoted", result)
	}
}

func TestPassiveBehaviorSummarizesCadenceFromDistinctBuckets(t *testing.T) {
	at := time.Date(2026, 11, 20, 2, 0, 0, 0, time.UTC)
	var events []PassiveBehaviorEvidence
	for i := range 3 {
		observed := at.Add(time.Duration(i) * 10 * time.Minute)
		events = append(events, PassiveBehaviorEvidence{Kind: "ntp", Value: "192.0.2.1", BucketAt: observed, ObservedAt: observed, EventID: "ntp"})
	}
	if result := SummarizePassiveBehavior(events, true, at.Add(30*time.Minute)); result.CadenceMinutes != 10 || result.NTPTarget != "192.0.2.1" || result.CandidateType != "" {
		t.Fatalf("unexpected result: %+v", result)
	}
}
