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
	if result := SummarizePassiveBehavior(values, true, at.Add(time.Minute), ""); result.CandidateType != "" {
		t.Fatal("connection attempt promoted to candidate", result)
	}
	values[1].Kind = "port_response"
	if result := SummarizePassiveBehavior(values, false, at.Add(time.Minute), ""); result.CandidateType != "" {
		t.Fatal("IP-only behavior promoted to hardware candidate", result)
	}
	if result := SummarizePassiveBehavior(values, true, at.Add(time.Minute), ""); result.CandidateType != "video_device" {
		t.Fatal("corroborated observed behavior was lost", result)
	}
	values = append(values, PassiveBehaviorEvidence{Kind: "vendor_domain", Value: "canon.com", BucketAt: at, ObservedAt: at, EventID: "domain2"},
		PassiveBehaviorEvidence{Kind: "port_response", Value: "tcp/9100", BucketAt: at, ObservedAt: at, EventID: "reply"})
	if result := SummarizePassiveBehavior(values, true, at.Add(time.Minute), ""); result.CandidateType != "" {
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
	if result := SummarizePassiveBehavior(events, true, at.Add(30*time.Minute), ""); result.CadenceMinutes != 10 || result.NTPTarget != "192.0.2.1" || result.CandidateType != "" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestPassiveSNIBrandNeedsScopedCorroboration(t *testing.T) {
	at := time.Date(2026, 11, 23, 8, 0, 0, 0, time.UTC)
	evidence := func(host string, minute int) PassiveBehaviorEvidence {
		when := at.Add(time.Duration(minute) * time.Minute)
		return PassiveBehaviorEvidence{Kind: "device_sni", Value: host, BucketAt: when.Truncate(5 * time.Minute), ObservedAt: when, EventID: host}
	}
	update := evidence("gdmf.apple.com", 1)
	enroll := evidence("deviceenrollment.apple.com", 2)
	otherUpdate := evidence("mesu.apple.com", 3)
	hikvision := []PassiveBehaviorEvidence{evidence("dev.hik-connect.com", 1), evidence("litedev.hik-connect.com", 6), evidence("dev.hik-connect.com", 11)}
	for _, tc := range []struct {
		name             string
		items            []PassiveBehaviorEvidence
		trusted          bool
		knownBrand, want string
		conflict         bool
	}{
		{"single service and bucket", []PassiveBehaviorEvidence{update, otherUpdate, update}, true, "", "", false},
		{"two device services", []PassiveBehaviorEvidence{update, enroll}, true, "", "Apple", false},
		{"repeated device service", hikvision, true, "", "Hikvision", false},
		{"IP without trusted ownership", []PassiveBehaviorEvidence{update, enroll}, false, "", "", false},
		{"known hardware brand", []PassiveBehaviorEvidence{update, enroll}, true, "Hikvision", "", true},
		{"multiple brand clues", append([]PassiveBehaviorEvidence{update, enroll}, hikvision...), true, "", "", true},
		{"old observation", []PassiveBehaviorEvidence{evidence("mesu.apple.com", -121), enroll}, true, "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := SummarizePassiveBehavior(tc.items, tc.trusted, at.Add(15*time.Minute), tc.knownBrand)
			if result.SNIBrandHint != tc.want || result.SNIBrandConflict != tc.conflict || result.CandidateType != "" {
				t.Fatalf("unexpected SNI brand result: %+v", result)
			}
		})
	}
	for input, want := range map[string]string{
		" GDMF.Apple.com. ": "gdmf.apple.com", "10-courier.push.apple.com": "push.apple.com",
		"dev.hik-connect.com": "dev.hik-connect.com", "ingress.did.mysystems.axis.com": "ingress.did.mysystems.axis.com",
		"www.apple.com": "", "gdmf.apple.com.example": "", "fakepush.apple.com": "", "gdmf.apple.com:443": "",
		"omada.tplinkcloud.com": "", "metrics.hicloud.com": "", "www.hik-connect.com": "",
	} {
		if got := PassiveDeviceSNI(input); got != want {
			t.Errorf("PassiveDeviceSNI(%q)=%q want %q", input, got, want)
		}
	}
}
