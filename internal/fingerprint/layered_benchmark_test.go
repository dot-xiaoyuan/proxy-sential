package fingerprint

import (
	"testing"
	"time"
)

// Keep this corpus compatible with the previous engine so the same attributed
// fresh input can be compared without databases, live traffic or backfill.
func BenchmarkLayeredFreshEvidence(b *testing.B) {
	now := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	library := Default()
	for _, tc := range []struct{ protocol, field, value, direction string }{
		{"dhcp", "hostname", "HUAWEI-ADY-AL00", "device"},
		{"dhcpv6", "dhcp_vendor_class", "android-dhcp-14", "device"},
		{"lldp", "lldp_system_description", "Cisco IOS Software", "device"},
		{"cdp", "cdp_platform", "Cisco C9300", "device"},
		{"dns_sd", "dns_sd_model", "iPhone14,5", "device"},
		{"mdns", "mdns_model", "MacBookPro18,3", "device"},
		{"ssdp", "ssdp_model", "ADY-AL00", "device"},
		{"snmp", "snmp_sysdescr", "HP LaserJet Pro M404", "device"},
		{"http", "http_server", "nginx/1.24", "server"},
		{"tls", "tls_subject", "CN=router.asus.com", "server"},
		{"ipp", "printer_make_and_model", "HP LaserJet Pro M404", "device"},
		{"http", "user_agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)", "client"},
	} {
		b.Run(tc.protocol+"/"+tc.field, func(b *testing.B) {
			evidence := []EvidenceSignal{{Protocol: tc.protocol, Field: tc.field, Value: tc.value, Direction: tc.direction, Association: "mac", EventID: "fresh-benchmark", ObservedAt: now, ValidUntil: now.Add(time.Hour)}}
			got := library.IdentifyEvidence("02:00:00:00:00:01", evidence, now)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				library.IdentifyEvidence("02:00:00:00:00:01", evidence, now)
			}
			b.ReportMetric(float64(got.Diagnostics.CandidateRules), "rules/event")
		})
	}
}
