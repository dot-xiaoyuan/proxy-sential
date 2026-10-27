package discovery

import (
	"testing"

	"proxy-sentinel/internal/normalized"
)

func TestStreamRecognitionFieldsKeepOnlyProtocolProductSignals(t *testing.T) {
	cases := []struct {
		origin string
		model  string
		field  string
		value  string
	}{
		{"dhcpv6", "", "dhcp_vendor_class", "android-dhcp-14"},
		{"snmp", "Printer M404", "snmp_sysoid", "1.3.6.1.4.1.11.2"},
		{"ssdp", "Archer AX55", "ssdp_model", "Archer AX55"},
		{"ipp", "LaserJet M404", "printer_make_and_model", "LaserJet M404"},
		{"onvif", "Camera 1", "onvif_model", "Camera 1"},
		{"http", "", "http_server", "lighttpd"},
		{"tls", "", "tls_subject", "CN=router.local"},
	}
	for _, tc := range cases {
		t.Run(tc.origin, func(t *testing.T) {
			o := Observation{Origin: tc.origin, ModelName: tc.model, Evidence: normalized.Event{Payload: map[string]any{
				"vendor_class": "android-dhcp-14", "system_object_id": "1.3.6.1.4.1.11.2",
				"server": "lighttpd", "subject": "CN=router.local",
				"attribution_side": "server",
				"user_agent":       "should not be copied", "password": "secret",
			}}}
			fields := streamRecognitionFields(o)
			if fields[tc.field] != tc.value || fields["password"] != "" || fields["user_agent"] != "" {
				t.Fatalf("unexpected compact signals: %+v", fields)
			}
		})
	}
}

func TestStreamHTTPRequiresExplicitServerAttribution(t *testing.T) {
	o := Observation{Origin: "http", Evidence: normalized.Event{Payload: map[string]any{"is_response": true, "server": "router-os"}}}
	if fields := streamRecognitionFields(o); len(fields) != 0 {
		t.Fatalf("unattributed response became device evidence: %+v", fields)
	}
}
