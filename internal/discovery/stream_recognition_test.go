package discovery

import (
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
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
		{"ws_discovery", "Printer M404", "wsd_model", "Printer M404"},
		{"http", "", "http_server", "lighttpd"},
		{"tls", "", "tls_subject", "CN=router.local"},
		{"ssh", "", "ssh_banner", "SSH-2.0-router"},
		{"sip", "", "sip_server", "lighttpd"},
	}
	for _, tc := range cases {
		t.Run(tc.origin, func(t *testing.T) {
			o := Observation{Origin: tc.origin, ModelName: tc.model, Evidence: normalized.Event{Payload: map[string]any{
				"vendor_class": "android-dhcp-14", "system_object_id": "1.3.6.1.4.1.11.2",
				"server": "lighttpd", "subject": "CN=router.local", "banner": "SSH-2.0-router",
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

func TestStreamSSHReplayKeepsServerDirection(t *testing.T) {
	stamp := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	base := normalized.Event{EventID: "ssh-1", Type: "device", SourceEventType: "ssh", Timestamp: stamp.Format(time.RFC3339Nano),
		Observer: map[string]any{"capture_scope_id": "scope-1", "sensor_id": "sensor-1"},
		Subject:  map[string]any{"campus_id": "campus-1", "ip": "10.1.1.5", "mac": "00:11:22:33:44:55"},
		Payload:  map[string]any{"is_response": true, "attribution_side": "server", "banner": "SSH-2.0-router", "ttl": 300}}
	segment := streamlog.Segment{Epoch: "fresh", AcceptedAt: stamp, Events: []normalized.Event{base}}
	items, err := prepareStreamDiscovery(segment)
	if err != nil || len(items) != 1 || items[0].Fact.RecognitionFields["ssh_banner"] != "SSH-2.0-router" {
		t.Fatalf("server replay lost banner: items=%+v err=%v", items, err)
	}
	base.EventID = "ssh-client"
	base.Payload["attribution_side"] = "client"
	segment.Events = []normalized.Event{base}
	items, err = prepareStreamDiscovery(segment)
	if err != nil || len(items) != 1 || len(items[0].Fact.RecognitionFields) != 0 {
		t.Fatalf("client replay became hardware evidence: items=%+v err=%v", items, err)
	}
}

func TestStreamHTTPRequiresExplicitServerAttribution(t *testing.T) {
	o := Observation{Origin: "http", Evidence: normalized.Event{Payload: map[string]any{"is_response": true, "server": "router-os"}}}
	if fields := streamRecognitionFields(o); len(fields) != 0 {
		t.Fatalf("unattributed response became device evidence: %+v", fields)
	}
}
