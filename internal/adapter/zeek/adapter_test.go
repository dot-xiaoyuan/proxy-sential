package zeek

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestConvertAppliesCollectorInstanceBeforeCaptureScope(t *testing.T) {
	now := time.Unix(1785232900, 0).UTC()
	input := bytes.NewBufferString(`{"ts":1785232900.5,"uid":"C5","id.orig_h":"192.168.10.23","id.resp_h":"198.51.100.1","method":"GET","host":"example.test","user_agent":"Mozilla/5.0 (Windows NT 10.0)"}` + "\n")
	var output bytes.Buffer
	scope := &normalized.CaptureScope{SchemaVersion: "capture-scope/v1", SensorID: "lab-30", CollectorInstanceID: "boot-1", CampusID: "campus", AccessDomain: "nas", ValidFrom: now.Add(-time.Minute), ValidUntil: now.Add(time.Minute)}
	stats, err := Convert(input, &output, Options{SensorID: "lab-30", CollectorInstanceID: "boot-1", LogKind: "http", CaptureScope: scope})
	if err != nil || stats.Emitted != 1 {
		t.Fatalf("convert failed: stats=%+v err=%v", stats, err)
	}
	var event map[string]any
	if err = json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	observer := event["observer"].(map[string]any)
	subject := event["subject"].(map[string]any)
	payload := event["payload"].(map[string]any)
	if observer["collector_instance_id"] != "boot-1" || observer["capture_scope_issue"] != nil || subject["campus_id"] != "campus" || payload["access_domain"] != "nas" {
		t.Fatalf("capture scope was not applied: %+v", event)
	}
}

func TestConvertDHCPFixture(t *testing.T) {
	path := filepath.Join("..", "..", "..", "examples", "zeek", "dhcp-sample.log")
	input, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()

	var output bytes.Buffer
	stats, err := Convert(input, &output, Options{SensorID: "lab-30"})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Emitted != 4 || stats.Malformed != 0 || stats.ByType["device"] != 4 {
		t.Fatalf("unexpected stats: %+v", stats)
	}

	scanner := bufio.NewScanner(bytes.NewReader(output.Bytes()))
	line := 0
	var first map[string]any
	for scanner.Scan() {
		line++
		var event map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("line %d is not json: %v", line, err)
		}
		requireString(t, event, "schema_version", "v1")
		requireString(t, event, "source", "zeek")
		requireString(t, event, "source_event_type", "dhcp")
		requireString(t, event, "type", "device")
		requireNonEmptyString(t, event, "event_id")
		requireNonEmptyString(t, event, "timestamp")
		if _, err := time.Parse(time.RFC3339Nano, event["timestamp"].(string)); err != nil {
			t.Fatalf("line %d timestamp is not RFC3339Nano: %v", line, err)
		}
		requireNestedString(t, event, "subject", "ip")
		requireNestedString(t, event, "subject", "mac")
		requireNestedString(t, event, "flow", "src_ip")
		requireNestedString(t, event, "flow", "dst_ip")
		requireNestedString(t, event, "flow", "proto")
		requireNestedString(t, event, "payload", "origin")
		requireNestedString(t, event, "payload", "hostname")
		requireNestedString(t, event, "payload", "vendor_class")
		requireNestedString(t, event, "payload", "requested_options")
		if first == nil {
			first = event
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if line != 4 {
		t.Fatalf("expected 4 normalized lines, got %d", line)
	}
	payload := first["payload"].(map[string]any)
	if payload["device_hint"] != "apple" {
		t.Fatalf("expected apple device hint, got %#v", payload["device_hint"])
	}
	if payload["mac"] != "aa:bb:cc:dd:ee:01" || payload["client_mac"] != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("expected normalized MAC aliases, got %#v", payload)
	}
}

func TestConvertJSONLine(t *testing.T) {
	input := bytes.NewBufferString(`{"ts":1785232900.5,"uids":["C5"],"client_addr":"0.0.0.0","server_addr":"192.168.10.1","mac":"AA-BB-CC-DD-EE-04","host_name":"DESKTOP-TEST","requested_addr":"192.168.10.23","assigned_addr":"192.168.10.23","client_software":"MSFT 5.0","requested_options":["1","3","6","15"]}` + "\n")

	var output bytes.Buffer
	stats, err := Convert(input, &output, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Read != 1 || stats.Emitted != 1 || stats.Malformed != 0 || stats.Skipped != 0 {
		t.Fatalf("unexpected stats: %+v", stats)
	}

	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	if event["source"] != "zeek" || event["type"] != "device" {
		t.Fatalf("unexpected event: %+v", event)
	}
	payload := event["payload"].(map[string]any)
	if payload["device_hint"] != "windows" || payload["vendor_class"] != "MSFT 5.0" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
	subject := event["subject"].(map[string]any)
	if subject["mac"] != "aa:bb:cc:dd:ee:04" || payload["mac"] != "aa:bb:cc:dd:ee:04" || payload["client_mac"] != "aa:bb:cc:dd:ee:04" {
		t.Fatalf("expected normalized MAC fields, subject=%+v payload=%+v", subject, payload)
	}
}

func TestConvertSoftwareLog(t *testing.T) {
	input := bytes.NewBufferString("#separator \\x09\n" +
		"#empty_field\t(empty)\n" +
		"#unset_field\t-\n" +
		"#path\tsoftware\n" +
		"#fields\tts\thost\thost_p\tsoftware_type\tname\tversion.major\tversion.minor\tversion.minor2\tversion.minor3\tversion.addl\tunparsed_version\n" +
		"#types\ttime\taddr\tport\tenum\tstring\tcount\tcount\tcount\tcount\tstring\tstring\n" +
		"1785293807.759379\t192.168.0.6\t68\tDHCP::CLIENT\tMSFT\t5\t0\t-\t-\t-\tMSFT 5.0\n")

	var output bytes.Buffer
	stats, err := Convert(input, &output, Options{SensorID: "lab-30"})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Emitted != 1 || stats.Malformed != 0 || stats.ByType["device"] != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	requireString(t, event, "source", "zeek")
	requireString(t, event, "source_event_type", "software")
	requireString(t, event, "type", "device")
	requireNestedString(t, event, "subject", "ip")
	payload := event["payload"].(map[string]any)
	if payload["origin"] != "software" ||
		payload["software_type"] != "DHCP::CLIENT" ||
		payload["software_name"] != "MSFT" ||
		payload["software_version"] != "MSFT 5.0" ||
		payload["vendor_class"] != "MSFT 5.0" ||
		payload["device_hint"] != "windows" {
		t.Fatalf("unexpected software payload: %+v", payload)
	}
}

func TestConvertSkipsMalformedAndMissingDHCPFields(t *testing.T) {
	input := bytes.NewBufferString("{bad json\n" +
		"#separator \\x09\n" +
		"#fields\tts\tclient_addr\tserver_addr\tmac\n" +
		"1785232800.125\t0.0.0.0\t192.168.10.1\taa:bb:cc:dd:ee:01\n" +
		"1785232801.125\t192.168.10.30\t192.168.10.1\taa:bb:cc:dd:ee:02\n")

	var output bytes.Buffer
	stats, err := Convert(input, &output, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Read != 5 || stats.Emitted != 1 || stats.Malformed != 1 || stats.Skipped != 3 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestEventIDIsStableAcrossReplayOffsets(t *testing.T) {
	raw := []byte(`{"ts":1785232800.25,"client_addr":"10.0.0.2","server_addr":"10.0.0.1","assigned_addr":"10.0.0.2","mac":"aa:bb:cc:dd:ee:ff"}`)
	parser := logParser{}
	first, err := parser.convertLine(raw, 1, Options{SensorID: "sensor-a"})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := parser.convertLine(raw, 9001, Options{SensorID: "sensor-a"})
	if err != nil {
		t.Fatal(err)
	}
	if first.EventID != replayed.EventID {
		t.Fatalf("event id changed across replay: %s != %s", first.EventID, replayed.EventID)
	}
}

func TestConvertLocalDiscoveryAndTTLSignals(t *testing.T) {
	for _, tc := range []struct{ kind, raw, expected string }{
		{"mdns", `{"ts":1785232800.25,"src_ip":"192.168.10.30","name":"yuan-iphone.local","answers":"192.168.10.30"}`, "yuan-iphone.local"},
		{"nbns", `{"ts":1785232800.25,"src_ip":"192.168.10.31","name":"DESKTOP-01","mac":"aa:bb:cc:dd:ee:ff"}`, "DESKTOP-01"},
		{"llmnr", `{"ts":1785232800.25,"src_ip":"192.168.10.32","query":"laptop-a"}`, "laptop-a"},
	} {
		var output bytes.Buffer
		stats, err := Convert(strings.NewReader(tc.raw+"\n"), &output, Options{SensorID: "sensor-a", LogKind: tc.kind})
		if err != nil {
			t.Fatal(err)
		}
		if stats.Emitted != 1 || !strings.Contains(output.String(), tc.expected) || !strings.Contains(output.String(), `"origin":"`+tc.kind+`"`) {
			t.Fatalf("unexpected %s output: %s", tc.kind, output.String())
		}
	}
	var ttlOutput bytes.Buffer
	if _, err := Convert(strings.NewReader(`{"ts":1785232800.25,"src_ip":"192.168.10.33","ttl":63}`+"\n"), &ttlOutput, Options{LogKind: "ttl"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ttlOutput.String(), `"ttl":63`) {
		t.Fatalf("missing ttl payload: %s", ttlOutput.String())
	}
}

func TestConvertRouterProtocolLogsJSON(t *testing.T) {
	tests := []struct {
		kind, raw, eventType, payloadKey, payloadValue string
	}{
		{"conn", `{"ts":1785232800.25,"id.orig_h":"10.0.0.2","id.resp_h":"198.51.100.2","id.orig_p":50000,"id.resp_p":443,"proto":"tcp","orig_l2_addr":"00-46-4B-12-34-56","vlan":"120","service":"ssl"}`, "flow", "vlan", "120"},
		{"dns", `{"ts":1785232800.25,"id.orig_h":"10.0.0.2","id.resp_h":"10.0.0.53","proto":"udp","query":"router.huawei.test"}`, "dns", "query", "router.huawei.test"},
		{"http", `{"ts":1785232800.25,"id.orig_h":"10.0.0.2","id.resp_h":"10.0.0.1","proto":"tcp","host":"ar6140.local","server":"Huawei AR Web","title":"AR6140 Management"}`, "http", "title", "AR6140 Management"},
		{"ssl", `{"ts":1785232800.25,"id.orig_h":"10.0.0.2","id.resp_h":"10.0.0.1","proto":"tcp","server_name":"msr3600.local","subject":"CN=H3C MSR3600"}`, "tls", "certificate_subject", "CN=H3C MSR3600"},
		{"x509", `{"ts":1785232800.25,"host":"10.0.0.1","subject":"CN=Huawei AR6140","issuer":"CN=Huawei","san.dns":"ar6140.local"}`, "tls", "certificate_san", "ar6140.local"},
		{"lldp", `{"ts":1785232800.25,"src_ip":"10.0.0.1","src_mac":"00:46:4b:12:34:56","system_name":"AR6140","system_description":"Huawei AR6140","capabilities":"router,bridge","vlan":"120"}`, "discovery", "capabilities", "router,bridge"},
		{"ssdp", `{"ts":1785232800.25,"src_ip":"10.0.0.1","st":"urn:schemas-upnp-org:device:InternetGatewayDevice:1","server":"Huawei HG8245"}`, "discovery", "st", "urn:schemas-upnp-org:device:InternetGatewayDevice:1"},
	}
	for _, tc := range tests {
		t.Run(tc.kind, func(t *testing.T) {
			var output bytes.Buffer
			stats, err := Convert(strings.NewReader(tc.raw+"\n"), &output, Options{SensorID: "router-test", LogKind: tc.kind})
			if err != nil || stats.Emitted != 1 {
				t.Fatalf("convert %s: stats=%+v err=%v output=%s", tc.kind, stats, err, output.String())
			}
			var event map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
				t.Fatal(err)
			}
			if event["type"] != tc.eventType || event["source_event_type"] != tc.kind {
				t.Fatalf("unexpected event type: %+v", event)
			}
			payload := event["payload"].(map[string]any)
			if payload[tc.payloadKey] != tc.payloadValue {
				t.Fatalf("missing normalized %s=%q in %+v", tc.payloadKey, tc.payloadValue, payload)
			}
			if tc.kind == "conn" {
				subject := event["subject"].(map[string]any)
				if subject["mac"] != "00:46:4b:12:34:56" {
					t.Fatalf("MAC not normalized: %+v", subject)
				}
			}
		})
	}
}

func TestConvertSNMPIdentityLogsWithoutCommunity(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		deviceIP    string
		peerIP      string
		version     string
		description string
	}{
		{name: "v1-response", raw: `{"ts":1785232800.25,"uid":"snmp-v1","id.orig_h":"222.204.7.64","id.orig_p":40707,"id.resp_h":"10.120.249.163","id.resp_p":161,"version":"1","community":"private-secret","get_responses":1,"display_string":"Huawei AR6140"}`, deviceIP: "10.120.249.163", peerIP: "222.204.7.64", version: "1", description: "Huawei AR6140"},
		{name: "v2c-reverse", raw: `{"ts":1785232801.25,"uid":"snmp-v2","id.orig_h":"10.1.0.30","id.orig_p":"161/udp","id.resp_h":"222.204.7.64","id.resp_p":"50000/udp","version":"2c","community":"another-secret","get_responses":2,"display_string":"Cisco ISR4331","up_since":1785230000.0}`, deviceIP: "10.1.0.30", peerIP: "222.204.7.64", version: "2c", description: "Cisco ISR4331"},
		{name: "v3-trap", raw: `{"ts":1785232802.25,"uid":"snmp-v3","id.orig_h":"10.2.0.40","id.orig_p":49000,"id.resp_h":"222.204.7.64","id.resp_p":162,"version":"3","display_string":"Juniper MX480"}`, deviceIP: "10.2.0.40", peerIP: "222.204.7.64", version: "3", description: "Juniper MX480"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			stats, err := Convert(strings.NewReader(tc.raw+"\n"), &output, Options{SensorID: "snmp-test", LogKind: "snmp"})
			if err != nil || stats.Emitted != 1 || stats.Malformed != 0 {
				t.Fatalf("convert SNMP: stats=%+v err=%v output=%s", stats, err, output.String())
			}
			if strings.Contains(strings.ToLower(output.String()), "community") || strings.Contains(output.String(), "private-secret") || strings.Contains(output.String(), "another-secret") {
				t.Fatalf("SNMP credential escaped into normalized output: %s", output.String())
			}
			var event normalized.Event
			if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
				t.Fatal(err)
			}
			if event.Type != "discovery" || event.SourceEventType != "snmp" || event.Subject["ip"] != tc.deviceIP || event.Subject["entity_role"] != "network_device" {
				t.Fatalf("unexpected SNMP event identity: %+v", event)
			}
			if event.Payload["peer_ip"] != tc.peerIP || event.Payload["version"] != tc.version || event.Payload["system_description"] != tc.description {
				t.Fatalf("unexpected SNMP payload: %+v", event.Payload)
			}
		})
	}
}

func TestConvertSNMPSkipsRecordsWithoutIdentityOrResponder(t *testing.T) {
	input := strings.Join([]string{
		`{"ts":1785232800.25,"id.orig_h":"222.204.7.64","id.orig_p":40707,"id.resp_h":"10.120.249.163","id.resp_p":161,"version":"2c"}`,
		`{"ts":1785232801.25,"id.orig_h":"222.204.7.64","id.orig_p":40707,"id.resp_h":"10.120.249.163","id.resp_p":9999,"version":"2c","display_string":"Huawei AR6140"}`,
		`{"ts":"bad","id.orig_h":"222.204.7.64","id.orig_p":40707,"id.resp_h":"10.120.249.163","id.resp_p":161,"version":"2c","display_string":"Huawei AR6140"}`,
	}, "\n") + "\n"
	var output bytes.Buffer
	stats, err := Convert(strings.NewReader(input), &output, Options{LogKind: "snmp"})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Read != 3 || stats.Emitted != 0 || stats.Skipped != 3 || output.Len() != 0 {
		t.Fatalf("unexpected invalid SNMP handling: stats=%+v output=%s", stats, output.String())
	}
}

func TestConvertRouterHTTPLogTSV(t *testing.T) {
	input := "#separator \\x09\n#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\thost\tserver\ttitle\tvlan\n" +
		"1785232800.25\t10.0.0.2\t50000\t10.0.0.1\t80\ttcp\tar6140.local\tHuawei AR Web\tAR6140 Management\t120\n"
	var output bytes.Buffer
	stats, err := Convert(strings.NewReader(input), &output, Options{LogKind: "http"})
	if err != nil || stats.Emitted != 1 || !strings.Contains(output.String(), `"title":"AR6140 Management"`) || !strings.Contains(output.String(), `"vlan":"120"`) {
		t.Fatalf("unexpected TSV conversion stats=%+v err=%v output=%s", stats, err, output.String())
	}
}

func requireString(t *testing.T, event map[string]any, key string, expected string) {
	t.Helper()
	value, ok := event[key].(string)
	if !ok || value != expected {
		t.Fatalf("expected %s=%q, got %#v", key, expected, event[key])
	}
}

func requireNonEmptyString(t *testing.T, event map[string]any, key string) {
	t.Helper()
	value, ok := event[key].(string)
	if !ok || value == "" {
		t.Fatalf("expected non-empty string %s, got %#v", key, event[key])
	}
}

func requireNestedString(t *testing.T, event map[string]any, objectKey, fieldKey string) {
	t.Helper()
	object, ok := event[objectKey].(map[string]any)
	if !ok {
		t.Fatalf("expected object %s, got %#v", objectKey, event[objectKey])
	}
	value, ok := object[fieldKey].(string)
	if !ok || value == "" {
		t.Fatalf("expected non-empty string %s.%s, got %#v", objectKey, fieldKey, object[fieldKey])
	}
}
