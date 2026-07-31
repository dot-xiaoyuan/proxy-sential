package zeek

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
