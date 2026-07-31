package identity

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestConvertRadiusJSONLToIdentityEvent(t *testing.T) {
	input := bytes.NewBufferString(`{"timestamp":"2026-07-29T10:00:00+08:00","account_id":"2026000123","ip":"10.20.15.83","calling_station_id":"AA-BB-CC-DD-EE-FF","ap":"Dorm-3F-AP08","vlan":"108","session_id":"sess-1"}` + "\n")
	var output bytes.Buffer
	stats, err := Convert(input, &output, Options{SensorID: "campus-mirror-01", Source: "radius"})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Read != 1 || stats.Emitted != 1 || stats.ByType["identity"] != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	var event map[string]any
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	requireIdentityString(t, event, "type", "identity")
	requireIdentityString(t, event, "source", "radius")
	requireIdentityNestedString(t, event, "subject", "account_id", "2026000123")
	requireIdentityNestedString(t, event, "subject", "mac", "aa:bb:cc:dd:ee:ff")
	requireIdentityNestedString(t, event, "subject", "endpoint_id", "mac:aa:bb:cc:dd:ee:ff")
	requireIdentityNestedString(t, event, "subject", "entity_role", "endpoint")
	requireIdentityNestedString(t, event, "subject", "access_id", "Dorm-3F-AP08")
	requireIdentityNestedString(t, event, "payload", "origin", "radius")
	requireIdentityNestedString(t, event, "payload", "vlan", "108")
}

func TestConvertPortalCSVToIdentityEvent(t *testing.T) {
	input := bytes.NewBufferString("timestamp,username,client_ip,client_mac,switch_port,entity_role\n2026-07-29 10:00:00,stu01,10.0.0.8,001122334455,sw1/0/3,endpoint\n")
	var output bytes.Buffer
	stats, err := Convert(input, &output, Options{SensorID: "campus-mirror-01", Source: "portal"})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Read != 1 || stats.Emitted != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	var event map[string]any
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	requireIdentityNestedString(t, event, "subject", "account_id", "stu01")
	requireIdentityNestedString(t, event, "subject", "mac", "00:11:22:33:44:55")
	requireIdentityNestedString(t, event, "subject", "access_id", "sw1/0/3")
}

func requireIdentityString(t *testing.T, event map[string]any, key string, expected string) {
	t.Helper()
	value, ok := event[key].(string)
	if !ok || value != expected {
		t.Fatalf("expected %s=%q, got %#v", key, expected, event[key])
	}
}

func requireIdentityNestedString(t *testing.T, event map[string]any, objectKey, fieldKey, expected string) {
	t.Helper()
	object, ok := event[objectKey].(map[string]any)
	if !ok {
		t.Fatalf("expected object %s, got %#v", objectKey, event[objectKey])
	}
	value, ok := object[fieldKey].(string)
	if !ok || value != expected {
		t.Fatalf("expected %s.%s=%q, got %#v", objectKey, fieldKey, expected, object[fieldKey])
	}
}
