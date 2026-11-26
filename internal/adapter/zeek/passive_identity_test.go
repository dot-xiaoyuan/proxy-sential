package zeek

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"proxy-sentinel/internal/normalized"
)

func identityRow(kind string) map[string]any {
	r := map[string]any{"ts": 1785232800.25, "uid": "identity-test", "id.orig_h": "10.0.0.2", "id.orig_p": 50000, "id.resp_h": "10.0.0.9", "id.resp_p": 161, "source_h": "10.0.0.9", "source_p": 161, "destination_h": "10.0.0.2", "destination_p": 50000, "is_orig": false}
	switch kind {
	case "snmp":
		r["parser_version"], r["is_response"] = "snmp-device/v1", true
		r["system_description"], r["system_object_id"] = "NetBotz Environment Sensor", "1.3.6.1.4.1.52674.500.1"
		r["snmp_varbinds"] = map[string]string{"1.3.6.1.2.1.1.1.0": "NetBotz Environment Sensor", "1.3.6.1.2.1.1.2.0": "1.3.6.1.4.1.52674.500.1"}
	case "bacnet":
		r["pdu_service"], r["object_type"], r["instance_number"] = "read-property-ack", "device", 101
		r["property"], r["value"] = "model-name", "Watchdog Test Controller"
	case "modbus":
		r["request_response"], r["mei_type"] = "RESPONSE", "READ-DEVICE-IDENTIFICATION"
		r["object_id_code"], r["object_value"], r["unit"] = "0x05", "Watchdog Test Controller", 1
	}
	return r
}

func convertIdentity(t *testing.T, kind string, row map[string]any) (normalized.Event, Stats) {
	t.Helper()
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	s, err := Convert(bytes.NewReader(raw), &out, Options{LogKind: kind, SensorID: "mirror-204"})
	if err != nil {
		t.Fatal(err)
	}
	var event normalized.Event
	if s.Emitted > 0 {
		if err := json.Unmarshal(out.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
	}
	return event, s
}

func TestPassiveIdentityResponsesDoNotInventMACOrHardwareType(t *testing.T) {
	for _, kind := range []string{"snmp", "bacnet", "modbus"} {
		t.Run(kind, func(t *testing.T) {
			r := identityRow(kind)
			r["orig_l2_addr"], r["src_mac"], r["community"], r["password"] = "00:11:22:33:44:55", "00:11:22:33:44:55", "private-secret", "password-secret"
			e, s := convertIdentity(t, kind, r)
			if s.Emitted != 1 || e.Subject["ip"] != "10.0.0.9" || e.Subject["mac"] != nil || e.SourceEventType != kind || e.Payload["is_response"] != true || e.Payload["response_source_ip"] != "10.0.0.9" {
				t.Fatalf("invalid identity: %+v %+v", s, e)
			}
			if e.RawRef["content_sha256"] == "" || e.RawRef["line_offset"] == nil {
				t.Fatalf("lost raw reference: %+v", e.RawRef)
			}
			b, _ := json.Marshal(e)
			if strings.Contains(string(b), "secret") || e.Payload["device_type"] != nil || e.Payload["product_verified"] == true {
				t.Fatalf("unsafe inference or credential: %s", b)
			}
		})
	}
}

func TestPassiveIdentityRejectsSourceDirectionMismatch(t *testing.T) {
	for _, kind := range []string{"snmp", "bacnet", "modbus"} {
		for _, edit := range []func(map[string]any){func(r map[string]any) { r["source_h"] = "10.0.0.66" }, func(r map[string]any) { r["is_orig"] = true }, func(r map[string]any) { delete(r, "is_orig") }, func(r map[string]any) { r["source_p"] = 9999 }} {
			r := identityRow(kind)
			edit(r)
			if _, s := convertIdentity(t, kind, r); s.Emitted != 0 {
				t.Fatalf("%s accepted inconsistent response: %+v", kind, r)
			}
		}
	}
}

func TestPassiveIdentityQueriesAndUnboundedFieldsAreNotEvidence(t *testing.T) {
	for _, tc := range []struct {
		kind, key string
		value     any
	}{
		{"snmp", "is_response", false}, {"snmp", "system_description", strings.Repeat("x", 2049)}, {"snmp", "system_object_id", "not-an-oid"},
		{"bacnet", "pdu_service", "read-property-request"}, {"bacnet", "object_type", "analog-input"}, {"bacnet", "property", "present-value"}, {"bacnet", "value", strings.Repeat("x", 513)},
		{"modbus", "request_response", "REQUEST"}, {"modbus", "mei_type", "CANOPEN-GENERAL-REFERENCE"}, {"modbus", "object_id_code", "0x80"}, {"modbus", "object_value", strings.Repeat("x", 513)},
	} {
		r := identityRow(tc.kind)
		r[tc.key] = tc.value
		if _, s := convertIdentity(t, tc.kind, r); s.Emitted != 0 {
			t.Fatalf("accepted %s %s=%v", tc.kind, tc.key, tc.value)
		}
	}
}

func TestSNMPVarbindAllowlistAndConflictingDescription(t *testing.T) {
	r := identityRow("snmp")
	r["snmp_varbinds"] = map[string]string{"1.3.6.1.2.1.1.1.0": "NetBotz Environment Sensor", "1.3.6.1.4.1.9.9.96.1.1.1.1.6": "secret"}
	e, s := convertIdentity(t, "snmp", r)
	if s.Emitted != 1 {
		t.Fatalf("%+v", s)
	}
	b, _ := json.Marshal(e.Payload["snmp_varbinds"])
	if strings.Contains(string(b), "secret") {
		t.Fatal("nonallowlisted management OID escaped")
	}
	r["snmp_varbinds"] = map[string]string{"1.3.6.1.2.1.1.1.0": "different device"}
	if _, s := convertIdentity(t, "snmp", r); s.Emitted != 0 {
		t.Fatal("conflicting convenience field accepted")
	}
}

func TestSNMPStackedVLANRetainsScopeWithoutInventingPhysicalIdentity(t *testing.T) {
	r := identityRow("snmp")
	r["vlan"], r["inner_vlan"] = "20", "101"
	e, s := convertIdentity(t, "snmp", r)
	if s.Emitted != 1 || e.Payload["vlan"] != "20" || e.Payload["inner_vlan"] != "101" || e.Payload["endpoint_identity_unverified"] != true {
		t.Fatalf("stacked scope lost: %+v %+v", s, e)
	}
}

func TestPassiveIdentityDuplicateAndLateTimestampRemainStable(t *testing.T) {
	for _, kind := range []string{"snmp", "bacnet", "modbus"} {
		r := identityRow(kind)
		first, _ := convertIdentity(t, kind, r)
		second, _ := convertIdentity(t, kind, r)
		if first.EventID == "" || first.EventID != second.EventID || first.Timestamp != "2026-07-28T10:00:00.25Z" {
			t.Fatalf("%s unstable event: %+v", kind, first)
		}
	}
}

func TestSNMPTSVPreservesQuotedAndMultilineDescription(t *testing.T) {
	r := identityRow("snmp")
	descr := "Comware Version 7\nH3C \"S5130\" Switch"
	r["system_description"] = descr
	r["snmp_varbinds"] = map[string]string{"1.3.6.1.2.1.1.1.0": descr}
	keys := []string{"ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "source_h", "source_p", "destination_h", "destination_p", "is_orig", "parser_version", "is_response", "system_description", "snmp_varbinds"}
	values := make([]string, len(keys))
	for i, k := range keys {
		value := stringify(r[k])
		if k == "snmp_varbinds" {
			b, _ := json.Marshal(r[k])
			value = string(b)
		}
		value = strings.ReplaceAll(value, "\\", "\\\\")
		value = strings.ReplaceAll(value, "\n", `\x0a`)
		values[i] = value
	}
	input := "#fields\t" + strings.Join(keys, "\t") + "\n" + strings.Join(values, "\t") + "\n"
	var out bytes.Buffer
	s, err := Convert(strings.NewReader(input), &out, Options{LogKind: "snmp"})
	if err != nil || s.Emitted != 1 {
		t.Fatalf("TSV failed: %+v %v", s, err)
	}
	var e normalized.Event
	if err = json.Unmarshal(out.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	if e.Payload["system_description"] != descr {
		t.Fatalf("description changed: %+v", e.Payload)
	}
}

func TestSNMPSelfMACExtractionAndConflictProtection(t *testing.T) {
	r := identityRow("snmp")
	r["system_description"] = "H3C Comware Switch"
	r["snmp_varbinds"] = map[string]string{
		"1.3.6.1.2.1.1.1.0":      "H3C Comware Switch",
		"1.3.6.1.2.1.17.1.1.0":   "aabbccddeeff",
		"1.0.8802.1.1.2.1.3.2.0": "aa:bb:cc:dd:ee:ff",
	}
	e, s := convertIdentity(t, "snmp", r)
	if s.Emitted != 1 || e.Payload["snmp_self_mac"] != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("expected snmp_self_mac aa:bb:cc:dd:ee:ff, got %+v", e.Payload)
	}

	// 若两个 OID 冲突，不得输出 snmp_self_mac
	rConflict := identityRow("snmp")
	rConflict["system_description"] = "H3C Comware Switch"
	rConflict["snmp_varbinds"] = map[string]string{
		"1.3.6.1.2.1.1.1.0":      "H3C Comware Switch",
		"1.3.6.1.2.1.17.1.1.0":   "aabbccddeeff",
		"1.0.8802.1.1.2.1.3.2.0": "00:22:33:44:55:66",
	}
	eConflict, sConflict := convertIdentity(t, "snmp", rConflict)
	if sConflict.Emitted != 1 || eConflict.Payload["snmp_self_mac"] != nil {
		t.Fatalf("conflicting SNMP MAC OIDs must not set snmp_self_mac: %+v", eConflict.Payload)
	}
}
