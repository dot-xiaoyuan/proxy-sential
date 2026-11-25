package zeek

import (
	"bytes"
	"encoding/json"
	"proxy-sentinel/internal/normalized"
	"strings"
	"testing"
)

func TestHTTPDeviceKeepsResponseOwnerAndClientDirection(t *testing.T) {
	var out bytes.Buffer
	_, err := Convert(strings.NewReader(`{"ts":1785232800,"orig_h":"10.0.0.2","resp_h":"10.0.0.10","orig_l2_addr":"00:11:22:33:44:55","server":"PrinterServer","status":200,"user_agent":"Firefox"}`+"\n"), &out, Options{LogKind: "http-device"})
	if err != nil {
		t.Fatal(err)
	}
	var e normalized.Event
	if err = json.Unmarshal(bytes.TrimSpace(out.Bytes()), &e); err != nil {
		t.Fatal(err)
	}
	if e.Subject["ip"] != "10.0.0.10" || e.Subject["mac"] != nil || e.Payload["is_response"] != true || e.Flow["src_ip"] != "10.0.0.2" || e.Flow["dst_ip"] != "10.0.0.10" {
		t.Fatalf("response ownership/flow corrupted: %+v", e)
	}
}
func TestTLSKeepsServerFingerprintAndCertificateReferences(t *testing.T) {
	var out bytes.Buffer
	_, err := Convert(strings.NewReader(`{"ts":1785232800,"uid":"C1","id.orig_h":"10.0.0.2","id.resp_h":"10.0.0.10","ja3":"client","ja3s":"server","cert_chain_fps":["F1","F2"],"client_cert_chain_fps":["C3"]}`+"\n"), &out, Options{LogKind: "ssl"})
	if err != nil {
		t.Fatal(err)
	}
	var e normalized.Event
	json.Unmarshal(bytes.TrimSpace(out.Bytes()), &e)
	if e.Payload["ja3s"] != "server" || e.Payload["certificate_chain_fps"] != "F1,F2" || e.Payload["client_certificate_chain_fps"] != "C3" {
		t.Fatalf("TLS existing fields lost: %+v", e.Payload)
	}
}

func TestSIPOriginalRecordsHaveDistinctStableReferences(t *testing.T) {
	input := `{"ts":1785232800,"id.orig_h":"10.0.0.2","id.resp_h":"10.0.0.10","user_agent":"Huawei eSpace 7910 V200R003C00","method":"REGISTER"}` + "\n"
	var a, b bytes.Buffer
	Convert(strings.NewReader(input), &a, Options{LogKind: "sip"})
	Convert(strings.NewReader(strings.ReplaceAll(input, "10.0.0.2", "10.0.0.3")), &b, Options{LogKind: "sip"})
	var ea, eb normalized.Event
	json.Unmarshal(bytes.TrimSpace(a.Bytes()), &ea)
	json.Unmarshal(bytes.TrimSpace(b.Bytes()), &eb)
	if ea.EventID == eb.EventID {
		t.Fatal("different SIP records share the empty-byte digest")
	}
}

func TestX509MetadataAndServerLeafShareFingerprint(t *testing.T) {
	const fp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, tc := range []struct{ kind, record string }{
		{"x509", `{"ts":1785232800,"fingerprint":"` + fp + `","certificate.subject":"CN=fixture","host_cert":true}`},
		{"ssl", `{"ts":1785232800,"id.orig_h":"192.0.2.1","id.resp_h":"192.0.2.2","cert_chain_fps":["` + fp + `"],"subject":"CN=fixture"}`},
	} {
		var out bytes.Buffer
		stats, err := Convert(strings.NewReader(tc.record+"\n"), &out, Options{LogKind: tc.kind})
		var e normalized.Event
		if err != nil || stats.Emitted != 1 || json.Unmarshal(out.Bytes(), &e) != nil || e.Payload["certificate_fingerprint"] != fp {
			t.Fatalf("missing %s metadata: %+v %v", tc.kind, stats, err)
		}
		if tc.kind == "x509" && (e.Subject["ip"] != nil || e.Flow["dst_ip"] != nil) {
			t.Fatal("invented endpoint on detached certificate")
		}
	}
}
