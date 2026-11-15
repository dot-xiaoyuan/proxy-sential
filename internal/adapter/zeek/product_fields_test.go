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
