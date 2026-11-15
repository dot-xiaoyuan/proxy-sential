package zeek

import (
	"bytes"
	"encoding/json"
	"proxy-sentinel/internal/normalized"
	"strings"
	"testing"
)

func TestProtocolPreservesZeekConnectionScope(t *testing.T) {
	for _, kind := range []string{"ssl", "sip", "http"} {
		var out bytes.Buffer
		_, err := Convert(strings.NewReader(`{"ts":1785232800,"id.orig_h":"10.0.0.2","id.resp_h":"10.0.0.10","id.ctx.vlan":2701,"id.ctx.inner_vlan":26,"user_agent":"Huawei eSpace 7910 V200R003C00","method":"REGISTER"}`+"\n"), &out, Options{LogKind: kind})
		if err != nil {
			t.Fatal(err)
		}
		var e normalized.Event
		if err = json.Unmarshal(bytes.TrimSpace(out.Bytes()), &e); err != nil {
			t.Fatal(err)
		}
		if e.Payload["vlan"] != "2701/26" {
			t.Fatalf("%s scope lost: %+v", kind, e)
		}
	}
}

func TestConnectionVLANRejectsConflictsAndPreservesZero(t *testing.T) {
	for _, fields := range []map[string]string{
		{"id.ctx.inner_vlan": "26"}, {"id.ctx.vlan": "4095"}, {"id.ctx.vlan": "-1"},
		{"id.ctx.vlan": "2701", "vlan": "2702"}, {"id.ctx.vlan": "2701", "id.ctx.inner_vlan": "26", "capture_vlan": "2701/27"},
	} {
		if err := retainConnectionVLAN(fields); err == nil {
			t.Fatalf("accepted ambiguous scope: %v", fields)
		}
	}
	fields := map[string]string{"id.ctx.vlan": "0", "id.ctx.inner_vlan": "0"}
	if err := retainConnectionVLAN(fields); err != nil || fields["vlan"] != "0/0" {
		t.Fatalf("zero tags lost: %v %v", fields, err)
	}
}

func TestCustomDeviceLogsPreserveCapturedScope(t *testing.T) {
	for _, kind := range []string{"http-device", "sip-server", "rtsp-device", "mdns"} {
		var out bytes.Buffer
		_, err := Convert(strings.NewReader(`{"ts":1785232800,"uid":"C1","orig_h":"10.0.0.2","resp_h":"10.0.0.3","src_h":"10.0.0.2","dst_h":"10.0.0.3","src_ip":"10.0.0.2","dst_ip":"224.0.0.251","capture_vlan":"2701/26","server":"DeviceServer","direction":"client","value":"NVR","is_response":true,"record_type":"TXT","record_text":"am=AppleTV3,1"}`+"\n"), &out, Options{LogKind: kind})
		if err != nil {
			t.Fatal(err)
		}
		var e normalized.Event
		if err = json.Unmarshal(bytes.TrimSpace(out.Bytes()), &e); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if e.Payload["vlan"] != "2701/26" && e.Subject["vlan"] != "2701/26" {
			t.Fatalf("%s lost scope: %+v", kind, e)
		}
	}
}
