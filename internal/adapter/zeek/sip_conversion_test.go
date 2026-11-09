package zeek

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"proxy-sentinel/internal/normalized"
)

func TestConvertSIPUserAgentEvidence(t *testing.T) {
	input := strings.Join([]string{
		`{"ts":1785232800.25,"uid":"sip-1","id.orig_h":"222.204.40.17","id.orig_p":5060,"id.resp_h":"222.204.3.131","id.resp_p":5060,"method":"REGISTER","status_code":"401","user_agent":"Huawei eSpace 7910 V200R003C00","content_type":"-"}`,
		`{"ts":1785232801.25,"uid":"sip-2","id.orig_h":"222.204.40.18","id.orig_p":5060,"id.resp_h":"222.204.3.131","id.resp_p":5060,"method":"REGISTER","status_code":"200","user_agent":"-"}`,
	}, "\n") + "\n"
	var output bytes.Buffer
	stats, err := Convert(strings.NewReader(input), &output, Options{SensorID: "sip-test", LogKind: "sip"})
	if err != nil || stats.Emitted != 1 || stats.Skipped != 1 {
		t.Fatalf("stats=%+v err=%v output=%s", stats, err, output.String())
	}
	var event normalized.Event
	if err = json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	if event.Type != "device" || event.SourceEventType != "sip" || event.Subject["ip"] != "222.204.40.17" {
		t.Fatalf("unexpected SIP identity: %+v", event)
	}
	if event.Payload["user_agent"] != "Huawei eSpace 7910 V200R003C00" || event.Payload["method"] != "REGISTER" || event.Payload["status"] != "401" {
		t.Fatalf("unexpected SIP payload: %+v", event.Payload)
	}
	if event.Flow["direction"] != "client" {
		t.Fatalf("unexpected SIP direction: %+v", event.Flow)
	}
}
