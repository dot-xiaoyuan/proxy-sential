package zeek

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"proxy-sentinel/internal/normalized"
)

func TestConvertSIPServerResponse(t *testing.T) {
	input := `{"ts":1785232800.25,"uid":"sip-srv","orig_h":"222.204.40.17","orig_p":5060,"resp_h":"222.204.3.131","resp_p":5060,"server":"Cisco-CP-8841/9.4.1.1"}` + "\n"
	var output bytes.Buffer
	stats, err := Convert(strings.NewReader(input), &output, Options{SensorID: "sip-test", LogKind: "sip-server"})
	if err != nil || stats.Emitted != 1 {
		t.Fatalf("stats=%+v err=%v output=%s", stats, err, output.String())
	}
	var event normalized.Event
	if err = json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	if event.Subject["ip"] != "222.204.3.131" || event.Payload["server"] != "Cisco-CP-8841/9.4.1.1" || event.SourceEventType != "sip" {
		t.Fatalf("unexpected SIP server event: %+v", event)
	}
	if event.Flow["direction"] != "server" || event.Flow["src_ip"] != "222.204.40.17" {
		t.Fatalf("unexpected SIP server flow: %+v", event.Flow)
	}
}
