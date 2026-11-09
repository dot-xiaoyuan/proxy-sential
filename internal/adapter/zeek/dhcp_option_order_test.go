package zeek

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"proxy-sentinel/internal/normalized"
)

func TestConvertDHCPOptionOrder(t *testing.T) {
	input := "#separator \\x09\n#fields\tts\tclient_addr\tmac\tmsg_types\toption_order\trequested_options\tvendor_class\n" +
		"1785232800.25\t10.0.0.5\taa:bb:cc:dd:ee:ff\tDISCOVER\t53,57,55,60,61\t1,3,6,15\tHuawei\n"
	var output bytes.Buffer
	stats, err := Convert(strings.NewReader(input), &output, Options{SensorID: "dhcp-test", LogKind: "dhcp"})
	if err != nil || stats.Emitted != 1 {
		t.Fatalf("stats=%+v err=%v output=%s", stats, err, output.String())
	}
	var event normalized.Event
	if err = json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	if event.Payload["dhcp_options"] != "53,57,55,60,61" || event.Payload["requested_options"] != "1,3,6,15" {
		t.Fatalf("unexpected DHCP payload: %+v", event.Payload)
	}
}
