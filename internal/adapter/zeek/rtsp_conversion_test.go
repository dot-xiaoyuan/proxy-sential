package zeek

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"proxy-sentinel/internal/normalized"
)

func TestConvertRTSPDeviceIdentities(t *testing.T) {
	input := strings.Join([]string{
		`{"ts":1785232800.25,"uid":"rtsp-1","src_h":"10.126.255.252","src_p":41000,"dst_h":"10.126.254.7","dst_p":554,"method":"DESCRIBE","url":"rtsp://10.126.254.7/ch1","direction":"client","value":"HIKVISION player NVR V4.84.030"}`,
		`{"ts":1785232801.25,"uid":"rtsp-1","src_h":"10.126.255.252","src_p":41000,"dst_h":"10.126.254.7","dst_p":554,"method":"DESCRIBE","url":"rtsp://10.126.254.7/ch1","direction":"server","value":"Hikvision"}`,
	}, "\n") + "\n"
	var output bytes.Buffer
	stats, err := Convert(strings.NewReader(input), &output, Options{SensorID: "rtsp-test", LogKind: "rtsp-device"})
	if err != nil || stats.Emitted != 2 {
		t.Fatalf("stats=%+v err=%v output=%s", stats, err, output.String())
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	var client, server normalized.Event
	if err = json.Unmarshal([]byte(lines[0]), &client); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal([]byte(lines[1]), &server); err != nil {
		t.Fatal(err)
	}
	if client.SourceEventType != "rtsp" || client.Subject["ip"] != "10.126.255.252" || client.Payload["user_agent"] != "HIKVISION player NVR V4.84.030" {
		t.Fatalf("unexpected RTSP client event: %+v", client)
	}
	if server.Subject["ip"] != "10.126.254.7" || server.Payload["server"] != "Hikvision" {
		t.Fatalf("unexpected RTSP server event: %+v", server)
	}
}
