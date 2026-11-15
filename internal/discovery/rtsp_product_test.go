package discovery

import (
	"testing"
	"time"
)

func TestRTSPProductAndHardwareRequireOwnClient(t *testing.T) {
	now := time.Now().UTC()
	o := hardwareTestObservation(now.Add(-time.Minute))
	o.Origin = "rtsp"
	o.EventID = "zeek-aaaaaaaaaaaaaaaaaaaaaaaa"
	o.Evidence.EventID = o.EventID
	o.Evidence.Source = "zeek"
	o.Evidence.Payload = map[string]any{"method": "DESCRIBE", "user_agent": "HIKVISION player NVR V4.74.210", "hardware_identity": "unique_binding"}
	o.Evidence.Flow = map[string]any{"src_ip": o.IP, "dst_ip": "10.0.0.8", "dst_port": 554, "direction": "client"}
	o.Evidence.RawRef = map[string]any{"content_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	c, err := BuildIPProductClue(o, now)
	if err != nil || c == nil || c.Type != "recorder" || c.Model != "" || c.Attribution != "request_ip" {
		t.Fatalf("recorder product lost: %+v %v", c, err)
	}
	f, err := HardwareFactFromObservation(o)
	if err != nil || f == nil || len(f.Signals) != 1 {
		t.Fatalf("attributed recorder lost: %+v %v", f, err)
	}
	o.MAC = ""
	if f, _ := HardwareFactFromObservation(o); f != nil {
		t.Fatal("IP product became physical identity")
	}
	o.IP = "10.0.0.8"
	if c, _ := BuildIPProductClue(o, now); c != nil {
		t.Fatal("recorder UA assigned to camera")
	}
	o.Evidence.Flow["direction"] = "server"
	if c, _ := BuildIPProductClue(o, now); c != nil {
		t.Fatal("server direction accepted client UA")
	}
}
