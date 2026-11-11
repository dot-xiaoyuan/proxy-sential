package discovery

import (
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestAdaptSADPStandardEventPreservesProductEvidence(t *testing.T) {
	source := normalized.Event{
		SchemaVersion: "v1", EventID: "sadp-sample", Source: "packet-sidecar", SourceEventType: "sadp", Type: "device", Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Observer: map[string]any{"sensor_id": "campus-204", "interface": "enp3s0f0"},
		Subject:  map[string]any{"ip": "10.126.253.1", "mac": "08:54:11:13:c1:84", "campus_id": "campus-204"},
		Payload:  map[string]any{"product_model": "DS-K1T6QT-F72M", "claimed_ip": "10.126.253.1", "claimed_mac": "08:54:11:13:c1:84", "l2_source_mac": "08:54:11:13:c1:84", "identity_status": "direct_l2", "message_type": "probe_match", "is_response": true, "payload_sha256": "sample-hash"},
	}
	adapted, err := AdaptDiscoveryEvent(source)
	if err != nil {
		t.Fatal(err)
	}
	if adapted.Type != "discovery" || adapted.Payload["origin"] != "sadp" || adapted.Payload["product_model"] != "DS-K1T6QT-F72M" {
		t.Fatalf("SADP product fields lost: %+v", adapted)
	}
	if _, ok := source.Payload["origin"]; ok {
		t.Fatal("adapter mutated the authoritative event")
	}
	observation, err := FromEvent(adapted)
	if err != nil || observation.DeviceType != "access_control" {
		t.Fatalf("verified SADP model not classified: observation=%+v err=%v", observation, err)
	}
	adapted.Subject["mac"] = ""
	adapted.Payload["identity_status"] = "l2_mismatch"
	observation, err = FromEvent(adapted)
	if err != nil || observation.DeviceType != "" || observation.Evidence.Payload["product_verified"] == true {
		t.Fatalf("unverified SADP model became a type: observation=%+v err=%v", observation, err)
	}
}
