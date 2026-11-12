package discovery

import (
	"testing"
	"time"
)

func TestSADPProductModelFamiliesStayDistinct(t *testing.T) {
	for _, sample := range []struct{ model, want string }{
		{"DS-K1T6QT-F72M", "access_control"},
		{"DS-2CD2143G0-I", "camera"},
		{"DS-7608NI-K2", "recorder"},
		{"DS-7908N-R4(C)", "recorder"},
		{"DS-8832N-R8(C)", "recorder"},
		{"DS-7916N-K4", "recorder"},
		{"iDS-2DC3A40BX-DE", "camera"},
		{"Hikvision", ""},
		{"DS-7908N", ""},
		{"iDS-2DC3A40BX-DE2", ""},
		{"852122", ""},
	} {
		kind, _, _ := ProductModelType(sample.model)
		if kind != sample.want {
			t.Fatalf("%q classified as %q, want %q", sample.model, kind, sample.want)
		}
	}
}

func TestSADPVerifiedTypeFeedsDiscoveryAndTerminalCensus(t *testing.T) {
	now := time.Now().UTC()
	sadp := Observation{ID: "sadp", Origin: "sadp", IP: "10.126.253.1", MAC: "08:54:11:13:c1:84", Node: "campus-204", Site: "campus-204", Domain: "enp3s0f0", ModelName: "DS-K1T6QT-F72M", DeviceType: "access_control", Confidence: "strong", ObservedAt: now, ValidUntil: now.Add(30 * time.Minute)}
	row := deviceObservationRow{DeviceKey: "device", Observation: sadp, ProfileDeviceType: "camera", ProfileTypeConfidence: .7}
	view := aggregateDeviceRows([]deviceObservationRow{row}, now)[0]
	if view.ClassificationStatus != "identified" || view.DeviceType != "access_control" || censusTerminalType(view) != "access_control" || !censusDirectTypeEvidence(view, "access_control", now) {
		t.Fatalf("verified SADP was not an effective census type: %+v", view)
	}
	camera := sadp
	camera.ID, camera.Origin, camera.DeviceType, camera.ModelName = "camera", "ws_discovery", "camera", "DS-2CD2143G0-I"
	conflict := aggregateDeviceRows([]deviceObservationRow{row, {DeviceKey: "device", Observation: camera}}, now)[0]
	if conflict.ClassificationStatus != "conflict" || conflict.DeviceType != "" {
		t.Fatalf("contradictory current product evidence was hidden: %+v", conflict)
	}
	expired := aggregateDeviceRows([]deviceObservationRow{row}, now.Add(time.Hour))[0]
	if expired.ClassificationStatus != "expired" || censusDirectTypeEvidence(expired, "access_control", now.Add(time.Hour)) {
		t.Fatalf("expired SADP stayed current: %+v", expired)
	}
	otherVLAN := sadp
	otherVLAN.ID, otherVLAN.VLAN = "sadp-other-vlan", "18"
	sadp.VLAN = "17"
	separate := aggregateDeviceRows([]deviceObservationRow{{DeviceKey: "vlan-17", Observation: sadp}, {DeviceKey: "vlan-18", Observation: otherVLAN}}, now)
	if len(separate) != 2 {
		t.Fatalf("same MAC across VLANs was merged: %+v", separate)
	}
}
