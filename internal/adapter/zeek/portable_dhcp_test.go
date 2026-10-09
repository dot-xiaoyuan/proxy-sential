package zeek

import (
	"bytes"
	"encoding/json"
	"proxy-sentinel/internal/normalized"
	"testing"
)

func TestPortableDHCPClientIsNotAnOperatingSystem(t *testing.T) {
	for _, client := range []string{"dhcpcd-16", "dhcpcd 6.8.2", "udhcpc-1.36", "dhclient/4.4"} {
		p := map[string]any{"vendor_class": client, "software_name": client, "device_hint": "linux"}
		if got := deviceHint(p); got != "" {
			t.Errorf("%s became %s", client, got)
		}
		if got := softwareDeviceHint(p); got != "" {
			t.Errorf("software %s became %s", client, got)
		}
	}
	for _, tc := range []struct {
		p    map[string]any
		want string
	}{{map[string]any{"vendor_class": "MSFT 5.0"}, "windows"}, {map[string]any{"hostname": "android-phone", "vendor_class": "dhcpcd-16"}, "android"}, {map[string]any{"hostname": "ubuntu-host", "vendor_class": "dhcpcd-16"}, "linux"}} {
		if got := deviceHint(tc.p); got != tc.want {
			t.Errorf("explicit hint lost: got=%s want=%s", got, tc.want)
		}
	}
}

func TestPortableDHCPNormalizedReplayKeepsRawIdentity(t *testing.T) {
	input := bytes.NewBufferString(`{"ts":1790809200,"client_addr":"192.0.2.82","server_addr":"192.0.2.1","mac":"02:00:00:00:00:82","host_name":"fixture-phone","assigned_addr":"192.0.2.82","client_software":"dhcpcd-16","requested_options":["1","3","6"]}` + "\n")
	var output bytes.Buffer
	stats, err := Convert(input, &output, Options{SensorID: "fixture", LogKind: "dhcp"})
	if err != nil || stats.Emitted != 1 || stats.Malformed != 0 {
		t.Fatalf("adapter failed: %+v %v", stats, err)
	}
	var event normalized.Event
	if err = json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event.Payload["vendor_class"] != "dhcpcd-16" || event.Subject["mac"] != "02:00:00:00:00:82" || event.Payload["hostname"] != "fixture-phone" || event.Payload["device_hint"] != nil {
		t.Fatalf("identity lost or portable software became OS: %+v", event.Payload)
	}
}
