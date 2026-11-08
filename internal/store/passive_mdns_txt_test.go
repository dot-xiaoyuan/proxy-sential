package store

import (
	"testing"
	"time"
)

func TestPassiveTXTObservationUsesModelAndInstanceAddress(t *testing.T) {
	scope, _ := parsePassiveDiscoveryScope("10.0.0.0/8")
	at := time.Now().UTC()
	event := passiveTestEvent("mdns", "", "", map[string]any{
		"is_response": true, "record_type": "TXT", "record_name": "ff 43f265c-dab9(10.152.42.82)._airplay._tcp.local",
		"record_text": "deviceid=aa features=0x527F model=AppleTV3,1", "ttl": 4500,
	})
	observation, ok := passiveTXTObservation(event, "campus-204", "enp3s0f0", "ff 43f265c-dab9(10.152.42.82)._airplay._tcp.local", "deviceid=aa features=0x527F model=AppleTV3,1", at, at.Add(time.Hour), scope)
	if !ok {
		t.Fatal("txt observation not produced")
	}
	if observation.IP != "10.152.42.82" || observation.DeviceType != "media_device" || observation.ModelName != "AppleTV3,1" || observation.Origin != "dns_sd" {
		t.Fatalf("unexpected observation: %+v", observation)
	}
}
