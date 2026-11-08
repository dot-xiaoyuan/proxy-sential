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

func TestPassiveTXTObservationTypesAndroidTVPackage(t *testing.T) {
	scope, _ := parseParseScopeForTest(t)
	at := time.Now().UTC()
	text := "port=35037 version=3.2 packagename=com.tcl.MultiScreenInteraction_TV htv=1 etv=1"
	event := passiveTestEvent("mdns", "", "", map[string]any{"is_response": true, "record_type": "TXT", "record_name": "ff 43f265c-dab9(10.152.42.82)._leboremote._tcp.local", "record_text": text, "ttl": 4500})
	observation, ok := passiveTXTObservation(event, "campus-204", "enp3s0f0", "ff 43f265c-dab9(10.152.42.82)._leboremote._tcp.local", text, at, at.Add(time.Hour), scope)
	if !ok || observation.DeviceType != "media_device" || observation.IP != "10.152.42.82" || observation.ModelName != "" {
		t.Fatalf("android tv txt observation: ok=%v %+v", ok, observation)
	}
}

func parseParseScopeForTest(t *testing.T) (passiveDiscoveryScope, error) {
	t.Helper()
	return parsePassiveDiscoveryScope("10.0.0.0/8")
}

func TestPassiveTXTObservationFallsBackToResponderAddress(t *testing.T) {
	scope, _ := parseParseScopeForTest(t)
	at := time.Now().UTC()
	text := "model=J181AP"
	event := passiveTestEvent("mdns", "10.152.11.9", "", map[string]any{"is_response": true, "record_type": "TXT", "record_name": "ipad._device-info._tcp.local", "record_text": text, "ttl": 4500})
	observation, ok := passiveTXTObservation(event, "campus-204", "enp3s0f0", "ipad._device-info._tcp.local", text, at, at.Add(time.Hour), scope)
	if !ok || observation.IP != "10.152.11.9" || observation.DeviceType != "tablet" || observation.ModelName != "J181AP" {
		t.Fatalf("device-info observation: ok=%v %+v", ok, observation)
	}
}

func TestPassiveTXTObservationSkipsLinkLocalResponder(t *testing.T) {
	scope, _ := parseParseScopeForTest(t)
	at := time.Now().UTC()
	text := "model=J181AP"
	event := passiveTestEvent("mdns", "fe80::1813:991:cb61:4405", "", map[string]any{"is_response": true, "record_type": "TXT", "record_name": "ipad._device-info._tcp.local", "record_text": text, "ttl": 4500})
	if _, ok := passiveTXTObservation(event, "campus-204", "enp3s0f0", "ipad._device-info._tcp.local", text, at, at.Add(time.Hour), scope); ok {
		t.Fatal("link-local responder must not create a TXT observation")
	}
}
