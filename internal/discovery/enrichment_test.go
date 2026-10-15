package discovery

import (
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

func TestEnrichmentParsersAndTarget(t *testing.T) {
	p, e := parseEnrichment("onvif", []byte(`<q:Envelope xmlns:q="urn:soap"><q:Body><x:GetDeviceInformationResponse xmlns:x="urn:device"><x:Manufacturer>Hikvision</x:Manufacturer><x:Model>DS-2CD2143</x:Model></x:GetDeviceInformationResponse></q:Body></q:Envelope>`))
	if e != nil {
		t.Fatal(e)
	}
	o := Observation{Origin: "onvif", ObservedAt: time.Now(), ValidUntil: time.Now().Add(time.Hour), Evidence: normalized.Event{Payload: p}}
	applyProductRules(&o)
	if ClassifyIoT([]Observation{o}, time.Now()).DeviceType != "camera" {
		t.Fatal("verified model not classified")
	}
	if _, e = parseEnrichment("onvif", []byte(`<Probe><Model>DS-2CD2143</Model></Probe>`)); e == nil {
		t.Fatal("query passed response validation")
	}
	if _, e = parseEnrichment("onvif", []byte(`<!DOCTYPE foo><GetDeviceInformationResponse/>`)); e == nil {
		t.Fatal("DTD admitted")
	}
}
