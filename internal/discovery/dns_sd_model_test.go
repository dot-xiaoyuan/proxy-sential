package discovery

import (
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
)

func TestDNSSDModelFromTXT(t *testing.T) {
	cases := []struct {
		name, txt, want string
	}{
		{"product", "product=(HP LaserJet Pro)", "HP LaserJet Pro"},
		{"ty", "ty=HP LaserJet Pro;product=(HP LaserJet Pro)", "HP LaserJet Pro"},
		{"model", "model=AppleTV6,2", "AppleTV6,2"},
		{"md", "md=Chromecast", "Chromecast"},
		{"usb_mdl", "usb_mdl=Brother HL-L2350DW", "Brother HL-L2350DW"},
		{"spaces", "  model =  (Pixel 8)  ", "Pixel 8"},
		{"unrelated keys", "rp=ipp/print;firmware=1.2.3", ""},
		{"airplay", "deviceid=5a:62:cf:42:03:7a features=0x527FFFF7,0x1E srcvers=220.68 vv=2 model=AppleTV3,1 flags=0x4 pw=0", "AppleTV3,1"},
		{"space separated", "model=MacBookPro18,3 flags=0x4", "MacBookPro18,3"},
		{"value with spaces", "ty=HP LaserJet Pro features=x", "HP LaserJet Pro"},
		{"raop metadata", "cn=0,1 md=0,1,2 am=AppleTV3,1 sf=0x44", "AppleTV3,1"},
		{"raop metadata only", "md=0,1,2", ""},
		{"raop mac model", "md=0,1,2 am=Mac15,12", "Mac15,12"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DNSSDModelFromTXT(tc.txt); got != tc.want {
				t.Fatalf("DNSSDModelFromTXT(%q) = %q, want %q", tc.txt, got, tc.want)
			}
		})
	}
	if got := DNSSDModelFromTXT("model=\x00bad\x01name"); got != "badname" {
		t.Fatalf("control characters must be stripped: %q", got)
	}
	if got := DNSSDModelFromTXT("model=" + strings.Repeat("x", 200)); len([]rune(got)) != 128 {
		t.Fatalf("model text must stay bounded, got %d runes", len([]rune(got)))
	}
}

func TestFromEventDNSDCarriesModelName(t *testing.T) {
	event := normalized.Event{
		SchemaVersion: "v1",
		EventID:       "dns-sd-model-test",
		Type:          "discovery",
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		Subject:       map[string]any{"ip": "10.20.30.40"},
		Payload: map[string]any{
			"origin":       "dns_sd",
			"is_response":  true,
			"service_type": "_ipp._tcp",
			"txt":          "ty=HP LaserJet Pro;product=(HP LaserJet Pro)",
			"ttl":          120,
		},
	}
	observation, err := FromEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	if observation.ModelName != "HP LaserJet Pro" {
		t.Fatalf("DNS-SD TXT model was not kept on the observation: %+v", observation)
	}
}

func TestDNSSDReceiverImplementationIsSoftwareEvidence(t *testing.T) {
	o := hardwareTestObservation(time.Now().UTC().Add(-time.Minute))
	o.Origin = "dns_sd"
	o.ModelName = ""
	o.Evidence.Payload = map[string]any{"hardware_identity": "unique_binding", "service_type": "_leboremote._tcp", "txt": "port=35037 version=3.2 packagename=com.tcl.MultiScreenInteraction_TV htv=1 etv=1"}
	f, err := HardwareFactFromObservation(o)
	if err != nil || f == nil {
		t.Fatalf("lost owned software clue: %+v %v", f, err)
	}
	found := false
	for _, s := range f.Signals {
		if s.Field == "dns_sd_model" {
			t.Fatal("package treated as hardware model")
		}
		if s.Field == "dns_sd_receiver_implementation" && s.Value == "com.tcl.MultiScreenInteraction_TV" {
			found = true
		}
	}
	if !found {
		t.Fatal("receiver software not retained")
	}
	o.Evidence.Payload["service_type"] = "_ipp._tcp"
	if dnsSDReceiverImplementation(o) != "" {
		t.Fatal("unrelated service supplied receiver marker")
	}
	o.Evidence.Payload["service_type"] = "_leboremote._tcp"
	o.Evidence.Payload["txt"] = "packagename=com.tcl.MultiScreenInteraction_TV.evil"
	if dnsSDReceiverImplementation(o) != "" {
		t.Fatal("partial package matched")
	}
}

// The field sample publishes these records in separate services on one scoped
// identity. Never synthesize a single TXT containing both statements.
func TestAirPlaySeparateServicesScopeWithdrawalAndTime(t *testing.T) {
	now := time.Now().UTC()
	o := hardwareTestObservation(now.Add(-time.Minute))
	o.Origin = "dns_sd"
	o.ModelName = "AppleTV3,1"
	o.Evidence.Payload = map[string]any{"hardware_identity": "unique_binding", "service_type": "_airplay._tcp", "service_instance": "tv._airplay._tcp.local", "txt": "model=AppleTV3,1 flags=0x4"}
	model, err := HardwareFactFromObservation(o)
	if err != nil || model == nil {
		t.Fatal(err)
	}
	o.ModelName = ""
	o.Evidence.Payload = map[string]any{"hardware_identity": "unique_binding", "service_type": "_leboremote._tcp", "service_instance": "tv._leboremote._tcp.local", "txt": "port=35037 version=3.2 packagename=com.tcl.MultiScreenInteraction_TV htv=1 etv=1"}
	receiver, err := HardwareFactFromObservation(o)
	if err != nil || receiver == nil {
		t.Fatal(err)
	}
	state, err := EvaluateHardwareFacts([]HardwareFact{*model, *receiver}, nil, now)
	if err != nil || state.HardwareModel != "" || state.Manufacturer != "" || state.HardwareTypeStatus == "identified" {
		t.Fatalf("compatibility became hardware: %+v %v", state, err)
	}
	receiver.Revoked = true
	state, err = EvaluateHardwareFacts([]HardwareFact{*model, *receiver}, nil, now)
	if err != nil || state.Manufacturer != "Apple" {
		t.Fatalf("withdrawn marker suppressed model: %+v %v", state, err)
	}
	receiver.Revoked = false
	receiver.ObservedAt = model.ObservedAt.Add(-6 * time.Minute)
	receiver.ActiveUntil = model.ObservedAt.Add(-time.Minute)
	state, err = EvaluateHardwareFacts([]HardwareFact{*model, *receiver}, nil, now)
	if err != nil || state.Manufacturer != "Apple" {
		t.Fatalf("old software marker erased newer model: %+v %v", state, err)
	}
	receiver.IdentityKey += "other-scope"
	if _, err = EvaluateHardwareFacts([]HardwareFact{*model, *receiver}, nil, now); err == nil {
		t.Fatal("cross-scope software marker joined")
	}
}
