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
