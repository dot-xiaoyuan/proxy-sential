package discovery

import (
	"proxy-sentinel/internal/normalized"
	"testing"
	"time"
)

func TestIoTClassificationRequiresProductEvidence(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name, origin, kind string
		payload            map[string]any
		want               string
	}{
		{"computer airplay", "dns_sd", "", map[string]any{"service_type": "_airplay._tcp", "txt": "model=MacBookPro18,1"}, ""},
		{"generic casting", "dns_sd", "", map[string]any{"service_type": "_googlecast._tcp"}, ""},
		{"printer product", "dns_sd", "", map[string]any{"service_type": "_ipp._tcp", "txt": "ty=HP LaserJet Pro;product=(HP LaserJet Pro)"}, "printer"},
		{"apple tv", "dns_sd", "", map[string]any{"service_type": "_airplay._tcp", "txt": "model=AppleTV6,2"}, "media"},
		{"wsd camera", "ws_discovery", "", map[string]any{"is_response": true, "types": "dn:NetworkVideoTransmitter"}, "camera"},
		{"wsd query", "ws_discovery", "", map[string]any{"message": "probe", "types": "dn:NetworkVideoTransmitter"}, ""},
		{"dhcp hostname", "dhcp", "", map[string]any{"hostname": "camera-printer"}, ""},
		{"rtsp port", "rtsp", "", map[string]any{"port": 554}, ""},
		{"mqtt client", "mqtt", "", map[string]any{"client_id": "sensor-123"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := Observation{Origin: tc.origin, DeviceType: tc.kind, ObservedAt: now, ValidUntil: now.Add(time.Hour), Evidence: normalized.Event{Payload: tc.payload}}
			c := ClassifyIoT([]Observation{o}, now)
			if c.Category != tc.want {
				t.Fatalf("got %+v want %q", c, tc.want)
			}
		})
	}
	o := Observation{Origin: "ws_discovery", ObservedAt: now, ValidUntil: now.Add(time.Hour), Evidence: normalized.Event{Payload: map[string]any{"is_response": true, "types": "dn:NetworkVideoTransmitter"}}}
	if c := ClassifyIoT([]Observation{o, {Origin: "lldp", DeviceType: "router", ObservedAt: now, ValidUntil: now.Add(time.Hour)}}, now); !c.Conflict || c.Category != "" {
		t.Fatalf("infrastructure exclusion missing: %+v", c)
	}
	o.Withdrawn = true
	if c := ClassifyIoT([]Observation{o}, now); c.Category != "" {
		t.Fatal("withdrawn device admitted")
	}
}

func TestIOTClassificationUsesServiceCatalog(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name, service, txt, want string
	}{
		{"printer product", "_ipp._tcp", "ty=HP LaserJet Pro", "printer"},
		{"scanner product", "_uscan._tcp", "product=Canon DR-C225", "printer"},
		{"casting product", "_googlecast._tcp", "product=Chromecast", "media"},
		{"no product marker", "_ipp._tcp", "rp=ipp/print", ""},
		{"unknown service", "_acme._tcp", "product=Widget", ""},
		{"known kind outside iot catalogue", "_smb._tcp", "product=NAS", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			observation := Observation{
				Origin: "dns_sd", ObservedAt: now, ValidUntil: now.Add(time.Hour),
				Evidence: normalized.Event{Payload: map[string]any{"service_type": tc.service, "txt": tc.txt}},
			}
			if got := ClassifyIoT([]Observation{observation}, now); got.Category != tc.want {
				t.Fatalf("got %+v want %q", got, tc.want)
			}
		})
	}
}

func TestWSDiscoveryNamespacesAndRequestRejection(t *testing.T) {
	for _, body := range []string{
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:x="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"><s:Body><x:Hello><a:EndpointReference><a:Address>urn:uuid:camera-1</a:Address></a:EndpointReference><x:Types>dn:NetworkVideoTransmitter</x:Types><x:XAddrs>http://10.1.2.3/onvif/device_service</x:XAddrs></x:Hello></s:Body></s:Envelope>`,
		`<Envelope><Body><ProbeMatches><ProbeMatch><Types>dn:NetworkVideoTransmitter</Types></ProbeMatch></ProbeMatches></Body></Envelope>`,
	} {
		p, err := ParseWSDiscovery(body)
		if err != nil || p["is_response"] != true || p["types"] != "dn:NetworkVideoTransmitter" {
			t.Fatalf("bad parse %v %v", p, err)
		}
	}
	for _, body := range []string{`<Envelope><Body><Probe><Types>dn:NetworkVideoTransmitter</Types></Probe></Body></Envelope>`, `<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><Hello/>`, `<Hello>`} {
		if _, err := ParseWSDiscovery(body); err == nil {
			t.Fatalf("accepted invalid/query XML: %s", body)
		}
	}
	p, err := ParseWSDiscovery(`<Envelope><Body><Bye><EndpointReference><Address>urn:uuid:camera-1</Address></EndpointReference></Bye></Body></Envelope>`)
	if err != nil || p["withdrawn"] != true {
		t.Fatalf("withdrawal lost %v %v", p, err)
	}
}

func TestPrivateDiscoveryScope(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		want bool
	}{{"10.1.2.3", true}, {"172.31.2.3", true}, {"192.168.2.3", true}, {"169.254.1.2", true}, {"fd00::1", true}, {"fe80::1", true}, {"100.64.0.1", false}, {"222.204.3.184", false}, {"8.8.8.8", false}, {"ff02::fb", false}, {"127.0.0.1", false}} {
		if IsPrivateDiscoveryAddress(tc.ip) != tc.want {
			t.Fatalf("scope mismatch %s", tc.ip)
		}
	}
}
