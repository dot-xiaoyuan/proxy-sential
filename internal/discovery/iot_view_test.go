package discovery

import "testing"

func TestIoTViewRequiresUnwithdrawnServiceEvidence(t *testing.T) {
	printer := Observation{Origin: "dns_sd", Confidence: "strong", Capabilities: []string{"printing"}}
	media := Observation{Origin: "ssdp", Confidence: "strong", Capabilities: []string{"media_rendering"}}
	phone := Observation{Origin: "dhcp", Confidence: "confirmed", DeviceType: "mobile"}
	for _, test := range []struct {
		name string
		rows []Observation
		want string
	}{
		{"printer service", []Observation{printer}, "printer"},
		{"media service", []Observation{media}, "media"},
		{"dhcp phone", []Observation{phone}, ""},
		{"dhcp hostname type", []Observation{{Origin: "dhcp", Confidence: "confirmed", DeviceType: "printer", Capabilities: []string{"printing"}}}, ""},
		{"withdrawn printer", []Observation{{Origin: "dns_sd", Confidence: "strong", Capabilities: []string{"printing"}, Withdrawn: true}}, ""},
		{"weak service", []Observation{{Origin: "dns_sd", Confidence: "clue", Capabilities: []string{"printing"}}}, ""},
		{"self reported service with mac", []Observation{{Origin: "dns_sd", Confidence: "clue", MAC: "00:11:22:33:44:55", Capabilities: []string{"casting"}}}, "media"},
		{"router announcement", []Observation{{Origin: "ssdp", Confidence: "strong", Capabilities: []string{"routing"}}}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := iotServiceCategory(DeviceView{Observations: test.rows}); got != test.want {
				t.Fatalf("iotServiceCategory=%q, want %v", got, test.want)
			}
		})
	}
}
