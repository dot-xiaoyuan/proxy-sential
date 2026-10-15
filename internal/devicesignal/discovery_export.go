package devicesignal

// DiscoveryControl exposes credential-free protocol facts to the dedicated
// discovery collector without depending on risk scoring or storage.
type DiscoveryControl struct {
	Kind, IP, MAC string
	VLAN          int
	Payload       map[string]any
}

func DecodeDiscoveryControls(frame []byte) []DiscoveryControl {
	out := []DiscoveryControl{}
	for _, s := range parseControlFrames(frame) {
		switch s.Kind {
		case "arp", "ndp", "lldp", "cdp", "ieee1905_client_association":
			out = append(out, DiscoveryControl{s.Kind, s.IP, s.MAC, s.VLAN, s.Payload})
		}
	}
	return out
}
