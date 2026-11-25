package devicesignal

import (
	"net/netip"
	"os"
	"time"

	"proxy-sentinel/internal/normalized"
)

// captureBucket groups replayable frame observations without deriving device
// ownership from transit traffic. Control and IP packet eligibility are separate.
type captureBucket struct {
	behaviorTCPWindow bool
	discoveryNetworks []netip.Prefix
	discoverySYNKeys  int
	packets           map[packetBucketKey]int
	controls          map[string]controlSignal
	droppedPacketKeys int
	// handshakes holds one summary per device for the current bucket. Only populated when
	// the handshake filter is attached.
	handshakes              map[handshakeKey]*handshakeSummary
	handshakeEnabled        bool
	handshakeParseFailures  int
	handshakeFeatureSamples int
	controlParseFailures    int
	controlKeyDrops         int
	sadpFragments           map[sadpFragmentKey]*sadpAssembly
	lastSADPFragmentSweep   time.Time
}

// At roughly 0.5-1 KiB per normalized JSON record, this hard ceiling keeps the
// collector's raw output comfortably below the five GiB/hour pilot budget even
// if an adversarial or asymmetric mirror produces maximal key diversity.
const maxPacketBucketKeys = 50000
const maxHandshakeFeatureSamples = 32768

func newCaptureBucket() *captureBucket {
	return &captureBucket{behaviorTCPWindow: os.Getenv("PROXY_SENTINEL_PASSIVE_BEHAVIOR_WRITE") == "true", packets: map[packetBucketKey]int{}, controls: map[string]controlSignal{}, handshakes: map[handshakeKey]*handshakeSummary{}}
}

func (b *captureBucket) addFrame(frame []byte, scope *normalized.CaptureScope) {
	if b.handshakeEnabled {
		b.addHandshake(frame)
	}
	if value, ok := parsePacketFrame(frame); ok && value.TTL > 0 {
		if len(b.discoveryNetworks) > 0 && value.directTCP {
			// This collector receives a bounded slice of an initial SYN. Save
			// only the sender's stack and VLAN, never the forwarding MAC.
			if !value.TCP.present() {
				return
			}
			if !flowSourceAllowed(value.IP, b.discoveryNetworks) {
				return
			}
			direction := "outbound"
			if flowSourceAllowed(value.DestinationIP, b.discoveryNetworks) {
				direction = "internal"
			}
			eth, ok := parseEthernetFrame(frame)
			if !ok {
				return
			}
			key := packetBucketKey{IP: value.IP, Version: value.Version, TTL: value.TTL, Direction: direction, VLAN: eth.vlanScope, TCP: value.TCP, DiscoverySYN: true}
			if _, found := b.packets[key]; !found {
				// Reserve capacity for ARP, DHCP and the original control signals.
				if b.discoverySYNKeys >= 2048 || len(b.packets) >= maxPacketBucketKeys {
					b.droppedPacketKeys++
					return
				}
				b.discoverySYNKeys++
			}
			b.packets[key]++
			return
		}
		var vlan string
		if b.behaviorTCPWindow && value.TCP.Window > 0 {
			if ethernet, ok := parseEthernetFrame(frame); ok {
				vlan = ethernet.vlanScope
			} else {
				value.TCP.Window = 0
			}
		} else {
			value.TCP.Window = 0
		}
		value.Direction = scope.DirectionAddr(value.IP, value.DestinationIP)
		if value.Direction != "inbound" && value.Direction != "internal" && (value.Direction != "unknown" || value.IP.IsPrivate()) {
			key := packetBucketKey{IP: value.IP, MAC: value.MAC, Direction: value.Direction, TrafficScope: value.TrafficScope, Version: value.Version, TTL: value.TTL, TCP: value.TCP, VLAN: vlan}
			if _, found := b.packets[key]; found || len(b.packets) < maxPacketBucketKeys {
				b.packets[key]++
			} else {
				b.droppedPacketKeys++
			}
		}
	}
	controls, fragmented := b.acceptSADPFragment(frame)
	if !fragmented {
		controls = parseControlFrames(frame)
	}
	if eth, ok := parseEthernetFrame(frame); ok && eth.etherType == 0x893a && len(controls) == 0 {
		b.controlParseFailures++
	}
	for _, signal := range controls {
		// ARP only serves dumb-terminal discovery and the device-center address history; router
		// and shared-access detection never read it. It was ~73% of all events on 184 and
		// crowded the risk window sample, so it is emitted only when explicitly enabled.
		if signal.Kind == "arp" && !arpSignalsEnabled() {
			continue
		}
		// The control parser can supply an explicit protocol or management IP.
		// A packet forwarded under this MAC does not establish its source device IP.
		key := signal.key()
		if _, found := b.controls[key]; !found && len(b.controls) >= maxPacketBucketKeys {
			b.controlKeyDrops++
			continue
		}
		if signal.Kind == "ieee1905_client_snapshot" || signal.Kind == "ieee1905_client_association" {
			signal.ObservedAt = time.Now().UTC()
		}
		b.controls[key] = signal
	}
}

// arpSignalsEnabled reports whether ARP control signals are exported. Default off.
func arpSignalsEnabled() bool {
	return os.Getenv("PROXY_SENTINEL_DEVICE_SIGNAL_ARP") == "true"
}

// addHandshake folds one client handshake packet into its device's summary. A new device is
// dropped once the bucket reaches the key limit, the same bound the packet buckets use.
func (b *captureBucket) addHandshake(frame []byte) {
	observation, ok := parseHandshakeFrame(frame)
	if !ok {
		b.handshakeParseFailures++
		return
	}
	key := handshakeKey{IP: observation.IP, MAC: observation.MAC}
	summary := b.handshakes[key]
	if summary == nil {
		if len(b.handshakes) >= maxPacketBucketKeys {
			b.droppedPacketKeys++
			return
		}
		summary = &handshakeSummary{snis: map[string]bool{}, alpns: map[string]bool{}, hosts: map[string]bool{}, userAgents: map[string]bool{}}
		b.handshakes[key] = summary
	}
	before := len(summary.samples)
	if b.handshakeFeatureSamples >= maxHandshakeFeatureSamples-3 {
		observation.FeaturesOmitted = true
	}
	summary.add(observation)
	b.handshakeFeatureSamples += len(summary.samples) - before
}
