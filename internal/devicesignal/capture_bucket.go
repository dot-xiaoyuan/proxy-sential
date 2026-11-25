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
	authenticatedRouters map[handshakeKey]struct{}
	routerFrameReasons   map[handshakeKey]string
	helloReassembly      helloReassembly
	packets              map[packetBucketKey]int
	controls             map[string]controlSignal
	droppedPacketKeys    int
	// handshakes holds one summary per device for the current bucket. Only populated when
	// the handshake filter is attached.
	handshakes              map[handshakeKey]*handshakeSummary
	handshakeEnabled        bool
	handshakeCaptureV2      bool
	handshakeExcludedFrames int
	handshakeParseFailures  int
	handshakeFeatureSamples int
	handshakeCandidates     []handshakeCandidate
	handshakeCandidateBytes int
	controlParseFailures    int
	controlKeyDrops         int
	ieee1905                ieee1905CaptureStats
}

// At roughly 0.5-1 KiB per normalized JSON record, this hard ceiling keeps the
// collector's raw output comfortably below the five GiB/hour pilot budget even
// if an adversarial or asymmetric mirror produces maximal key diversity.
const maxPacketBucketKeys = 50000
const maxHandshakeFeatureSamples = 32768
const maxHandshakeCandidates = 131072
const maxHandshakeCandidateBytes = 24 << 20

type handshakeCandidate struct {
	summary *handshakeSummary
	feature handshakeFeatureObservation
}

// Frame counts describe the mirror input before output deduplication.
type ieee1905CaptureStats struct {
	Frames                int `json:"frames"`
	TopologyQueries       int `json:"topology_queries"`
	TopologyResponses     int `json:"topology_responses"`
	WithMemberSnapshot    int `json:"with_member_snapshot"`
	WithoutMemberSnapshot int `json:"without_member_snapshot"`
	FragmentedResponses   int `json:"fragmented_responses"`
	MalformedResponses    int `json:"malformed_responses"`
}

func (s *ieee1905CaptureStats) observe(frame ieee1905FrameObservation) {
	s.Frames++
	switch frame.messageType {
	case 0x0002:
		s.TopologyQueries++
	case 0x0003:
		s.TopologyResponses++
		switch {
		case frame.fragmented:
			s.FragmentedResponses++
		case !frame.complete:
			s.MalformedResponses++
		case frame.snapshot:
			s.WithMemberSnapshot++
		default:
			s.WithoutMemberSnapshot++
		}
	}
}

func newCaptureBucket() *captureBucket {
	return &captureBucket{packets: map[packetBucketKey]int{}, controls: map[string]controlSignal{}, handshakes: map[handshakeKey]*handshakeSummary{}}
}

func (b *captureBucket) addFrame(frame []byte, scope *normalized.CaptureScope) {
	if b.handshakeEnabled {
		if b.handshakeCaptureV2 {
			if syn, ok := parseFlowSYNFrame(frame); ok && !syn.Response && syn.SourceIP.Is4() {
				ethernet, valid := parseEthernetFrame(frame)
				if valid && ethernet.source != [6]byte{} && ethernet.source[0]&1 == 0 {
					b.recordHandshake(handshakeObservation{IP: syn.SourceIP, MAC: ethernet.source, ClientVLAN: ethernet.innerVLAN, ClientOuterVLAN: ethernet.outerVLAN, ObservedAt: time.Now().UTC(), DestinationPort: syn.DestinationPort})
				}
				return
			}
		}
		b.addHandshake(frame)
	}
	if value, ok := parsePacketFrame(frame); ok && value.TTL > 0 {
		value.Direction = scope.DirectionAddr(value.IP, value.DestinationIP)
		if value.Direction != "inbound" && value.Direction != "internal" && (value.Direction != "unknown" || value.IP.IsPrivate()) {
			key := packetBucketKey{IP: value.IP, MAC: value.MAC, Direction: value.Direction, TrafficScope: value.TrafficScope, Version: value.Version, TTL: value.TTL, TCP: value.TCP}
			if _, found := b.packets[key]; found || len(b.packets) < maxPacketBucketKeys {
				b.packets[key]++
			} else {
				b.droppedPacketKeys++
			}
		}
	}
	controls, ieee1905 := parseControlFramesWithCoverage(frame)
	if ieee1905.observed {
		b.ieee1905.observe(ieee1905)
		if !ieee1905.complete {
			b.controlParseFailures++
		}
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
	var observation handshakeObservation
	if b.handshakeCaptureV2 {
		var disposition handshakeFrameDisposition
		observation, disposition = classifyHandshakeFrame(frame)
		switch disposition {
		case handshakeExcluded:
			b.noteUnretainedRouter(handshakeKey{IP: observation.IP, MAC: observation.MAC}, routerNoUsableActivity)
			b.handshakeExcludedFrames++
			return
		case handshakeUnlocated:
			b.noteUnretainedRouter(handshakeKey{IP: observation.IP, MAC: observation.MAC}, routerParseIncomplete)
			b.handshakeParseFailures++
			return
		}
	} else {
		var ok bool
		observation, ok = parseHandshakeFrame(frame)
		if !ok {
			b.handshakeParseFailures++
			return
		}
	}
	b.recordHandshake(observation)
	if b.handshakeCaptureV2 && observation.Truncated && observation.DestinationPort == 443 {
		key := handshakeKey{IP: observation.IP, MAC: observation.MAC}
		if _, ok := b.authenticatedRouters[key]; ok && b.handshakes[key] != nil {
			b.helloReassembly.anchor(frame, observation)
		}
	}
}

func (b *captureBucket) recordHandshake(observation handshakeObservation) {
	key := handshakeKey{IP: observation.IP, MAC: observation.MAC}
	summary := b.handshakes[key]
	if summary == nil {
		if len(b.handshakes) >= maxPacketBucketKeys {
			b.noteUnretainedRouter(key, routerKeyLimit)
			b.droppedPacketKeys++
			return
		}
		summary = newHandshakeSummary()
		b.handshakes[key] = summary
	}
	if !b.handshakeCaptureV2 {
		before := len(summary.samples)
		summary.add(observation, maxHandshakeFeatureSamples-b.handshakeFeatureSamples)
		b.handshakeFeatureSamples += len(summary.samples) - before
		return
	}

	summary.addMetadata(observation)
	feature, ok := observation.feature()
	if !ok {
		return
	}
	// Keep only parsed feature fields until the bucket's output devices are
	// known. A dropped candidate may contain multiple fingerprint families.
	size := len(feature.eventID) + len(feature.userAgent) + len(feature.ja3) + len(feature.ja4)
	if len(b.handshakeCandidates) >= maxHandshakeCandidates || b.handshakeCandidateBytes+size > maxHandshakeCandidateBytes {
		summary.overflow++
		return
	}
	b.handshakeCandidates = append(b.handshakeCandidates, handshakeCandidate{summary: summary, feature: feature})
	b.handshakeCandidateBytes += size
	summary.featureQueued = true
}

func (b *captureBucket) selectHandshakes(limit int, bucket time.Time, priorityCIDRs []netip.Prefix) []handshakeKey {
	keys := b.selectHandshakeOutlets(limit, bucket, priorityCIDRs)
	if len(b.handshakeCandidates) == 0 && b.helloReassembly.stats.Started == 0 && len(b.helloReassembly.anchors) == 0 {
		return keys
	}
	selected := make(map[*handshakeSummary]bool, len(keys))
	for _, key := range keys {
		selected[b.handshakes[key]] = true
	}
	budget := maxHandshakeFeatureSamples
	for _, candidate := range b.handshakeCandidates {
		if selected[candidate.summary] {
			budget -= candidate.summary.addFeature(candidate.feature, budget)
		}
	}
	b.helloReassembly.apply(selected, b.handshakes, budget)
	return keys
}

// Reserve slots in an oversubscribed bucket for observed activity
// at authenticated router outlets. Other devices keep their existing weighted
// and rotating slots. An address or MAC on its own never receives priority.
func (b *captureBucket) selectHandshakeOutlets(limit int, at time.Time, cidrs []netip.Prefix) []handshakeKey {
	if limit <= 0 || len(b.handshakes) <= limit || len(b.authenticatedRouters) == 0 {
		return selectHandshakeKeys(b.handshakes, limit, at, cidrs)
	}
	var routers []handshakeKey
	for key := range b.authenticatedRouters {
		if summary := b.handshakes[key]; summary != nil && summary.activity != nil {
			routers = append(routers, key)
		}
	}
	if len(routers) == 0 {
		return selectHandshakeKeys(b.handshakes, limit, at, cidrs)
	}
	selected := selectHandshakePool(routers, b.handshakes, limit, at)
	if len(selected) == limit {
		return selected
	}
	remaining := make(map[handshakeKey]*handshakeSummary, len(b.handshakes))
	for key, summary := range b.handshakes {
		remaining[key] = summary
	}
	for _, key := range selected {
		delete(remaining, key)
	}
	return append(selected, selectHandshakeKeys(remaining, limit-len(selected), at, cidrs)...)
}

func (b *captureBucket) resetHandshakes() {
	b.helloReassembly = helloReassembly{}
	clear(b.routerFrameReasons)
	b.handshakes = make(map[handshakeKey]*handshakeSummary)
	b.handshakeParseFailures = 0
	b.handshakeExcludedFrames = 0
	b.handshakeFeatureSamples = 0
	clear(b.handshakeCandidates)
	b.handshakeCandidates = b.handshakeCandidates[:0]
	b.handshakeCandidateBytes = 0
}
