package devicesignal

import "proxy-sentinel/internal/normalized"

// captureBucket groups replayable frame observations without deriving device
// ownership from transit traffic. Control and IP packet eligibility are separate.
type captureBucket struct {
	packets           map[packetBucketKey]int
	controls          map[string]controlSignal
	droppedPacketKeys int
}

// At roughly 0.5-1 KiB per normalized JSON record, this hard ceiling keeps the
// collector's raw output comfortably below the five GiB/hour pilot budget even
// if an adversarial or asymmetric mirror produces maximal key diversity.
const maxPacketBucketKeys = 50000

func newCaptureBucket() *captureBucket {
	return &captureBucket{packets: map[packetBucketKey]int{}, controls: map[string]controlSignal{}}
}

func (b *captureBucket) addFrame(frame []byte, scope *normalized.CaptureScope) {
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
	for _, signal := range parseControlFrames(frame) {
		// The control parser can supply an explicit protocol or management IP.
		// A packet forwarded under this MAC does not establish its source device IP.
		b.controls[signal.key()] = signal
	}
}
