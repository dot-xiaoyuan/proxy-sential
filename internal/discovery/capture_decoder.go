package discovery

import "net/netip"

func newCaptureFrameDecoder(recordEvidenceV2 bool, allow ...netip.Prefix) *FrameDecoder {
	// Publish a reader-compatible binary before changing the durable producer
	// shape. Replay decoders remain able to read either evidence format.
	return &FrameDecoder{DNS: DNSCache{legacyEvidence: !recordEvidenceV2, allowedAddresses: append([]netip.Prefix(nil), allow...)}}
}
