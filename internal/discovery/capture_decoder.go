package discovery

func newCaptureFrameDecoder(recordEvidenceV2 bool) *FrameDecoder {
	// Publish a reader-compatible binary before changing the durable producer
	// shape. Replay decoders remain able to read either evidence format.
	return &FrameDecoder{DNS: DNSCache{legacyEvidence: !recordEvidenceV2}}
}
