package discovery

import (
	"fmt"

	"proxy-sentinel/internal/normalized"
)

const DiscoverySegmentMaxEvents = 50
const DiscoveryPublishMaxEvents = 10
const DiscoverySegmentMaxBytes = 1 << 20
const DiscoveryEventMaxBytes = DiscoverySegmentMaxBytes - 2

type DiscoverySegment struct {
	StartOffset int
	EventCount  int
	Events      []byte
}

func DiscoveryBatchHash(events []normalized.Event) string { return contentHash(events) }

// EncodeDiscoverySegments bounds the payload returned by a claim. The source
// batch hash remains the admission identity; segment ordinals never change.
func EncodeDiscoverySegments(events []normalized.Event) ([]DiscoverySegment, error) {
	segments := make([]DiscoverySegment, 0, (len(events)+DiscoveryPublishMaxEvents-1)/DiscoveryPublishMaxEvents)
	start := 0
	for start < len(events) {
		end := start
		for end < len(events) && end-start < DiscoveryPublishMaxEvents {
			candidate, err := EncodeDiscoveryBatch(events[start : end+1])
			if err != nil {
				return nil, err
			}
			if len(candidate) > DiscoverySegmentMaxBytes {
				break
			}
			end++
		}
		if end == start {
			return nil, fmt.Errorf("discovery event exceeds segment byte budget at offset %d", start)
		}
		raw, err := EncodeDiscoveryBatch(events[start:end])
		if err != nil {
			return nil, err
		}
		segments = append(segments, DiscoverySegment{StartOffset: start, EventCount: end - start, Events: raw})
		start = end
	}
	return segments, nil
}
