package discovery

import (
	"encoding/json"
	"fmt"
)

// Combine only batches already queued by capture. No timer delays durability;
// when disk falls behind, one fsync covers multiple queued capture windows.
// The combined file stays within AcceptDiscoveryBatch's event and byte limits.
func drainSpoolQueue(queue <-chan []byte, persist func([]byte) error) error {
	return drainSpoolQueueBounded(queue, persist, 2000, 8<<20)
}

func drainSpoolQueueBounded(queue <-chan []byte, persist func([]byte) error, maxEvents, maxBytes int) error {
	if maxEvents <= 0 || maxEvents > 2000 || maxBytes <= 0 || maxBytes > 8<<20 {
		return fmt.Errorf("invalid capture batch budget")
	}
	var held []byte
	closed := false
	for {
		raw := held
		held = nil
		if raw == nil {
			var ok bool
			raw, ok = <-queue
			if !ok {
				return nil
			}
		}
		var records []json.RawMessage
		if err := json.Unmarshal(raw, &records); err != nil {
			return fmt.Errorf("invalid capture batch: %w", err)
		}
		count := len(records)
		if count == 0 || count > maxEvents || len(raw) > maxBytes {
			return fmt.Errorf("capture batch exceeds durable budget")
		}
		combined := append([]byte(nil), raw...)
	gather:
		for count < maxEvents {
			select {
			case next, ok := <-queue:
				if !ok {
					closed = true
					break gather
				}
				var entries []json.RawMessage
				if err := json.Unmarshal(next, &entries); err != nil {
					return fmt.Errorf("invalid capture batch: %w", err)
				}
				if count+len(entries) > maxEvents || len(combined)+len(next)-1 > maxBytes {
					held = next
					break gather
				}
				// Capture emits compact nonempty JSON arrays. Preserve the exact event
				// documents instead of decoding numbers or re-normalizing their contents.
				if len(entries) == 0 {
					continue
				}
				combined[len(combined)-1] = ','
				combined = append(combined, next[1:]...)
				count += len(entries)
			default:
				break gather
			}
		}
		if err := persist(combined); err != nil {
			return err
		}
		if closed {
			return nil
		}
	}
}
