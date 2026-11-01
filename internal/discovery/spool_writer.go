package discovery

import (
	"encoding/json"
	"fmt"
	"time"
)

const captureFlushEvents = 250

// Combine batches already queued by capture. The stream variant may briefly
// wait for another capture window to reduce durable commits under load.
// Combined files stay within AcceptDiscoveryBatch's event and byte limits.
func drainSpoolQueue(queue <-chan []byte, persist func([]byte) error) error {
	return drainSpoolQueueBounded(queue, persist, 2000, 8<<20)
}

func drainSpoolQueueBounded(queue <-chan []byte, persist func([]byte) error, maxEvents, maxBytes int) error {
	return drainSpoolQueueBoundedWindow(queue, persist, maxEvents, maxBytes, 0)
}

func drainSpoolQueueBoundedWindow(queue <-chan []byte, persist func([]byte) error, maxEvents, maxBytes int, gatherWindow time.Duration) error {
	if maxEvents <= 0 || maxEvents > 2000 || maxBytes <= 0 || maxBytes > 8<<20 {
		return fmt.Errorf("invalid capture batch budget")
	}
	var held []byte
	closed := false
	for {
		raw := held
		held = nil
		backlogged := raw != nil
		if raw == nil {
			var ok bool
			select {
			case raw, ok = <-queue:
				backlogged = true
			default:
				raw, ok = <-queue
			}
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
		deadline := time.Now().Add(gatherWindow)
	gather:
		for count < maxEvents {
			var next []byte
			var ok bool
			select {
			case next, ok = <-queue:
			default:
				// Only a batch already waiting behind a durable commit gets a
				// short chance to include the next capture window. Keep room for it.
				if gatherWindow <= 0 || !backlogged || count < captureFlushEvents || count >= maxEvents/2 || len(combined) >= maxBytes/2 || time.Until(deadline) <= 0 {
					break gather
				}
				timer := time.NewTimer(time.Until(deadline))
				select {
				case next, ok = <-queue:
					timer.Stop()
				case <-timer.C:
					break gather
				}
			}
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
		}
		if err := persist(combined); err != nil {
			return err
		}
		if closed {
			return nil
		}
	}
}
