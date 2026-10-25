package discovery

import "proxy-sentinel/internal/normalized"

// ReceiptMatchesEvent supports receipts written by the former product classifier,
// which mutated the payload before hashing. A legacy hash is trusted only when
// the original durable batch also proves the exact unmodified event content.
func ReceiptMatchesEvent(e normalized.Event, storedHash string, originalBatch []byte) bool {
	rawHash := contentHash(e)
	if storedHash == rawHash {
		return true
	}
	if e.Type != "discovery" || str(e.Payload, "origin") == "" || len(originalBatch) == 0 {
		return false
	}
	var originals []normalized.Event
	if decodeDiscoveryBatch(originalBatch, &originals) != nil {
		return false
	}
	for _, original := range originals {
		if original.EventID != e.EventID || contentHash(original) != rawHash {
			continue
		}
		o, err := FromEvent(original)
		return err == nil && storedHash == contentHash(o.Evidence)
	}
	return false
}
