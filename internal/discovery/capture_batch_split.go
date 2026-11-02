package discovery

import (
	"encoding/json"
	"fmt"
)

// Split only exceptional oversized stream windows. Preserve the coalesced
// event documents and their order while keeping each journal batch bounded.
func splitCaptureBatch(raw []byte, maxBytes int) ([][]byte, error) {
	var events []json.RawMessage
	if err := json.Unmarshal(raw, &events); err != nil {
		return nil, err
	}
	batches := make([][]byte, 0, 2)
	batch := []byte{'['}
	for _, event := range events {
		if len(event)+2 > maxBytes {
			return nil, fmt.Errorf("capture event exceeds durable byte budget")
		}
		separator := 0
		if len(batch) > 1 {
			separator = 1
		}
		if len(batch)+separator+len(event)+1 > maxBytes {
			batches = append(batches, append(batch, ']'))
			batch = []byte{'['}
			separator = 0
		}
		if separator != 0 {
			batch = append(batch, ',')
		}
		batch = append(batch, event...)
	}
	return append(batches, append(batch, ']')), nil
}
