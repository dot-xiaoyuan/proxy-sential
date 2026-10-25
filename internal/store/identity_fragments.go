package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"proxy-sentinel/internal/normalized"
)

const (
	identityInboxFragmentMaxEvents = 50
	identityInboxFragmentMaxBytes  = 240 << 10
)

type identityInboxFragment struct {
	FirstOrdinal int
	Count        int
	JSON         []byte
	SHA256       string
}

// The identity HTTP batch is a transport envelope, not a PostgreSQL work unit.
// Keep each durable payload row bounded even when a client sends 10,000 records.
func splitIdentityInboxFragments(events []normalized.Event) ([]identityInboxFragment, error) {
	if len(events) == 0 {
		return nil, ErrInvalidIdentityBatch
	}
	fragments := make([]identityInboxFragment, 0, (len(events)+identityInboxFragmentMaxEvents-1)/identityInboxFragmentMaxEvents)
	var body bytes.Buffer
	first, count := 0, 0
	flush := func() {
		body.WriteByte(']')
		raw := bytes.Clone(body.Bytes())
		sum := sha256.Sum256(raw)
		fragments = append(fragments, identityInboxFragment{FirstOrdinal: first, Count: count, JSON: raw, SHA256: hex.EncodeToString(sum[:])})
		first += count
		count = 0
		body.Reset()
	}
	for _, event := range events {
		item, err := json.Marshal(event)
		if err != nil {
			return nil, err
		}
		if len(item)+2 > identityInboxFragmentMaxBytes {
			return nil, fmt.Errorf("identity event exceeds fragment byte limit: %w", ErrInvalidIdentityBatch)
		}
		if count > 0 && (count >= identityInboxFragmentMaxEvents || body.Len()+len(item)+2 > identityInboxFragmentMaxBytes) {
			flush()
		}
		if count == 0 {
			body.WriteByte('[')
		} else {
			body.WriteByte(',')
		}
		body.Write(item)
		count++
	}
	if count > 0 {
		flush()
	}
	return fragments, nil
}
