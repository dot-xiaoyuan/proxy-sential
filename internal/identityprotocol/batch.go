// Package identityprotocol defines the durable identity inbox wire contract.
package identityprotocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const Version = 2

type Request struct {
	Source   string              `json:"source"`
	SensorID string              `json:"sensor_id"`
	Records  []map[string]string `json:"records"`
}

type Receipt struct {
	ProtocolVersion int    `json:"protocol_version"`
	BatchID         string `json:"batch_id"`
	ContentSHA256   string `json:"content_sha256"`
	RecordCount     int    `json:"record_count"`
	DurablyAccepted bool   `json:"durably_accepted"`
	AcceptedAt      string `json:"accepted_at"`
}

func (r Request) Hash() string {
	body, _ := json.Marshal(r)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
func (r Receipt) Verify(id, hash string, count int) error {
	if r.ProtocolVersion != Version || !r.DurablyAccepted || r.BatchID != id || r.ContentSHA256 != hash || r.RecordCount != count || r.AcceptedAt == "" {
		return fmt.Errorf("identity durable receipt does not match submitted batch")
	}
	if _, err := time.Parse(time.RFC3339Nano, r.AcceptedAt); err != nil {
		return fmt.Errorf("invalid durable acceptance timestamp")
	}
	return nil
}
