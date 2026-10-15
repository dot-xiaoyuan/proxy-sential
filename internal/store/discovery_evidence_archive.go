package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"proxy-sentinel/internal/normalized"
	"time"
)

// WriteDiscoveryEvidenceArchive verifies ordinal/hash completeness explicitly;
// it never depends on eventual MergeTree replacement for idempotency.
func (s *ClickHouseStore) WriteDiscoveryEvidenceArchive(ctx context.Context, batch string, accepted time.Time, events []normalized.Event) error {
	if len(events) > 20000 {
		return fmt.Errorf("archive batch budget exceeded")
	}
	hashes := make([]string, len(events))
	docs := make([][]byte, len(events))
	for i, e := range events {
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		docs[i] = b
		sum := sha256.Sum256(b)
		hashes[i] = hex.EncodeToString(sum[:])
	}
	read := func() (map[int]string, error) {
		raw, err := s.query(ctx, `SELECT ordinal,content_hash FROM discovery_evidence_archive WHERE batch_id=`+chQuote(batch)+` GROUP BY ordinal,content_hash LIMIT 20001 SETTINGS max_threads=1,max_execution_time=2 FORMAT JSONEachRow`)
		if err != nil {
			return nil, err
		}
		var rows []struct {
			Ordinal int    `json:"ordinal"`
			Hash    string `json:"content_hash"`
		}
		if err = decodeJSONEachRow(raw, &rows); err != nil {
			return nil, err
		}
		found := map[int]string{}
		for _, row := range rows {
			if row.Ordinal < 0 || row.Ordinal >= len(events) || row.Hash != hashes[row.Ordinal] {
				return nil, fmt.Errorf("archive batch content conflict")
			}
			found[row.Ordinal] = row.Hash
		}
		return found, nil
	}
	found, err := read()
	if err != nil {
		return err
	}
	if len(found) == len(events) {
		return nil
	}
	var buffer bytes.Buffer
	buffer.WriteString("INSERT INTO discovery_evidence_archive FORMAT JSONEachRow\n")
	encoder := json.NewEncoder(&buffer)
	for i, e := range events {
		if _, ok := found[i]; ok {
			continue
		}
		observed, err := time.Parse(time.RFC3339Nano, e.Timestamp)
		if err != nil {
			return err
		}
		row := map[string]any{"batch_id": batch, "ordinal": i, "event_id": e.EventID, "accepted_at": accepted.UTC().Format("2006-01-02 15:04:05.000000"), "observed_at": observed.UTC().Format("2006-01-02 15:04:05.000000"), "sensor_id": stringFromMap(e.Observer, "sensor_id"), "protocol": e.SourceEventType, "content_hash": hashes[i], "document": string(docs[i])}
		if err = encoder.Encode(row); err != nil {
			return err
		}
	}
	if err = s.exec(ctx, buffer.String()); err != nil {
		return err
	}
	found, err = read()
	if err != nil {
		return err
	}
	if len(found) != len(events) {
		return fmt.Errorf("discovery archive incomplete")
	}
	return nil
}
