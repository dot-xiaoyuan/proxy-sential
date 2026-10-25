package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"proxy-sentinel/internal/normalized"
)

// InsertDiscoverySegments writes all segments in the same admission
// transaction as the work ledger. JSONB preserves the existing NUL envelope.
func InsertDiscoverySegments(ctx context.Context, tx *sql.Tx, batchID string, segments []DiscoverySegment) error {
	if len(segments) == 0 {
		return fmt.Errorf("empty discovery segments")
	}
	type row struct {
		Offset int             `json:"first_offset"`
		Count  int             `json:"event_count"`
		Bytes  int             `json:"byte_count"`
		Hash   string          `json:"content_sha256"`
		Events json.RawMessage `json:"events"`
	}
	rows := make([]row, 0, len(segments))
	expected := 0
	for _, segment := range segments {
		if segment.StartOffset != expected || segment.EventCount < 1 || segment.EventCount > DiscoverySegmentMaxEvents || len(segment.Events) > DiscoverySegmentMaxBytes {
			return fmt.Errorf("invalid discovery segment at offset %d", expected)
		}
		var decoded []normalized.Event
		if err := decodeDiscoveryBatch(segment.Events, &decoded); err != nil || len(decoded) != segment.EventCount {
			return fmt.Errorf("invalid discovery segment encoding at offset %d: %v", expected, err)
		}
		rows = append(rows, row{segment.StartOffset, segment.EventCount, len(segment.Events), contentHash(decoded), segment.Events})
		expected += segment.EventCount
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO discovery_batch_segments(batch_id,first_offset,event_count,byte_count,content_sha256,events)
 SELECT $1,s.first_offset,s.event_count,s.byte_count,s.content_sha256,s.events
 FROM jsonb_to_recordset($2::jsonb) AS s(first_offset integer,event_count integer,byte_count integer,content_sha256 text,events jsonb)`, batchID, raw)
	return err
}
