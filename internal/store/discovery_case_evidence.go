package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
)

type DiscoveryCaseEvidenceRef struct {
	SensorID string `json:"sensor_id"`
	SourceID string `json:"source_id"`
	EventID  string `json:"event_id"`
	Revision int64  `json:"revision"`
}

type DiscoveryCaseEvidence struct {
	Document    json.RawMessage
	ContentHash string
}

// ReadDiscoveryCaseEvidence retrieves only originals with a verified segment
// archive. Legacy work without an archive locator stays on the database
// trigger's original-batch path.
func (s *DBStore) ReadDiscoveryCaseEvidence(ctx context.Context, refs []DiscoveryCaseEvidenceRef) (map[DiscoveryCaseEvidenceRef]DiscoveryCaseEvidence, error) {
	out := make(map[DiscoveryCaseEvidenceRef]DiscoveryCaseEvidence, len(refs))
	if len(refs) == 0 {
		return out, nil
	}
	if len(refs) > 100 || s.pg == nil || s.ch == nil {
		return nil, fmt.Errorf("discovery evidence reader unavailable or request too large")
	}
	raw, err := json.Marshal(refs)
	if err != nil {
		return nil, err
	}
	rows, err := s.pg.db.QueryContext(ctx, `SELECT r.sensor_id,r.source_id,r.event_id,r.revision,r.content_hash,r.archive_batch_id,r.archive_ordinal,r.accepted_at
 FROM discovery_event_receipts r JOIN jsonb_to_recordset($1::jsonb) v(sensor_id text,source_id text,event_id text,revision bigint)
 USING(sensor_id,source_id,event_id,revision)
 WHERE r.archive_batch_id IS NOT NULL AND r.archive_ordinal IS NOT NULL
 AND EXISTS(SELECT 1 FROM discovery_batch_segments s WHERE s.batch_id=r.batch_id
  AND r.event_ordinal>=s.first_offset AND r.event_ordinal<s.first_offset+s.event_count
  AND s.archive_verified_at IS NOT NULL)`, raw)
	if err != nil {
		return nil, err
	}
	type location struct {
		Ref      DiscoveryCaseEvidenceRef
		Hash     string
		Batch    string
		Ordinal  int
		Accepted time.Time
	}
	locations := make(map[string]location, len(refs))
	minAt, maxAt := time.Time{}, time.Time{}
	for rows.Next() {
		var item location
		if err = rows.Scan(&item.Ref.SensorID, &item.Ref.SourceID, &item.Ref.EventID, &item.Ref.Revision, &item.Hash, &item.Batch, &item.Ordinal, &item.Accepted); err != nil {
			break
		}
		key := fmt.Sprintf("%s/%d", item.Batch, item.Ordinal)
		locations[key] = item
		if minAt.IsZero() || item.Accepted.Before(minAt) {
			minAt = item.Accepted
		}
		if maxAt.IsZero() || item.Accepted.After(maxAt) {
			maxAt = item.Accepted
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil || len(locations) == 0 {
		return out, err
	}
	targets := make([]string, 0, len(locations))
	for _, item := range locations {
		targets = append(targets, "("+chQuote(item.Batch)+","+fmt.Sprint(item.Ordinal)+")")
	}
	query := `SELECT batch_id,ordinal,content_hash,document FROM discovery_evidence_archive WHERE (batch_id,ordinal) IN (` + strings.Join(targets, ",") + `)
 AND accepted_at>=parseDateTime64BestEffort(` + chQuote(minAt.Add(-time.Second).UTC().Format(time.RFC3339Nano)) + `,6)
 AND accepted_at<=parseDateTime64BestEffort(` + chQuote(maxAt.Add(time.Second).UTC().Format(time.RFC3339Nano)) + `,6)
 SETTINGS max_threads=1,max_memory_usage=134217728,max_execution_time=5 FORMAT JSONEachRow`
	data, err := s.ch.query(ctx, query)
	if err != nil {
		return nil, err
	}
	var archives []struct {
		Batch    string `json:"batch_id"`
		Ordinal  int    `json:"ordinal"`
		Hash     string `json:"content_hash"`
		Document string `json:"document"`
	}
	if err = decodeJSONEachRow(data, &archives); err != nil {
		return nil, err
	}
	for _, archive := range archives {
		item, ok := locations[fmt.Sprintf("%s/%d", archive.Batch, archive.Ordinal)]
		if !ok || archive.Hash != item.Hash {
			return nil, fmt.Errorf("discovery archive content conflict")
		}
		var event normalized.Event
		if err = json.Unmarshal([]byte(archive.Document), &event); err != nil {
			return nil, err
		}
		if discoveryRawHash(event) != item.Hash || event.EventID != item.Ref.EventID || discoveryRevision(event) != item.Ref.Revision || stringFromMap(event.Observer, "sensor_id") != item.Ref.SensorID || discoverySource(event) != item.Ref.SourceID {
			return nil, fmt.Errorf("discovery archive identity conflict")
		}
		document := json.RawMessage(archive.Document)
		if strings.Contains(archive.Document, `\u0000`) {
			encoded, encodeErr := json.Marshal(map[string]string{"encoding": "base64-json-v1", "data": base64.StdEncoding.EncodeToString([]byte(archive.Document))})
			if encodeErr != nil {
				return nil, encodeErr
			}
			document = encoded
		}
		if prior, exists := out[item.Ref]; exists && prior.ContentHash != item.Hash {
			return nil, fmt.Errorf("discovery archive duplicate conflict")
		}
		out[item.Ref] = DiscoveryCaseEvidence{Document: document, ContentHash: item.Hash}
	}
	if len(out) != len(locations) {
		return nil, fmt.Errorf("discovery archive incomplete")
	}
	return out, nil
}
