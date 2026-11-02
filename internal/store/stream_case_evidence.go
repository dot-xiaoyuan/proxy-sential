package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"proxy-sentinel/internal/streamlog"
)

type StreamCaseEvidence struct {
	Document    json.RawMessage
	ContentHash string
}

// ReadStreamCaseEvidence accepts only a receipt whose unique body is already
// archived. The caller inserts these verified bytes into the case transaction
// before its snapshot references them.
func (s *DBStore) ReadStreamCaseEvidence(ctx context.Context, refs []StreamBodyRef) (map[StreamBodyRef]StreamCaseEvidence, error) {
	out := make(map[StreamBodyRef]StreamCaseEvidence, len(refs))
	if len(refs) == 0 {
		return out, nil
	}
	if len(refs) > 100 || s.pg == nil || s.ch == nil {
		return nil, errors.New("stream case evidence reader unavailable or request too large")
	}
	for _, ref := range refs {
		if ref.Epoch == "" || ref.Class != "evidence" || ref.Validate() != nil {
			return nil, errors.New("case evidence needs a complete retained stream reference")
		}
	}
	raw, err := json.Marshal(refs)
	if err != nil {
		return nil, err
	}
	rows, err := s.pg.db.QueryContext(ctx, `SELECT v.epoch,v.scope,v.key,v.sha256,r.body_ref
 FROM jsonb_to_recordset($1::jsonb) AS v(epoch text,scope text,key text,sha256 text)
	LEFT JOIN stream_discovery_event_keys k ON k.epoch=v.epoch AND k.scope_id=v.scope AND k.event_key=v.key
	LEFT JOIN stream_discovery_event_keys_compact kc
	 ON kc.key_hash=sentinel_stream_discovery_key_hash(v.epoch,v.scope,v.key)
	 AND kc.epoch=v.epoch AND kc.scope_id=v.scope AND kc.event_key=v.key
	JOIN stream_discovery_receipts r ON r.accepted_month=coalesce(kc.accepted_month,k.accepted_month)
	 AND r.epoch=v.epoch AND r.scope_id=v.scope AND r.event_key=v.key
	LEFT JOIN stream_projection_segments s ON s.segment_id=r.archive_segment_id
	 AND s.epoch=r.epoch AND s.archive_receipt_mode='segment'
	WHERE (r.archive_state='verified'
	 OR (r.archive_state<>'failed' AND
	  ((r.archive_segment_id IS NULL AND r.archive_state='confirmed')
	   OR (r.archive_segment_id IS NOT NULL AND s.lanes_finalized_at IS NOT NULL))))
	 AND (k.event_key IS NOT NULL OR kc.event_key IS NOT NULL)
	 AND (k.event_key IS NULL OR k.content_sha256=v.sha256)
	 AND (kc.event_key IS NULL OR kc.content_sha256=v.sha256)
	 AND (k.event_key IS NULL OR kc.event_key IS NULL OR k.accepted_month=kc.accepted_month)`, raw)
	if err != nil {
		return nil, err
	}
	confirmed := make(map[StreamBodyRef]struct{}, len(refs))
	for rows.Next() {
		var epoch, scope, key, hash string
		var rawRef []byte
		if err = rows.Scan(&epoch, &scope, &key, &hash, &rawRef); err != nil {
			break
		}
		var ref StreamBodyRef
		if err = json.Unmarshal(rawRef, &ref); err != nil {
			break
		}
		if ref.Epoch != epoch || ref.Scope != scope || ref.Key != key || ref.SHA256 != hash || ref.Class != "evidence" {
			err = streamlog.ErrContentConflict
			break
		}
		confirmed[ref] = struct{}{}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, err
	}
	manifestRefs := make([]StreamBodyRef, 0)
	for _, ref := range refs {
		if _, ok := confirmed[ref]; !ok && strings.HasPrefix(ref.Key, ref.Epoch+":stream2-") {
			manifestRefs = append(manifestRefs, ref)
		}
	}
	if len(manifestRefs) != 0 {
		manifestInput, err := json.Marshal(manifestRefs)
		if err != nil {
			return nil, err
		}
		manifestRows, err := s.pg.db.QueryContext(ctx, `SELECT v.epoch,v.scope,v.key,v.sha256,kc.content_sha256,to_char(kc.accepted_month,'YYYYMM'),
 kc.receipt_segment_id,kc.receipt_ordinal,sm.epoch,sm.source_kind,sm.archive_receipt_mode,
 sm.event_count,sm.lanes_finalized_at,sm.source_file_id,sm.source_start_offset,sm.source_end_offset,
 m.archive_month,m.body_layout,m.results
 FROM jsonb_to_recordset($1::jsonb) AS v(epoch text,scope text,key text,sha256 text)
 JOIN stream_discovery_event_keys_compact kc
  ON kc.key_hash=sentinel_stream_discovery_key_hash(v.epoch,v.scope,v.key)
  AND kc.epoch=v.epoch AND kc.scope_id=v.scope AND kc.event_key=v.key
 LEFT JOIN stream_discovery_receipts r ON r.accepted_month=kc.accepted_month
  AND r.epoch=v.epoch AND r.scope_id=v.scope AND r.event_key=v.key
 LEFT JOIN stream_projection_segments sm ON sm.segment_id=kc.receipt_segment_id
 LEFT JOIN stream_discovery_segment_receipt_manifests m ON m.segment_id=sm.segment_id
 WHERE r.event_key IS NULL`, manifestInput)
		if err != nil {
			return nil, err
		}
		for manifestRows.Next() {
			var epoch, scope, key, hash, savedHash, acceptedMonth string
			var locator, markerEpoch, source, mode, fileID, month, bodyLayout sql.NullString
			var ordinal, eventCount, sourceStart, sourceEnd sql.NullInt64
			var finalized sql.NullTime
			var results []byte
			if err = manifestRows.Scan(&epoch, &scope, &key, &hash, &savedHash, &acceptedMonth,
				&locator, &ordinal, &markerEpoch, &source, &mode,
				&eventCount, &finalized, &fileID, &sourceStart, &sourceEnd,
				&month, &bodyLayout, &results); err != nil {
				break
			}
			var requested StreamBodyRef
			for _, ref := range manifestRefs {
				if ref.Epoch == epoch && ref.Scope == scope && ref.Key == key && ref.SHA256 == hash {
					requested = ref
					break
				}
			}
			if requested.Key == "" || savedHash != hash {
				err = streamlog.ErrContentConflict
				break
			}
			if !locator.Valid || locator.String == "" || !ordinal.Valid || !mode.Valid || mode.String != "manifest" {
				err = streamlog.ErrUnconfirmed
				break
			}
			if !markerEpoch.Valid || markerEpoch.String != epoch || !source.Valid || source.String != "passive-discovery" ||
				!eventCount.Valid || !fileID.Valid || fileID.String == "" || !sourceStart.Valid || !sourceEnd.Valid || sourceEnd.Int64 <= sourceStart.Int64 ||
				!month.Valid || !bodyLayout.Valid || month.String != acceptedMonth || month.String != requested.Month || bodyLayout.String != requested.BodyLayout {
				err = streamlog.ErrContentConflict
				break
			}
			var values []*string
			if json.Unmarshal(results, &values) != nil || len(values) != int(eventCount.Int64) ||
				ordinal.Int64 < 0 || ordinal.Int64 >= int64(len(values)) || values[ordinal.Int64] == nil || *values[ordinal.Int64] == "" {
				err = streamlog.ErrContentConflict
				break
			}
			if !finalized.Valid {
				err = streamlog.ErrUnconfirmed
				break
			}
			confirmed[requested] = struct{}{}
		}
		if err == nil {
			err = manifestRows.Err()
		}
		manifestRows.Close()
		if err != nil {
			return nil, err
		}
	}
	for _, ref := range refs {
		if _, ok := confirmed[ref]; !ok {
			return nil, fmt.Errorf("stream case evidence is not archived: %w", streamlog.ErrUnconfirmed)
		}
	}
	return s.readStreamCaseBodies(ctx, refs)
}

// Shared case locators come from a committed decision's exact source records
// and the verified narrow index. Their bodies are fetched only during case
// creation, with the same hash and event-key checks as discovery evidence.
func (s *DBStore) ReadStreamSharedCaseEvidence(ctx context.Context, refs []StreamBodyRef) (map[StreamBodyRef]StreamCaseEvidence, error) {
	if s == nil || s.ch == nil || len(refs) == 0 || len(refs) > 100 {
		return nil, errors.New("shared case original reader unavailable or request too large")
	}
	for _, ref := range refs {
		if ref.Epoch == "" || ref.Class != "evidence" || ref.Validate() != nil {
			return nil, errors.New("shared case original needs a complete evidence reference")
		}
	}
	return s.readStreamCaseBodies(ctx, refs)
}

func (s *DBStore) readStreamCaseBodies(ctx context.Context, refs []StreamBodyRef) (map[StreamBodyRef]StreamCaseEvidence, error) {
	out := make(map[StreamBodyRef]StreamCaseEvidence, len(refs))
	bodies, err := s.ch.getStreamBodiesByRefs(ctx, refs, false)
	if err != nil {
		return nil, err
	}
	for _, ref := range refs {
		evidence, found := bodies[ref]
		if !found || len(evidence.Body) == 0 || evidence.BodySHA256 != ref.SHA256 || ref.Key != ref.Epoch+":"+evidence.Event.EventID {
			return nil, streamlog.ErrContentConflict
		}
		out[ref] = StreamCaseEvidence{Document: evidence.Body, ContentHash: ref.SHA256}
	}
	return out, nil
}
