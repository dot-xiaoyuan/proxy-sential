package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

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
	WHERE r.archive_state IN ('confirmed','verified')
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
	bodies, err := s.ch.getStreamBodiesByRefs(ctx, refs)
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
