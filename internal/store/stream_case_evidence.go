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
	rows, err := s.pg.db.QueryContext(ctx, `SELECT k.epoch,k.scope_id,k.event_key,k.content_sha256,r.body_ref
 FROM jsonb_to_recordset($1::jsonb) AS v(epoch text,scope text,key text,sha256 text)
 JOIN stream_discovery_event_keys k ON k.epoch=v.epoch AND k.scope_id=v.scope AND k.event_key=v.key AND k.content_sha256=v.sha256
 JOIN stream_discovery_receipts r ON r.accepted_month=k.accepted_month AND r.epoch=k.epoch AND r.scope_id=k.scope_id AND r.event_key=k.event_key
 WHERE r.archive_state IN ('confirmed','verified')`, raw)
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
