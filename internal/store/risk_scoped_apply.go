package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
)

type scopedRiskRow struct {
	Sensor   string         `json:"sensor_id"`
	Type     string         `json:"subject_type"`
	ID       string         `json:"subject_id"`
	IP       string         `json:"ip"`
	Score    int            `json:"score"`
	Level    string         `json:"level"`
	Observed time.Time      `json:"observed_at"`
	AsOf     time.Time      `json:"evaluated_at"`
	Hash     string         `json:"content_sha256"`
	Snapshot *risk.Snapshot `json:"snapshot"`
}

type scopedEvidenceRow struct {
	Sensor   string            `json:"sensor_id"`
	ID       string            `json:"evidence_id"`
	Type     string            `json:"subject_type"`
	Subject  string            `json:"subject_id"`
	Hash     string            `json:"content_sha256"`
	Evidence evidence.Evidence `json:"evidence"`
	Created  time.Time         `json:"created_at"`
	AsOf     time.Time         `json:"evaluated_at"`
}

type scopedRiskChange struct {
	Sensor   string    `json:"sensor_id"`
	Type     string    `json:"subject_type"`
	ID       string    `json:"subject_id"`
	Previous string    `json:"previous_sha256"`
	Current  string    `json:"current_sha256"`
	Reason   string    `json:"reason"`
	Evidence []string  `json:"evidence_ids"`
	Observed time.Time `json:"observed_at"`
}

func (s *DBStore) ListStreamRiskFeatureEvents(ctx context.Context, sensor string, claims []RiskSubjectClaim, from, to, acceptedAfter time.Time, limit int) ([]normalized.Event, error) {
	if s == nil || s.ch == nil {
		return nil, errors.New("risk feature store unavailable")
	}
	return s.ch.ListStreamRiskFeatureEvents(ctx, sensor, claims, from, to, acceptedAfter, limit)
}

func (s *DBStore) ApplyStreamRiskEvaluation(ctx context.Context, sensor string, claims []RiskSubjectClaim, facts []evidence.Evidence, snapshots []risk.Snapshot, asOf time.Time) error {
	if s == nil || s.pg == nil || sensor == "" || asOf.IsZero() || len(claims) == 0 || len(claims) > maxRiskSubjectClaim {
		return errors.New("invalid scoped risk commit")
	}
	claimKeys := make(map[string]bool, len(claims))
	for _, claim := range claims {
		if claim.SensorID != sensor || claim.ID == "" || claim.Generation <= 0 || (claim.Type != "ip" && claim.Type != "account") {
			return errors.New("scoped risk claim mismatch")
		}
		key := claim.Type + "\x00" + claim.ID
		if claimKeys[key] {
			return errors.New("duplicate scoped risk claim")
		}
		claimKeys[key] = true
	}
	rowsByKey := make(map[string]scopedRiskRow, len(snapshots))
	for _, snapshot := range snapshots {
		kind, id := snapshot.SubjectType, snapshot.SubjectID
		if kind == "" || kind == "ip" {
			kind, id = "ip", snapshot.IP
		}
		key := kind + "\x00" + id
		if !claimKeys[key] || rowsByKey[key].ID != "" {
			return errors.New("unclaimed or duplicate scoped risk snapshot")
		}
		observed, err := time.Parse(time.RFC3339Nano, snapshot.UpdatedAt)
		if err != nil || observed.After(asOf.Add(time.Second)) {
			return errors.New("scoped risk snapshot has invalid observation time")
		}
		semantic := snapshot
		semantic.UpdatedAt = ""
		digest, err := riskJSONHash(semantic)
		if err != nil {
			return err
		}
		rowsByKey[key] = scopedRiskRow{Sensor: sensor, Type: kind, ID: id, IP: snapshot.IP, Score: snapshot.Score, Level: snapshot.Level, Observed: observed.UTC(), AsOf: asOf.UTC(), Hash: digest, Snapshot: &snapshot}
	}
	evidenceRows := make([]scopedEvidenceRow, 0, len(facts))
	evidenceIDs := make(map[string]bool, len(facts))
	for _, fact := range facts {
		kind, id := fact.SubjectType, fact.SubjectID
		if kind == "" || kind == "ip" {
			kind, id = "ip", fact.IP
		}
		if !claimKeys[kind+"\x00"+id] || fact.EvidenceID == "" || evidenceIDs[fact.EvidenceID] {
			return errors.New("unclaimed or duplicate scoped risk evidence")
		}
		evidenceIDs[fact.EvidenceID] = true
		created, err := time.Parse(time.RFC3339Nano, fact.CreatedAt)
		if err != nil {
			return err
		}
		digest, err := riskJSONHash(fact)
		if err != nil {
			return err
		}
		evidenceRows = append(evidenceRows, scopedEvidenceRow{Sensor: sensor, ID: fact.EvidenceID, Type: kind, Subject: id, Hash: digest, Evidence: fact, Created: created.UTC(), AsOf: asOf.UTC()})
	}
	claimJSON, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var locked int
	err = tx.QueryRowContext(ctx, `WITH locked AS (SELECT q.sensor_id FROM risk_feature_dirty_subjects q JOIN jsonb_to_recordset($1::jsonb) r(sensor_id text,subject_type text,subject_id text,generation bigint)
 ON q.sensor_id=r.sensor_id AND q.subject_type=r.subject_type AND q.subject_id=r.subject_id
 WHERE q.generation=r.generation AND q.claimed_generation=r.generation AND q.claim_until>now() FOR UPDATE OF q)
 SELECT count(*) FROM locked`, claimJSON).Scan(&locked)
	if err != nil || locked != len(claims) {
		if err != nil {
			return fmt.Errorf("lock incremental risk claims: %w", err)
		}
		return fmt.Errorf("incremental risk lease changed: locked=%d claims=%d", locked, len(claims))
	}
	previous := map[string]struct {
		hash     string
		observed time.Time
	}{}
	priorRows, err := tx.QueryContext(ctx, `SELECT q.subject_type,q.subject_id,q.content_sha256,q.observed_at FROM stream_risk_current q
 JOIN jsonb_to_recordset($1::jsonb) r(sensor_id text,subject_type text,subject_id text)
 ON q.sensor_id=r.sensor_id AND q.subject_type=r.subject_type AND q.subject_id=r.subject_id
 WHERE q.evaluated_at>=(SELECT max(accepted_after) FROM stream_risk_fresh_cutovers WHERE sensor_id=q.sensor_id) FOR UPDATE OF q`, claimJSON)
	if err != nil {
		return err
	}
	for priorRows.Next() {
		var kind, id, hash string
		var observed time.Time
		if err := priorRows.Scan(&kind, &id, &hash, &observed); err != nil {
			priorRows.Close()
			return err
		}
		previous[kind+"\x00"+id] = struct {
			hash     string
			observed time.Time
		}{hash, observed}
	}
	err = priorRows.Err()
	priorRows.Close()
	if err != nil {
		return err
	}
	upserts := make([]scopedRiskRow, 0, len(snapshots))
	expires := make([]scopedRiskRow, 0)
	changes := make([]scopedRiskChange, 0)
	late := make(map[string]bool)
	for _, claim := range claims {
		key := claim.Type + "\x00" + claim.ID
		prior, existed := previous[key]
		row, present := rowsByKey[key]
		if present && existed && row.Observed.Before(prior.observed) {
			late[key] = true
			continue // late observation cannot replace a newer current result
		}
		if !present {
			if !existed {
				continue
			}
			expires = append(expires, scopedRiskRow{Sensor: sensor, Type: claim.Type, ID: claim.ID})
			changes = append(changes, scopedRiskChange{Sensor: sensor, Type: claim.Type, ID: claim.ID, Previous: prior.hash, Reason: "expired", Evidence: []string{}, Observed: asOf.UTC()})
			continue
		}
		upserts = append(upserts, row)
		if !existed || prior.hash != row.Hash {
			reason, priorHash := "created", ""
			if existed {
				reason, priorHash = "corrected", prior.hash
			}
			changes = append(changes, scopedRiskChange{Sensor: sensor, Type: claim.Type, ID: claim.ID, Previous: priorHash, Current: row.Hash, Reason: reason, Evidence: append([]string{}, row.Snapshot.EvidenceIDs...), Observed: row.Observed})
		}
	}
	if len(evidenceRows) > 0 {
		currentEvidence := evidenceRows[:0]
		for _, item := range evidenceRows {
			if !late[item.Type+"\x00"+item.Subject] {
				currentEvidence = append(currentEvidence, item)
			}
		}
		evidenceRows = currentEvidence
	}
	if len(evidenceRows) > 0 {
		raw, marshalErr := json.Marshal(evidenceRows)
		if marshalErr != nil {
			return marshalErr
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO stream_risk_evidence(sensor_id,evidence_id,subject_type,subject_id,content_sha256,evidence,created_at,evaluated_at)
 SELECT sensor_id,evidence_id,subject_type,subject_id,content_sha256,evidence,created_at,evaluated_at
 FROM jsonb_to_recordset($1::jsonb) r(sensor_id text,evidence_id text,subject_type text,subject_id text,content_sha256 text,evidence jsonb,created_at timestamptz,evaluated_at timestamptz)
 ON CONFLICT(sensor_id,evidence_id) DO UPDATE SET content_sha256=EXCLUDED.content_sha256,evidence=EXCLUDED.evidence,created_at=EXCLUDED.created_at,evaluated_at=EXCLUDED.evaluated_at,updated_at=now()
 WHERE stream_risk_evidence.content_sha256 IS DISTINCT FROM EXCLUDED.content_sha256
 OR stream_risk_evidence.evaluated_at IS NULL
	 OR stream_risk_evidence.evaluated_at<(SELECT max(accepted_after) FROM stream_risk_fresh_cutovers WHERE sensor_id=EXCLUDED.sensor_id)`, raw); err != nil {
			return err
		}
	}
	if len(upserts) > 0 {
		raw, marshalErr := json.Marshal(upserts)
		if marshalErr != nil {
			return marshalErr
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO stream_risk_current(sensor_id,subject_type,subject_id,ip,score,level,observed_at,evaluated_at,content_sha256,snapshot)
 SELECT sensor_id,subject_type,subject_id,NULLIF(ip,'')::inet,score,level,observed_at,evaluated_at,content_sha256,snapshot
 FROM jsonb_to_recordset($1::jsonb) r(sensor_id text,subject_type text,subject_id text,ip text,score integer,level text,observed_at timestamptz,evaluated_at timestamptz,content_sha256 text,snapshot jsonb)
 ON CONFLICT(sensor_id,subject_type,subject_id) DO UPDATE SET ip=EXCLUDED.ip,score=EXCLUDED.score,level=EXCLUDED.level,observed_at=EXCLUDED.observed_at,evaluated_at=EXCLUDED.evaluated_at,content_sha256=EXCLUDED.content_sha256,snapshot=EXCLUDED.snapshot
	 WHERE stream_risk_current.evaluated_at<(SELECT max(accepted_after) FROM stream_risk_fresh_cutovers WHERE sensor_id=EXCLUDED.sensor_id)
 OR (stream_risk_current.observed_at<=EXCLUDED.observed_at AND
 ((stream_risk_current.content_sha256,stream_risk_current.observed_at,stream_risk_current.snapshot) IS DISTINCT FROM
 (EXCLUDED.content_sha256,EXCLUDED.observed_at,EXCLUDED.snapshot)
 ))`, raw); err != nil {
			return err
		}
	}
	if len(expires) > 0 {
		raw, marshalErr := json.Marshal(expires)
		if marshalErr != nil {
			return marshalErr
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM stream_risk_current q USING jsonb_to_recordset($1::jsonb) r(sensor_id text,subject_type text,subject_id text)
 WHERE q.sensor_id=r.sensor_id AND q.subject_type=r.subject_type AND q.subject_id=r.subject_id`, raw); err != nil {
			return err
		}
	}
	if len(changes) > 0 {
		raw, marshalErr := json.Marshal(changes)
		if marshalErr != nil {
			return marshalErr
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO stream_risk_changes(sensor_id,subject_type,subject_id,previous_sha256,current_sha256,reason,evidence_ids,observed_at)
 SELECT sensor_id,subject_type,subject_id,previous_sha256,current_sha256,reason,coalesce(evidence_ids,'[]'::jsonb),observed_at
 FROM jsonb_to_recordset($1::jsonb) r(sensor_id text,subject_type text,subject_id text,previous_sha256 text,current_sha256 text,reason text,evidence_ids jsonb,observed_at timestamptz)`, raw); err != nil {
			return err
		}
	}
	deleted, err := tx.ExecContext(ctx, `DELETE FROM risk_feature_dirty_subjects q USING jsonb_to_recordset($1::jsonb) r(sensor_id text,subject_type text,subject_id text,generation bigint)
 WHERE q.sensor_id=r.sensor_id AND q.subject_type=r.subject_type AND q.subject_id=r.subject_id AND q.generation=r.generation AND q.claimed_generation=r.generation`, claimJSON)
	if err != nil {
		return err
	}
	affected, err := deleted.RowsAffected()
	if err != nil || affected != int64(len(claims)) {
		if err != nil {
			return fmt.Errorf("count incremental risk acknowledgements: %w", err)
		}
		return fmt.Errorf("incremental risk acknowledgement lost: deleted=%d claims=%d", affected, len(claims))
	}
	return tx.Commit()
}

func riskJSONHash(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
