package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

type RiskSubjectClaim struct {
	SensorID   string    `json:"sensor_id"`
	Type       string    `json:"subject_type"`
	ID         string    `json:"subject_id"`
	Generation int64     `json:"generation"`
	ObservedAt time.Time `json:"observed_at"`
	FirstDirty time.Time `json:"first_dirty_at"`
}

const maxRiskSubjectClaim = 256

// Expiry is a separate bounded producer of dirty subjects. Without it a quiet
// subject could retain a current risk indefinitely after its last signal.
func (s *DBStore) QueueExpiredStreamRiskSubjects(ctx context.Context, sensor string, before time.Time, limit int) error {
	if s == nil || s.pg == nil || sensor == "" || before.IsZero() || limit < 1 || limit > maxRiskSubjectClaim {
		return errors.New("invalid risk expiry scan")
	}
	_, err := s.pg.db.ExecContext(ctx, `WITH expired AS (
 SELECT c.sensor_id,c.subject_type,c.subject_id,c.observed_at
 FROM stream_risk_current c
 WHERE c.sensor_id=$1 AND c.observed_at<$2
 AND c.evaluated_at>=(SELECT max(accepted_after) FROM stream_risk_fresh_cutovers WHERE sensor_id=c.sensor_id)
 AND NOT EXISTS (SELECT 1 FROM risk_feature_dirty_subjects q
                 WHERE q.sensor_id=c.sensor_id AND q.subject_type=c.subject_type AND q.subject_id=c.subject_id)
 ORDER BY c.observed_at,c.subject_type,c.subject_id LIMIT $3
)
INSERT INTO risk_feature_dirty_subjects(sensor_id,subject_type,subject_id,generation,last_observed_at)
SELECT sensor_id,subject_type,subject_id,nextval('risk_feature_dirty_generation'),observed_at FROM expired
ON CONFLICT(sensor_id,subject_type,subject_id) DO NOTHING`, sensor, before, limit)
	return err
}

func (s *DBStore) ClaimRiskSubjects(ctx context.Context, sensor string, limit int) ([]RiskSubjectClaim, error) {
	if s == nil || s.pg == nil || sensor == "" || limit < 1 || limit > maxRiskSubjectClaim {
		return nil, errors.New("invalid incremental risk claim")
	}
	rows, err := s.pg.db.QueryContext(ctx, `WITH picked AS (
 SELECT sensor_id,subject_type,subject_id FROM risk_feature_dirty_subjects
 WHERE sensor_id=$1 AND (claim_until IS NULL OR claim_until<now())
 ORDER BY last_dirty_at,subject_type,subject_id LIMIT $2 FOR UPDATE SKIP LOCKED
)
UPDATE risk_feature_dirty_subjects q SET claim_until=now()+interval '2 minutes',claimed_generation=q.generation
FROM picked p WHERE q.sensor_id=p.sensor_id AND q.subject_type=p.subject_type AND q.subject_id=p.subject_id
RETURNING q.sensor_id,q.subject_type,q.subject_id,q.claimed_generation,q.last_observed_at,q.first_dirty_at`, sensor, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]RiskSubjectClaim, 0, limit)
	for rows.Next() {
		var item RiskSubjectClaim
		if err := rows.Scan(&item.SensorID, &item.Type, &item.ID, &item.Generation, &item.ObservedAt, &item.FirstDirty); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *DBStore) AckRiskSubjects(ctx context.Context, claims []RiskSubjectClaim) error {
	return s.finishRiskSubjects(ctx, claims, true)
}

func (s *DBStore) ReleaseRiskSubjects(ctx context.Context, claims []RiskSubjectClaim) error {
	return s.finishRiskSubjects(ctx, claims, false)
}

func (s *DBStore) finishRiskSubjects(ctx context.Context, claims []RiskSubjectClaim, completed bool) error {
	if len(claims) == 0 {
		return nil
	}
	if s == nil || s.pg == nil || len(claims) > maxRiskSubjectClaim {
		return errors.New("invalid incremental risk acknowledgement")
	}
	encoded, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if completed {
		_, err = tx.ExecContext(ctx, `DELETE FROM risk_feature_dirty_subjects q USING jsonb_to_recordset($1::jsonb) AS r(sensor_id text,subject_type text,subject_id text,generation bigint)
 WHERE q.sensor_id=r.sensor_id AND q.subject_type=r.subject_type AND q.subject_id=r.subject_id
 AND q.generation=r.generation AND q.claimed_generation=r.generation`, encoded)
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE risk_feature_dirty_subjects q SET claim_until=NULL,claimed_generation=NULL
 FROM jsonb_to_recordset($1::jsonb) AS r(sensor_id text,subject_type text,subject_id text,generation bigint)
 WHERE q.sensor_id=r.sensor_id AND q.subject_type=r.subject_type AND q.subject_id=r.subject_id
 AND q.claimed_generation=r.generation`, encoded)
	if err != nil {
		return err
	}
	return tx.Commit()
}
