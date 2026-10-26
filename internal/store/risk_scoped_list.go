package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"proxy-sentinel/internal/risk"
)

var ErrStreamRiskCursor = errors.New("invalid or stale stream risk cursor")

type StreamRiskCurrentPage struct {
	Items      []risk.Snapshot `json:"items"`
	NextCursor string          `json:"next_cursor,omitempty"`
	Cutoff     time.Time       `json:"accepted_after"`
}

type streamRiskCursor struct {
	Cutoff time.Time `json:"cutoff"`
	Type   string    `json:"subject_type"`
	Level  string    `json:"level"`
	Score  int       `json:"score"`
	ID     string    `json:"subject_id"`
}

func (s *DBStore) ListStreamRiskCurrent(ctx context.Context, sensor, subjectType, level, cursor string, limit int) (StreamRiskCurrentPage, error) {
	if s == nil || s.pg == nil {
		return StreamRiskCurrentPage{}, errors.New("scoped risk list store unavailable")
	}
	return s.pg.ListStreamRiskCurrent(ctx, sensor, subjectType, level, cursor, limit)
}

// ListStreamRiskCurrent uses the existing (sensor,level,score,subject_id)
// index and returns only one cursor page. The old global snapshot list remains
// separate until its read cutover has passed the input and freshness gates.
func (s *PostgresStore) ListStreamRiskCurrent(ctx context.Context, sensor, subjectType, level, cursor string, limit int) (StreamRiskCurrentPage, error) {
	if s == nil || s.db == nil || sensor == "" || (subjectType != "ip" && subjectType != "account") ||
		limit < 1 || limit > 100 {
		return StreamRiskCurrentPage{}, errors.New("invalid scoped risk list")
	}
	if level != "" {
		if _, ok := levelRank(level); !ok {
			return StreamRiskCurrentPage{}, errors.New("invalid scoped risk level")
		}
	}
	var cutoff time.Time
	if err := s.db.QueryRowContext(ctx, `SELECT accepted_after FROM stream_risk_fresh_cutovers WHERE sensor_id=$1 ORDER BY accepted_after DESC LIMIT 1`, sensor).Scan(&cutoff); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return StreamRiskCurrentPage{}, errors.New("risk fresh cutover has not been audited")
		}
		return StreamRiskCurrentPage{}, err
	}
	cutoff = cutoff.UTC()
	var after streamRiskCursor
	if cursor != "" {
		if len(cursor) > 1024 {
			return StreamRiskCurrentPage{}, ErrStreamRiskCursor
		}
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || json.Unmarshal(raw, &after) != nil || !after.Cutoff.Equal(cutoff) ||
			after.Type != subjectType || after.ID == "" || (level != "" && after.Level != level) {
			return StreamRiskCurrentPage{}, ErrStreamRiskCursor
		}
		if _, ok := levelRank(after.Level); !ok || after.Score < 0 || after.Score > 100 {
			return StreamRiskCurrentPage{}, ErrStreamRiskCursor
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT snapshot,content_sha256,observed_at,subject_type,subject_id,level,score
 FROM stream_risk_current c
 WHERE c.sensor_id=$1 AND c.subject_type=$2 AND c.evaluated_at>=$3
 AND observed_at>=now()-interval '10 minutes'
 AND NOT EXISTS (SELECT 1 FROM risk_feature_dirty_subjects q
                 WHERE q.sensor_id=c.sensor_id AND q.subject_type=c.subject_type AND q.subject_id=c.subject_id)
 AND ($4::text='' OR c.level=$4)
 AND (NOT $5::boolean OR (c.level>$6 OR (c.level=$6 AND (c.score<$7 OR (c.score=$7 AND c.subject_id>$8)))))
 ORDER BY c.level ASC,c.score DESC,c.subject_id ASC LIMIT $9`,
		sensor, subjectType, cutoff, level, cursor != "", after.Level, after.Score, after.ID, limit+1)
	if err != nil {
		return StreamRiskCurrentPage{}, err
	}
	defer rows.Close()
	type entry struct {
		snapshot risk.Snapshot
		cursor   streamRiskCursor
	}
	items := make([]entry, 0, limit+1)
	for rows.Next() {
		var raw []byte
		var hash, kind, id, rowLevel string
		var observed time.Time
		var score int
		if err := rows.Scan(&raw, &hash, &observed, &kind, &id, &rowLevel, &score); err != nil {
			return StreamRiskCurrentPage{}, err
		}
		var snapshot risk.Snapshot
		if err := json.Unmarshal(raw, &snapshot); err != nil {
			return StreamRiskCurrentPage{}, err
		}
		identity := snapshot.SubjectID
		if kind == "ip" {
			identity = snapshot.IP
		}
		stamp, err := time.Parse(time.RFC3339Nano, snapshot.UpdatedAt)
		semantic := snapshot
		semantic.UpdatedAt = ""
		actualHash, hashErr := riskJSONHash(semantic)
		if err != nil || hashErr != nil || identity != id || kind != subjectType ||
			snapshot.Level != rowLevel || snapshot.Score != score || !stamp.Equal(observed.UTC()) || actualHash != hash {
			return StreamRiskCurrentPage{}, fmt.Errorf("scoped risk list content conflict: %s", id)
		}
		items = append(items, entry{snapshot: snapshot, cursor: streamRiskCursor{Cutoff: cutoff, Type: kind, Level: rowLevel, Score: score, ID: id}})
	}
	if err := rows.Err(); err != nil {
		return StreamRiskCurrentPage{}, err
	}
	page := StreamRiskCurrentPage{Items: make([]risk.Snapshot, 0, limit), Cutoff: cutoff}
	if len(items) > limit {
		items = items[:limit]
		raw, err := json.Marshal(items[len(items)-1].cursor)
		if err != nil {
			return StreamRiskCurrentPage{}, err
		}
		page.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	for _, item := range items {
		page.Items = append(page.Items, item.snapshot)
	}
	return page, nil
}
