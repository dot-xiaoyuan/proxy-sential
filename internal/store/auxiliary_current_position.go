package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"proxy-sentinel/internal/pagination"
)

const streamRiskCurrentSelectionSQL = ` FROM stream_risk_current c
 WHERE c.sensor_id=$1 AND c.subject_type=$2 AND c.evaluated_at>=$3
 AND observed_at>=now()-interval '10 minutes'
 AND NOT EXISTS (SELECT 1 FROM risk_feature_dirty_subjects q
                 WHERE q.sensor_id=c.sensor_id AND q.subject_type=c.subject_type AND q.subject_id=c.subject_id)
 AND ($4::text='' OR c.level=$4)`

func (s *PostgresStore) streamRiskPositionCutoff(ctx context.Context, sensor, kind, level string, limit int) (time.Time, error) {
	if sensor == "" || (kind != "ip" && kind != "account") || limit < 1 || limit > 100 {
		return time.Time{}, fmt.Errorf("invalid scoped risk query")
	}
	if level != "" {
		if _, ok := levelRank(level); !ok {
			return time.Time{}, fmt.Errorf("invalid risk level")
		}
	}
	var cutoff time.Time
	err := s.db.QueryRowContext(ctx, `SELECT accepted_after FROM stream_risk_fresh_cutovers WHERE sensor_id=$1 ORDER BY accepted_after DESC LIMIT 1`, sensor).Scan(&cutoff)
	if errors.Is(err, sql.ErrNoRows) {
		return cutoff, fmt.Errorf("risk fresh cutover has not been audited")
	}
	return cutoff.UTC(), err
}

func (s *PostgresStore) StreamRiskCurrentMetadata(ctx context.Context, sensor, kind, level string) (pagination.Metadata, error) {
	cutoff, err := s.streamRiskPositionCutoff(ctx, sensor, kind, level, 20)
	if err != nil {
		return pagination.Metadata{}, err
	}
	result := pagination.Metadata{AsOf: time.Now().UTC()}
	err = s.db.QueryRowContext(ctx, "SELECT count(*)"+streamRiskCurrentSelectionSQL, sensor, kind, cutoff, level).Scan(&result.Total)
	return result, err
}

func (s *PostgresStore) PositionStreamRiskCurrent(ctx context.Context, sensor, kind, level string, page, limit int) (pagination.Position, error) {
	offset, err := pagination.BoundaryOffset(page, limit)
	if err != nil {
		return pagination.Position{}, err
	}
	cutoff, err := s.streamRiskPositionCutoff(ctx, sensor, kind, level, limit)
	if err != nil {
		return pagination.Position{}, err
	}
	result := pagination.Position{Page: page, Limit: limit, AsOf: time.Now().UTC()}
	if page == 1 {
		return result, nil
	}
	rows, err := s.db.QueryContext(ctx, "SELECT c.level,c.score,c.subject_id"+streamRiskCurrentSelectionSQL+" ORDER BY c.level ASC,c.score DESC,c.subject_id ASC LIMIT 2 OFFSET $5", sensor, kind, cutoff, level, offset)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	c := streamRiskCursor{Cutoff: cutoff, Type: kind}
	count := 0
	for rows.Next() {
		var entry streamRiskCursor
		if err = rows.Scan(&entry.Level, &entry.Score, &entry.ID); err != nil {
			return result, err
		}
		if count == 0 {
			c.Level = entry.Level
			c.Score = entry.Score
			c.ID = entry.ID
		}
		count++
	}
	if err = rows.Err(); err != nil {
		return result, err
	}
	if count < 2 {
		return result, pagination.ErrPageOutOfRange
	}
	raw, _ := json.Marshal(c)
	result.Cursor = base64.RawURLEncoding.EncodeToString(raw)
	return result, nil
}
func (s *DBStore) StreamRiskCurrentMetadata(ctx context.Context, sensor, kind, level string) (pagination.Metadata, error) {
	return s.pg.StreamRiskCurrentMetadata(ctx, sensor, kind, level)
}
func (s *DBStore) PositionStreamRiskCurrent(ctx context.Context, sensor, kind, level string, page, limit int) (pagination.Position, error) {
	return s.pg.PositionStreamRiskCurrent(ctx, sensor, kind, level, page, limit)
}

// Resolve the same audited source generation used by the traffic list. Source
// unavailability is an error, never an invented zero-record statistic.
func (s *DBStore) ipTrafficObservationIndexQuery(ctx context.Context, q IPTrafficObservationQuery) (StreamEventIndexQuery, bool, error) {
	if err := q.Validate(); err != nil {
		return StreamEventIndexQuery{}, false, err
	}
	var source IPTrafficObservationSource
	err := s.pg.db.QueryRowContext(ctx, `SELECT s.epoch,s.scope_id,s.source_cutoff_at,c.state
 FROM stream_shared_source_cutovers s
 JOIN stream_source_cutovers c USING(epoch,source_kind,source_path)
 WHERE s.sensor_id=$1 AND s.source_owner=$2 AND s.state='active' AND c.sensor_id=s.sensor_id`, q.SensorID, q.SourceOwner).Scan(&source.Epoch, &source.ScopeID, &source.CutoffAt, &source.State)
	if err != nil {
		return StreamEventIndexQuery{}, false, err
	}
	if source.Epoch == "" || source.ScopeID == "" || source.CutoffAt.IsZero() {
		return StreamEventIndexQuery{}, false, fmt.Errorf("traffic source metadata incomplete")
	}
	ip, _ := netip.ParseAddr(q.IP)
	query := StreamEventIndexQuery{ScopeID: source.ScopeID, Protocol: q.Protocol, SensorID: q.SensorID, SubjectIP: ip.Unmap().String(), Epoch: source.Epoch, ObservationOnly: true, From: q.From, To: q.To, Limit: q.Limit}
	if !q.To.After(source.CutoffAt) {
		return query, false, nil
	}
	if query.From.Before(source.CutoffAt) {
		query.From = source.CutoffAt
	}
	return query, true, nil
}
func (s *DBStore) IPTrafficObservationMetadata(ctx context.Context, q IPTrafficObservationQuery) (pagination.Metadata, error) {
	query, active, err := s.ipTrafficObservationIndexQuery(ctx, q)
	if err != nil {
		return pagination.Metadata{}, err
	}
	if !active {
		return pagination.Metadata{AsOf: time.Now().UTC()}, nil
	}
	return s.ch.StreamEventIndexMetadata(ctx, query)
}
func (s *DBStore) PositionIPTrafficObservations(ctx context.Context, q IPTrafficObservationQuery, page int) (pagination.Position, error) {
	if _, err := pagination.BoundaryOffset(page, q.Limit); err != nil {
		return pagination.Position{}, err
	}
	query, active, err := s.ipTrafficObservationIndexQuery(ctx, q)
	if err != nil {
		return pagination.Position{}, err
	}
	if !active {
		if page > 1 {
			return pagination.Position{}, pagination.ErrPageOutOfRange
		}
		return pagination.Position{Page: page, Limit: q.Limit, AsOf: time.Now().UTC()}, nil
	}
	return s.ch.PositionStreamEventIndex(ctx, query, page)
}
