package store

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/sharedaccess"
	"time"
)

type SharedAccessReader interface {
	ListSharedAccessWindows(context.Context, time.Time, time.Time, int) ([]sharedaccess.Window, error)
}

func (s *PostgresStore) ListSharedAccessWindows(ctx context.Context, from, to time.Time, limit int) ([]sharedaccess.Window, error) {
	if limit < 1 || limit > 10000 || !to.After(from) {
		return nil, fmt.Errorf("invalid shared evidence query bounds")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT metadata FROM (
 SELECT DISTINCT ON (ip,metadata->'shared_access'->>'sensor_id',metadata->'shared_access'->>'campus_id',metadata->'shared_access'->>'access_domain') metadata,created_at,evidence_id
 FROM evidence WHERE type='shared_access_window' AND created_at >= $1 AND created_at <= $2
 ORDER BY ip,metadata->'shared_access'->>'sensor_id',metadata->'shared_access'->>'campus_id',metadata->'shared_access'->>'access_domain',created_at DESC,evidence_id DESC
 ) latest ORDER BY created_at DESC,evidence_id DESC LIMIT $3`, from, to, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []sharedaccess.Window{}
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		var item evidence.Evidence
		if err = json.Unmarshal(raw, &item); err != nil {
			return nil, err
		}
		if item.SharedAccess == nil {
			return nil, fmt.Errorf("shared evidence metadata missing")
		}
		out = append(out, *item.SharedAccess)
		if len(out) > limit {
			return nil, fmt.Errorf("shared evidence scope limit exceeded; evaluation incomplete")
		}
	}
	return out, rows.Err()
}
func (s *DBStore) ListSharedAccessWindows(ctx context.Context, from, to time.Time, limit int) ([]sharedaccess.Window, error) {
	return s.pg.ListSharedAccessWindows(ctx, from, to, limit)
}
func (s *FileStore) ListSharedAccessWindows(ctx context.Context, from, to time.Time, limit int) ([]sharedaccess.Window, error) {
	if limit < 1 || limit > 10000 || !to.After(from) {
		return nil, fmt.Errorf("invalid shared evidence query bounds")
	}
	latest, ok, err := s.latestRun(ctx)
	if err != nil {
		return nil, err
	}
	if !ok {
		return []sharedaccess.Window{}, nil
	}
	all, err := readEvidence(filepath.Join(latest.Dir, "evidence.json"))
	if err != nil {
		return nil, err
	}
	chosen := map[sharedaccess.Scope]sharedaccess.Window{}
	for _, item := range all.Evidence {
		w := item.SharedAccess
		if item.Type != "shared_access_window" || w == nil || w.To.Before(from) || w.To.After(to) {
			continue
		}
		k := sharedaccess.Scope{IP: w.IP, SensorID: w.SensorID, CampusID: w.CampusID, AccessDomain: w.AccessDomain}
		old, ok := chosen[k]
		if !ok || w.To.After(old.To) || (w.To.Equal(old.To) && w.ID > old.ID) {
			chosen[k] = *w
		}
	}
	if len(chosen) > limit {
		return nil, fmt.Errorf("shared evidence scope limit exceeded; evaluation incomplete")
	}
	out := []sharedaccess.Window{}
	for _, w := range chosen {
		out = append(out, w)
	}
	return out, nil
}
