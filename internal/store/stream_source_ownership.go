package store

import (
	"context"
	"errors"
	"fmt"
)

// ActiveStreamSourceCutovers is a small startup guard for the legacy reader.
// A source owned by a fresh stream epoch must never fall back to the old
// checkpoint when an application rollback restarts legacy ingest.
func (s *DBStore) ActiveStreamSourceCutovers(ctx context.Context) (map[string]string, error) {
	if s == nil || s.pg == nil {
		return nil, errors.New("stream source ownership store unavailable")
	}
	return s.pg.ActiveStreamSourceCutovers(ctx)
}

func (s *PostgresStore) ActiveStreamSourceCutovers(ctx context.Context) (map[string]string, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("stream source ownership store unavailable")
	}
	// A retired or paused stream still owns its old file position. A compatible
	// application rollback must never resume the legacy checkpoint for it.
	rows, err := s.db.QueryContext(ctx, `SELECT source_kind,source_path,sensor_id FROM stream_source_cutovers WHERE state IN ('active','paused','closed')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	owners := map[string]string{}
	for rows.Next() {
		var kind, path, sensor string
		if err := rows.Scan(&kind, &path, &sensor); err != nil {
			return nil, err
		}
		key := kind + "\x00" + path
		if prior := owners[key]; prior != "" && prior != sensor {
			return nil, fmt.Errorf("stream source %s at %s has conflicting owners", kind, path)
		}
		owners[key] = sensor
	}
	return owners, rows.Err()
}
