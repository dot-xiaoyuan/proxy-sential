package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type StreamSharedCutover struct {
	Epoch      string
	Cutoff     time.Time
	SourcePath string
	ScopeID    string
}

// The reader selects one owner generation before fetching any signal rows.
// A missing row means that owner still uses the legacy bounded reader.
func (s *DBStore) activeStreamSharedCutover(ctx context.Context, sensor, owner string) (StreamSharedCutover, bool, error) {
	if s == nil || s.pg == nil || sensor == "" || (owner != "handshake-sidecar" && owner != "packet-sidecar") {
		return StreamSharedCutover{}, false, errors.New("invalid shared source cutover lookup")
	}
	var item StreamSharedCutover
	err := s.pg.db.QueryRowContext(ctx, `SELECT epoch,source_cutoff_at,source_path,scope_id FROM stream_shared_source_cutovers
 WHERE sensor_id=$1 AND source_owner=$2 AND state='active'`, sensor, owner).Scan(&item.Epoch, &item.Cutoff, &item.SourcePath, &item.ScopeID)
	if errors.Is(err, sql.ErrNoRows) {
		return StreamSharedCutover{}, false, nil
	}
	if err != nil {
		return StreamSharedCutover{}, false, err
	}
	if item.Epoch == "" || item.Cutoff.IsZero() || item.SourcePath == "" || item.ScopeID == "" {
		return StreamSharedCutover{}, false, errors.New("shared source cutover is incomplete")
	}
	return item, true, nil
}
