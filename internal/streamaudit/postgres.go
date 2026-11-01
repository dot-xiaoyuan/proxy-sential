package streamaudit

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const segmentWitnessSQL = `SELECT segment_id,epoch,source_kind,source_path,source_file_id,
 source_start_offset,source_end_offset,content_sha256,event_count,projected_at,lanes_finalized_at
 FROM stream_projection_segments WHERE segment_id=$1 LIMIT 1`

// AuditPostgres reads at most MaxSegments primary-key rows in a read-only
// snapshot. It never queries a whole epoch or attempts to mutate a receipt.
func AuditPostgres(ctx context.Context, db *sql.DB, manifest Manifest) (Report, error) {
	if len(ManifestIssues(manifest)) != 0 {
		return Verify(manifest, nil), nil
	}
	if db == nil {
		return Verify(manifest, nil), errors.New("PostgreSQL connection is required")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return Verify(manifest, nil), err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SET LOCAL statement_timeout = '5s'`); err != nil {
		return Verify(manifest, nil), err
	}
	witnesses := make([]Witness, 0, len(manifest.Segments))
	for _, segment := range manifest.Segments {
		row := Witness{ID: segment.ID}
		err := tx.QueryRowContext(ctx, segmentWitnessSQL, segment.ID).Scan(
			&row.ID, &row.Epoch, &row.SourceKind, &row.SourcePath, &row.FileID,
			&row.StartOffset, &row.EndOffset, &row.ProjectionSHA256, &row.EventCount, &row.ProjectedAt, &row.FinalizedAt,
		)
		if errors.Is(err, sql.ErrNoRows) {
			witnesses = append(witnesses, row)
			continue
		}
		if err != nil {
			return Verify(manifest, witnesses), err
		}
		row.Found = true
		witnesses = append(witnesses, row)
	}
	return Verify(manifest, witnesses), nil
}
