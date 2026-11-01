package discovery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/streamlog"
)

// MarkStreamSegmentFinalized records the source position after the processor
// has durably acknowledged projection, archive, search and downstream wakes.
// The projection acknowledgement already checked the row's content hash, so
// this finalizer only scans the bounded event list for its projected count.
// A row created before the source-position migration stays unwitnessed.
func (p StreamDiscoveryProjector) MarkStreamSegmentFinalized(ctx context.Context, id string, segment streamlog.Segment) error {
	if p.DB == nil || id == "" || !segment.NeedsProjection || segment.Epoch == "" || segment.Source == "" || segment.SourcePath == "" ||
		segment.FileID == "" || segment.StartOffset < 0 || segment.EndOffset <= segment.StartOffset {
		return errors.New("stream finalization witness needs a projected source position")
	}
	count := 0
	for _, event := range segment.Events {
		if normalized.IsDiscoveryProjectionEvent(event) {
			count++
		}
	}
	if count == 0 {
		return ErrUnsupportedStreamProjection
	}
	result, err := p.DB.ExecContext(ctx, `UPDATE stream_projection_segments
 SET lanes_finalized_at=clock_timestamp()
 WHERE segment_id=$1 AND epoch=$2 AND source_kind=$3 AND source_path=$4
 AND source_file_id=$5 AND source_start_offset=$6 AND source_end_offset=$7
 AND event_count=$8 AND lanes_finalized_at IS NULL`, id, segment.Epoch, segment.Source, segment.SourcePath,
		segment.FileID, segment.StartOffset, segment.EndOffset, count)
	if err != nil {
		// A lost response might follow a committed UPDATE. Keep the journal and
		// retry; the next call reads back the same immutable position.
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated == 1 {
		return nil
	}
	if updated != 0 {
		return streamlog.ErrContentConflict
	}
	var epoch, source, path string
	var file sql.NullString
	var start, end sql.NullInt64
	var eventCount int
	var finalized sql.NullTime
	err = p.DB.QueryRowContext(ctx, `SELECT epoch,source_kind,source_path,source_file_id,source_start_offset,source_end_offset,event_count,lanes_finalized_at
 FROM stream_projection_segments WHERE segment_id=$1`, id).Scan(&epoch, &source, &path, &file, &start, &end, &eventCount, &finalized)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("stream projection marker missing: %w", streamlog.ErrUnconfirmed)
	}
	if err != nil {
		return err
	}
	if epoch != segment.Epoch || source != segment.Source || path != segment.SourcePath || eventCount != count {
		return streamlog.ErrContentConflict
	}
	if !file.Valid && !start.Valid && !end.Valid && !finalized.Valid {
		// Old projector versions did not store the position. Do not manufacture
		// a completion proof from an already acknowledged legacy row.
		return nil
	}
	if !file.Valid || !start.Valid || !end.Valid || file.String != segment.FileID || start.Int64 != segment.StartOffset || end.Int64 != segment.EndOffset {
		return streamlog.ErrContentConflict
	}
	if !finalized.Valid {
		return fmt.Errorf("stream finalization witness not committed: %w", streamlog.ErrUnconfirmed)
	}
	return nil
}
