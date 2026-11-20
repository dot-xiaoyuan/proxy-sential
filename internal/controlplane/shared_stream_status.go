package controlplane

import (
	"context"
	"database/sql"
	"time"
)

type sharedStreamProgress struct {
	Owner                  string     `json:"source"`
	State                  string     `json:"state"`
	Blocker                string     `json:"blocker,omitempty"`
	FileEpoch              string     `json:"file_epoch,omitempty"`
	SharedEpoch            string     `json:"shared_epoch,omitempty"`
	AcceptedSegment        string     `json:"last_accepted_segment,omitempty"`
	AcceptedAt             *time.Time `json:"last_accepted_at,omitempty"`
	ArchivedSegment        string     `json:"last_archived_segment,omitempty"`
	ArchivedInputAt        *time.Time `json:"last_archived_input_at,omitempty"`
	SharedConfirmedSegment string     `json:"last_shared_confirmed_segment,omitempty"`
	SharedConfirmedAt      *time.Time `json:"last_shared_confirmed_at,omitempty"`
	PendingSegments        int        `json:"pending_segments"`
	PendingBytes           int64      `json:"pending_bytes"`
	OldestPendingAt        *time.Time `json:"oldest_pending_at,omitempty"`
	FailedSegment          string     `json:"failed_segment,omitempty"`
	FailedStage            string     `json:"failed_stage,omitempty"`
	FirstFailedAt          *time.Time `json:"first_failed_at,omitempty"`
	ReportedAt             *time.Time `json:"reported_at,omitempty"`
}

func (s *Server) readSharedStreamProgress(ctx context.Context, now time.Time) ([]sharedStreamProgress, error) {
	rows, err := s.operations.db.QueryContext(ctx, `SELECT owner.name,COALESCE(f.epoch,''),COALESCE(g.epoch,''),
 COALESCE(r.accepted_segment,''),r.accepted_at,COALESCE(r.archived_segment,''),r.archived_at,
 COALESCE(a.segment_id,''),a.completed_at,COALESCE(r.pending_segments,0),COALESCE(r.pending_bytes,0),r.oldest_pending_at,
 COALESCE(r.failed_segment,''),COALESCE(r.failed_stage,''),r.failed_at,COALESCE(r.blocker,''),r.updated_at
 FROM (VALUES('packet-sidecar','/ttl.jsonl'),('handshake-sidecar','/handshake.jsonl')) owner(name,suffix)
 LEFT JOIN stream_shared_source_cutovers g ON g.sensor_id=$1 AND g.source_owner=owner.name AND g.state='active'
 LEFT JOIN LATERAL (SELECT epoch,source_path FROM stream_source_cutovers c WHERE c.sensor_id=$1 AND c.source_kind='device-signals'
 AND c.state='active' AND (c.source_path=g.source_path OR (g.source_path IS NULL AND right(c.source_path,length(owner.suffix))=owner.suffix))
 ORDER BY c.cutover_at DESC LIMIT 1) f ON true
 LEFT JOIN stream_shared_source_runtime r ON r.sensor_id=$1 AND r.source_path=f.source_path AND r.epoch=f.epoch
 LEFT JOIN LATERAL (SELECT segment_id,completed_at FROM stream_shared_segment_receipts
 WHERE epoch=f.epoch AND source_path=f.source_path AND source_owner=owner.name ORDER BY completed_at DESC,segment_id LIMIT 1) a ON true`, s.sensorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	nullable := func(at sql.NullTime) *time.Time {
		if !at.Valid {
			return nil
		}
		return &at.Time
	}
	progress := make([]sharedStreamProgress, 0, 2)
	for rows.Next() {
		var p sharedStreamProgress
		var accepted, archived, confirmed, pending, failed, reported sql.NullTime
		if err := rows.Scan(&p.Owner, &p.FileEpoch, &p.SharedEpoch, &p.AcceptedSegment, &accepted, &p.ArchivedSegment, &archived,
			&p.SharedConfirmedSegment, &confirmed, &p.PendingSegments, &p.PendingBytes, &pending,
			&p.FailedSegment, &p.FailedStage, &failed, &p.Blocker, &reported); err != nil {
			return nil, err
		}
		p.AcceptedAt, p.ArchivedInputAt, p.SharedConfirmedAt = nullable(accepted), nullable(archived), nullable(confirmed)
		p.OldestPendingAt, p.FirstFailedAt, p.ReportedAt = nullable(pending), nullable(failed), nullable(reported)
		switch {
		case p.FileEpoch == "" || p.FileEpoch != p.SharedEpoch:
			p.State, p.Blocker = "blocked", "shared_source_binding_mismatch"
		case p.Blocker != "":
			p.State = "blocked"
		case !reported.Valid || now.Sub(reported.Time) > 90*time.Second:
			p.State, p.Blocker = "unavailable", "stream_progress_stale"
		case pending.Valid && now.Sub(pending.Time) > s.sharedConfig.Freshness():
			p.State, p.Blocker = "delayed", "shared_source_backlog"
		case p.PendingSegments > 0:
			p.State = "processing"
		case !accepted.Valid || now.Sub(accepted.Time) > s.sharedConfig.Freshness():
			p.State = "quiet"
		default:
			p.State = "healthy"
		}
		progress = append(progress, p)
	}
	return progress, rows.Err()
}
