package store

import (
	"context"
	"database/sql"
	"time"
)

type IdentityPipelineSummary struct {
	ExportError          string     `json:"export_error"`
	ExportHeartbeatAt    *time.Time `json:"export_heartbeat_at"`
	DerivedCursorAt      *time.Time `json:"derived_cursor_at"`
	DerivedLastSuccessAt *time.Time `json:"derived_last_success_at"`
	DerivedError         string     `json:"derived_error"`
	Accounts             *int64     `json:"accounts"`
	Sessions             *int64     `json:"sessions"`
	StatisticsAt         *time.Time `json:"statistics_at"`
	AcceptedSequence     int64      `json:"accepted_sequence"`
	ProcessedSequence    int64      `json:"processed_sequence"`
	PendingRecords       int64      `json:"pending_records"`
	ExportPendingRecords int64      `json:"export_pending_records"`
	OldestPendingAt      *time.Time `json:"oldest_pending_at"`
	HeartbeatAt          *time.Time `json:"heartbeat_at"`
	LastError            string     `json:"last_error"`
	CalibrationState     string     `json:"calibration_state"`
	SnapshotAt           *time.Time `json:"snapshot_at"`
}

// This request path only reads one indexed summary row. Never derive counters
// from session detail tables here, including fallback/error branches.
func ReadIdentityPipelineSummary(ctx context.Context, db *sql.DB, scope IdentityScope) (IdentityPipelineSummary, error) {
	summary := IdentityPipelineSummary{CalibrationState: "pending"}
	err := db.QueryRowContext(ctx, `SELECT accounts,sessions,statistics_at,accepted_sequence,processed_sequence,pending_records,export_pending_records,oldest_pending_at,p.heartbeat_at,p.last_error,calibration_state,snapshot_at,export_last_error,export_heartbeat_at,c.cursor_at,c.last_success_at,COALESCE(d.state->>'last_error','') FROM identity_pipeline_scopes p LEFT JOIN identity_materializer_cursors c ON c.sensor_id=p.sensor_id AND c.phase='live' LEFT JOIN read_model_runtime_state d ON d.name='identity-materializer:'||p.sensor_id WHERE p.scope_key=$1`, IdentityScopeKey(scope)).Scan(&summary.Accounts, &summary.Sessions, &summary.StatisticsAt, &summary.AcceptedSequence, &summary.ProcessedSequence, &summary.PendingRecords, &summary.ExportPendingRecords, &summary.OldestPendingAt, &summary.HeartbeatAt, &summary.LastError, &summary.CalibrationState, &summary.SnapshotAt, &summary.ExportError, &summary.ExportHeartbeatAt, &summary.DerivedCursorAt, &summary.DerivedLastSuccessAt, &summary.DerivedError)
	if err == sql.ErrNoRows {
		return summary, nil
	}
	if summary.StatisticsAt == nil {
		summary.Accounts, summary.Sessions = nil, nil
	}
	return summary, err
}
