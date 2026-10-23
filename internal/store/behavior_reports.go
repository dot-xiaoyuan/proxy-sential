package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"proxy-sentinel/internal/behaviorreport"
)

type BehaviorReportChannel struct {
	ChannelID          string            `json:"channel_id"`
	Name               string            `json:"name"`
	EndpointURL        string            `json:"endpoint_url"`
	TokenEndpoint      string            `json:"token_endpoint,omitempty"`
	TokenMethod        string            `json:"token_method,omitempty"`
	TokenScope         string            `json:"token_scope,omitempty"`
	AuthType           string            `json:"auth_type"`
	SourceSystemIP     string            `json:"source_system_ip,omitempty"`
	SourceSystemName   string            `json:"source_system_name,omitempty"`
	BatchSize          int               `json:"batch_size"`
	FlushIntervalSecs  int               `json:"flush_interval_seconds"`
	TimeoutSeconds     int               `json:"timeout_seconds"`
	TLSSkipVerify      bool              `json:"tls_skip_verify"`
	FieldMapping       map[string]string `json:"field_mapping"`
	SuccessStatusCodes []int             `json:"success_status_codes"`
	Enabled            bool              `json:"enabled"`
	Revision           int               `json:"revision"`
	EncryptedSecret    string            `json:"-"`
	HasSecret          bool              `json:"has_secret"`
	UpdatedBy          string            `json:"updated_by,omitempty"`
	UpdatedAt          string            `json:"updated_at,omitempty"`
}

type BehaviorReportOutboxRow struct {
	ReportID         string `json:"report_id"`
	IdempotencyKey   string `json:"idempotency_key"`
	ChannelID        string `json:"channel_id"`
	EventType        string `json:"event_type"`
	SubjectType      string `json:"subject_type"`
	SubjectID        string `json:"subject_id"`
	AccountID        string `json:"account_id,omitempty"`
	IP               string `json:"ip,omitempty"`
	Target           string `json:"target,omitempty"`
	TargetType       string `json:"target_type,omitempty"`
	OccurredAt       string `json:"occurred_at"`
	Status           string `json:"status"`
	Attempts         int    `json:"attempts"`
	NextAttemptAt    string `json:"next_attempt_at,omitempty"`
	LastError        string `json:"last_error,omitempty"`
	HTTPStatus       int    `json:"http_status"`
	RemoteID         string `json:"remote_id,omitempty"`
	SentAt           string `json:"sent_at,omitempty"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
	PolicyDecisionID string `json:"policy_decision_id,omitempty"`
	ObservationID    string `json:"observation_id,omitempty"`
	EvidenceVersion  string `json:"evidence_version,omitempty"`
}

type BehaviorReportAttempt struct {
	AttemptID  string `json:"attempt_id"`
	ReportID   string `json:"report_id"`
	Attempt    int    `json:"attempt"`
	Status     string `json:"status"`
	HTTPStatus int    `json:"http_status"`
	RemoteID   string `json:"remote_id,omitempty"`
	Error      string `json:"error,omitempty"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
}

// BehaviorReportCandidate is an already-stored observation that should be
// reported northbound. Reporting never re-derives evidence.
type BehaviorReportCandidate struct {
	EvidenceID string `json:"evidence_id"`
	IP         string `json:"ip"`
	EventType  string `json:"event_type"`
	Window     string `json:"window"`
	Reason     string `json:"reason"`
	AccountID  string `json:"account_id,omitempty"`
	OccurredAt string `json:"occurred_at"`
}

const behaviorReportChannelColumns = `channel_id,name,endpoint_url,token_endpoint,token_method,token_scope,auth_type,encrypted_secret,source_system_ip,source_system_name,batch_size,flush_interval_seconds,timeout_seconds,tls_skip_verify,field_mapping,to_json(success_status_codes)::text,enabled,revision,updated_by,to_char(updated_at,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')`

func scanBehaviorReportChannel(scanner interface{ Scan(...any) error }) (BehaviorReportChannel, error) {
	var item BehaviorReportChannel
	var encrypted string
	var mapping []byte
	var codes string
	if err := scanner.Scan(&item.ChannelID, &item.Name, &item.EndpointURL, &item.TokenEndpoint, &item.TokenMethod, &item.TokenScope, &item.AuthType, &encrypted, &item.SourceSystemIP, &item.SourceSystemName, &item.BatchSize, &item.FlushIntervalSecs, &item.TimeoutSeconds, &item.TLSSkipVerify, &mapping, &codes, &item.Enabled, &item.Revision, &item.UpdatedBy, &item.UpdatedAt); err != nil {
		return BehaviorReportChannel{}, err
	}
	item.EncryptedSecret = encrypted
	item.HasSecret = encrypted != ""
	item.FieldMapping = map[string]string{}
	_ = json.Unmarshal(mapping, &item.FieldMapping)
	// integer[] arrives as a driver string; decode it as JSON for portability.
	item.SuccessStatusCodes = []int{}
	_ = json.Unmarshal([]byte(codes), &item.SuccessStatusCodes)
	if len(item.SuccessStatusCodes) == 0 {
		item.SuccessStatusCodes = []int{200}
	}
	return item, nil
}

func (s *PostgresStore) ListBehaviorReportChannels(ctx context.Context) ([]BehaviorReportChannel, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+behaviorReportChannelColumns+` FROM behavior_report_channels ORDER BY name,channel_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []BehaviorReportChannel{}
	for rows.Next() {
		item, err := scanBehaviorReportChannel(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetBehaviorReportChannel(ctx context.Context, id string) (BehaviorReportChannel, error) {
	return scanBehaviorReportChannel(s.db.QueryRowContext(ctx, `SELECT `+behaviorReportChannelColumns+` FROM behavior_report_channels WHERE channel_id=$1`, id))
}

func (s *PostgresStore) UpsertBehaviorReportChannel(ctx context.Context, channel behaviorreport.Channel, encryptedSecret, actor string, creating bool) (BehaviorReportChannel, error) {
	behaviorreport.NormalizeChannel(&channel)
	mapping, err := json.Marshal(channel.FieldMapping)
	if err != nil {
		return BehaviorReportChannel{}, err
	}
	codes := make([]int64, 0, len(channel.SuccessStatusCodes))
	for _, code := range channel.SuccessStatusCodes {
		codes = append(codes, int64(code))
	}
	if creating {
		_, err = s.db.ExecContext(ctx, `INSERT INTO behavior_report_channels(channel_id,name,endpoint_url,token_endpoint,token_method,token_scope,auth_type,encrypted_secret,source_system_ip,source_system_name,batch_size,flush_interval_seconds,timeout_seconds,tls_skip_verify,field_mapping,success_status_codes,enabled,revision,created_by,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,1,$18,$18)`,
			channel.ChannelID, channel.Name, channel.EndpointURL, channel.TokenEndpoint, channel.TokenMethod, channel.TokenScope, channel.AuthType, encryptedSecret, channel.SourceSystemIP, channel.SourceSystemName, channel.BatchSize, channel.FlushIntervalSecs, channel.TimeoutSeconds, channel.TLSSkipVerify, mapping, codes, channel.Enabled, actor)
	} else {
		var result sql.Result
		result, err = s.db.ExecContext(ctx, `UPDATE behavior_report_channels SET name=$2,endpoint_url=$3,token_endpoint=$4,token_method=$5,token_scope=$6,auth_type=$7,encrypted_secret=$8,source_system_ip=$9,source_system_name=$10,batch_size=$11,flush_interval_seconds=$12,timeout_seconds=$13,tls_skip_verify=$14,field_mapping=$15,success_status_codes=$16,enabled=$17,revision=revision+1,updated_by=$18,updated_at=now() WHERE channel_id=$1`,
			channel.ChannelID, channel.Name, channel.EndpointURL, channel.TokenEndpoint, channel.TokenMethod, channel.TokenScope, channel.AuthType, encryptedSecret, channel.SourceSystemIP, channel.SourceSystemName, channel.BatchSize, channel.FlushIntervalSecs, channel.TimeoutSeconds, channel.TLSSkipVerify, mapping, codes, channel.Enabled, actor)
		if err == nil {
			if affected, _ := result.RowsAffected(); affected == 0 {
				return BehaviorReportChannel{}, sql.ErrNoRows
			}
		}
	}
	if err != nil {
		return BehaviorReportChannel{}, err
	}
	return s.GetBehaviorReportChannel(ctx, channel.ChannelID)
}

func (s *PostgresStore) DeleteBehaviorReportChannel(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM behavior_report_channels WHERE channel_id=$1`, id)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ListBehaviorReportCandidates reads observations already stored as evidence.
// Only the three reportable types are returned; the caller maps them to the
// platform vocabulary.
func (s *PostgresStore) ListBehaviorReportCandidates(ctx context.Context, since time.Time, limit int) ([]BehaviorReportCandidate, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx, `SELECT evidence_id,host(ip),type,"window",reason,COALESCE(metadata->>'account_id',''),to_char(created_at,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') FROM evidence WHERE created_at >= $1 AND type IN ('proxy_protocol_transaction','ai_relay_domain_usage','internal_target_access') ORDER BY created_at LIMIT $2`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []BehaviorReportCandidate{}
	for rows.Next() {
		var item BehaviorReportCandidate
		if err := rows.Scan(&item.EvidenceID, &item.IP, &item.EventType, &item.Window, &item.Reason, &item.AccountID, &item.OccurredAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) EnqueueBehaviorReport(ctx context.Context, row BehaviorReportOutboxRow) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO behavior_report_outbox(report_id,idempotency_key,channel_id,event_type,subject_type,subject_id,account_id,ip,target,target_type,occurred_at,payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(idempotency_key) DO NOTHING`,
		row.ReportID, row.IdempotencyKey, row.ChannelID, row.EventType, row.SubjectType, row.SubjectID, row.AccountID, row.IP, row.Target, row.TargetType, row.OccurredAt, []byte(`{}`))
	return err
}

const behaviorReportOutboxColumns = `report_id,idempotency_key,channel_id,event_type,subject_type,subject_id,account_id,ip,target,target_type,to_char(occurred_at,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),status,attempts,coalesce(to_char(next_attempt_at,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),''),last_error,http_status,remote_id,coalesce(to_char(sent_at,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),''),to_char(created_at,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),to_char(updated_at,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),coalesce(payload->>'policy_decision_id',''),coalesce(payload->>'observation_id',''),coalesce(payload->>'evidence_version','')`

func scanBehaviorReportOutbox(scanner interface{ Scan(...any) error }) (BehaviorReportOutboxRow, error) {
	var row BehaviorReportOutboxRow
	err := scanner.Scan(&row.ReportID, &row.IdempotencyKey, &row.ChannelID, &row.EventType, &row.SubjectType, &row.SubjectID, &row.AccountID, &row.IP, &row.Target, &row.TargetType, &row.OccurredAt, &row.Status, &row.Attempts, &row.NextAttemptAt, &row.LastError, &row.HTTPStatus, &row.RemoteID, &row.SentAt, &row.CreatedAt, &row.UpdatedAt, &row.PolicyDecisionID, &row.ObservationID, &row.EvidenceVersion)
	return row, err
}

// ClaimBehaviorReportBatch leases up to batchSize due rows for one channel.
func (s *PostgresStore) ClaimBehaviorReportBatch(ctx context.Context, channelID string, batchSize int) ([]BehaviorReportOutboxRow, error) {
	if batchSize <= 0 {
		batchSize = behaviorreport.DefaultBatchSize
	}
	sqlText := `UPDATE behavior_report_outbox SET status='sending',attempts=attempts+1,lease_until=now()+interval '60 seconds',updated_at=now() WHERE report_id IN (SELECT report_id FROM behavior_report_outbox WHERE channel_id=$1 AND ((status='queued' AND (next_attempt_at IS NULL OR next_attempt_at<=now())) OR (status='sending' AND lease_until<now())) ORDER BY occurred_at,report_id FOR UPDATE SKIP LOCKED LIMIT $2) RETURNING ` + behaviorReportOutboxColumns
	rows, err := s.db.QueryContext(ctx, sqlText, channelID, batchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []BehaviorReportOutboxRow{}
	for rows.Next() {
		row, err := scanBehaviorReportOutbox(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, row)
	}
	return items, rows.Err()
}

func (s *PostgresStore) MarkBehaviorReportSent(ctx context.Context, row BehaviorReportOutboxRow, httpStatus int, remoteID string) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE behavior_report_outbox SET status='sent',lease_until=NULL,last_error='',http_status=$2,remote_id=$3,next_attempt_at=NULL,sent_at=now(),updated_at=now() WHERE report_id=$1`, row.ReportID, httpStatus, remoteID); err != nil {
		return err
	}
	return s.recordBehaviorReportAttempt(ctx, row, "sent", httpStatus, remoteID, "")
}

func (s *PostgresStore) MarkBehaviorReportFailed(ctx context.Context, row BehaviorReportOutboxRow, httpStatus int, message string) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE behavior_report_outbox SET status='failed',lease_until=NULL,last_error=$2,http_status=$3,next_attempt_at=NULL,updated_at=now() WHERE report_id=$1`, row.ReportID, message, httpStatus); err != nil {
		return err
	}
	return s.recordBehaviorReportAttempt(ctx, row, "failed", httpStatus, "", message)
}

func (s *PostgresStore) MarkBehaviorReportRetry(ctx context.Context, row BehaviorReportOutboxRow, httpStatus int, message string) error {
	next := time.Now().UTC().Add(behaviorreport.Backoff(row.Attempts))
	if _, err := s.db.ExecContext(ctx, `UPDATE behavior_report_outbox SET status='queued',lease_until=NULL,last_error=$2,http_status=$3,next_attempt_at=$4,updated_at=now() WHERE report_id=$1`, row.ReportID, message, httpStatus, next); err != nil {
		return err
	}
	return s.recordBehaviorReportAttempt(ctx, row, "failed", httpStatus, "", message)
}

func (s *PostgresStore) recordBehaviorReportAttempt(ctx context.Context, row BehaviorReportOutboxRow, status string, httpStatus int, remoteID, message string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO behavior_report_attempts(attempt_id,report_id,attempt,status,http_status,remote_id,error,started_at,finished_at) VALUES($1,$2,$3,$4,$5,$6,$7,now(),now()) ON CONFLICT(attempt_id) DO NOTHING`,
		"attempt-"+shortStoreToken(12), row.ReportID, row.Attempts, status, httpStatus, remoteID, message)
	return err
}

func (s *PostgresStore) ListBehaviorReportOutbox(ctx context.Context, status string, limit, offset int) ([]BehaviorReportOutboxRow, int, error) {
	where := ""
	args := []any{}
	if status != "" {
		args = append(args, status)
		where = " WHERE status=$1"
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM behavior_report_outbox`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, `SELECT `+behaviorReportOutboxColumns+` FROM behavior_report_outbox`+where+fmt.Sprintf(` ORDER BY occurred_at DESC,report_id LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := []BehaviorReportOutboxRow{}
	for rows.Next() {
		row, err := scanBehaviorReportOutbox(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, row)
	}
	return items, total, rows.Err()
}

func (s *PostgresStore) GetBehaviorReportOutbox(ctx context.Context, id string) (BehaviorReportOutboxRow, []BehaviorReportAttempt, error) {
	row, err := scanBehaviorReportOutbox(s.db.QueryRowContext(ctx, `SELECT `+behaviorReportOutboxColumns+` FROM behavior_report_outbox WHERE report_id=$1`, id))
	if err != nil {
		return BehaviorReportOutboxRow{}, nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT attempt_id,report_id,attempt,status,http_status,remote_id,error,to_char(started_at,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),to_char(finished_at,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') FROM behavior_report_attempts WHERE report_id=$1 ORDER BY attempt`, id)
	if err != nil {
		return BehaviorReportOutboxRow{}, nil, err
	}
	defer rows.Close()
	attempts := []BehaviorReportAttempt{}
	for rows.Next() {
		var item BehaviorReportAttempt
		if err := rows.Scan(&item.AttemptID, &item.ReportID, &item.Attempt, &item.Status, &item.HTTPStatus, &item.RemoteID, &item.Error, &item.StartedAt, &item.FinishedAt); err != nil {
			return BehaviorReportOutboxRow{}, nil, err
		}
		attempts = append(attempts, item)
	}
	return row, attempts, rows.Err()
}

func (s *PostgresStore) RequeueBehaviorReport(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE behavior_report_outbox SET status='queued',next_attempt_at=now(),lease_until=NULL,last_error='',updated_at=now() WHERE report_id=$1 AND status IN ('failed','cancelled')`, id)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *PostgresStore) CancelBehaviorReport(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE behavior_report_outbox SET status='cancelled',lease_until=NULL,updated_at=now() WHERE report_id=$1 AND status IN ('queued','sending','failed')`, id)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func shortStoreToken(size int) string {
	buffer := make([]byte, (size+1)/2)
	if _, err := rand.Read(buffer); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(buffer)[:size]
}
