package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/notify"
	"proxy-sentinel/internal/store"
)

// notificationManager owns notification configuration and the durable delivery
// outbox. Delivery state lives only here: an enforcement action succeeding means
// "accepted for delivery", never "delivered".
type notificationManager struct {
	db *sql.DB
}

func newNotificationManager(db *sql.DB) *notificationManager {
	return &notificationManager{db: db}
}

type notificationOutboxRow struct {
	NotificationID string            `json:"notification_id"`
	IdempotencyKey string            `json:"idempotency_key"`
	AccountID      string            `json:"account_id"`
	Template       string            `json:"template"`
	Parameters     map[string]string `json:"parameters"`
	Status         string            `json:"status"`
	ChannelID      string            `json:"channel_id"`
	Attempts       int               `json:"attempts"`
	NextAttemptAt  string            `json:"next_attempt_at,omitempty"`
	LastError      string            `json:"last_error,omitempty"`
	RemoteID       string            `json:"remote_id,omitempty"`
	SentAt         string            `json:"sent_at,omitempty"`
	CreatedAt      string            `json:"created_at"`
	UpdatedAt      string            `json:"updated_at"`
}

type notificationAttempt struct {
	AttemptID      string `json:"attempt_id"`
	NotificationID string `json:"notification_id"`
	Attempt        int    `json:"attempt"`
	Status         string `json:"status"`
	HTTPStatus     int    `json:"http_status"`
	RemoteID       string `json:"remote_id,omitempty"`
	Error          string `json:"error,omitempty"`
	StartedAt      string `json:"started_at"`
	FinishedAt     string `json:"finished_at"`
}

const notificationOutboxColumns = `notification_id,idempotency_key,account_id,template,parameters,status,channel_id,attempts,coalesce(to_char(next_attempt_at,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),''),last_error,remote_id,coalesce(to_char(sent_at,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),''),to_char(created_at,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),to_char(updated_at,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')`

func scanNotificationOutbox(scanner interface{ Scan(...any) error }) (notificationOutboxRow, error) {
	var row notificationOutboxRow
	var raw []byte
	if err := scanner.Scan(&row.NotificationID, &row.IdempotencyKey, &row.AccountID, &row.Template, &raw, &row.Status, &row.ChannelID, &row.Attempts, &row.NextAttemptAt, &row.LastError, &row.RemoteID, &row.SentAt, &row.CreatedAt, &row.UpdatedAt); err != nil {
		return notificationOutboxRow{}, err
	}
	row.Parameters = map[string]string{}
	if len(raw) > 0 {
		decoded := map[string]any{}
		if err := json.Unmarshal(raw, &decoded); err == nil {
			for key, value := range decoded {
				if text, ok := value.(string); ok {
					row.Parameters[key] = text
				}
			}
		}
	}
	return row, nil
}

// --- templates ---

func (m *notificationManager) listTemplates(ctx context.Context) ([]notify.Template, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT template_id,name,channel_type,subject,body,variables,enabled,revision FROM notification_templates ORDER BY name,template_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []notify.Template{}
	for rows.Next() {
		var item notify.Template
		var raw []byte
		if err := rows.Scan(&item.TemplateID, &item.Name, &item.ChannelType, &item.Subject, &item.Body, &raw, &item.Enabled, &item.Revision); err != nil {
			return nil, err
		}
		item.Variables = []string{}
		_ = json.Unmarshal(raw, &item.Variables)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (m *notificationManager) getTemplate(ctx context.Context, id string) (notify.Template, error) {
	var item notify.Template
	var raw []byte
	err := m.db.QueryRowContext(ctx, `SELECT template_id,name,channel_type,subject,body,variables,enabled,revision FROM notification_templates WHERE template_id=$1`, id).
		Scan(&item.TemplateID, &item.Name, &item.ChannelType, &item.Subject, &item.Body, &raw, &item.Enabled, &item.Revision)
	if err != nil {
		return notify.Template{}, err
	}
	item.Variables = []string{}
	_ = json.Unmarshal(raw, &item.Variables)
	return item, nil
}

func (m *notificationManager) upsertTemplate(ctx context.Context, item notify.Template, actor string, creating bool) (notify.Template, error) {
	if err := notify.ValidateTemplate(&item); err != nil {
		return notify.Template{}, err
	}
	variables, err := json.Marshal(item.Variables)
	if err != nil {
		return notify.Template{}, err
	}
	if creating {
		_, err = m.db.ExecContext(ctx, `INSERT INTO notification_templates(template_id,name,channel_type,subject,body,variables,enabled,revision,created_by,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$8)`,
			item.TemplateID, item.Name, item.ChannelType, item.Subject, item.Body, variables, item.Enabled, actor)
	} else {
		result, execErr := m.db.ExecContext(ctx, `UPDATE notification_templates SET name=$2,channel_type=$3,subject=$4,body=$5,variables=$6,enabled=$7,revision=revision+1,updated_by=$8,updated_at=now() WHERE template_id=$1`,
			item.TemplateID, item.Name, item.ChannelType, item.Subject, item.Body, variables, item.Enabled, actor)
		if execErr == nil {
			if affected, _ := result.RowsAffected(); affected == 0 {
				return notify.Template{}, sql.ErrNoRows
			}
		}
		err = execErr
	}
	if err != nil {
		return notify.Template{}, err
	}
	return m.getTemplate(ctx, item.TemplateID)
}

func (m *notificationManager) deleteTemplate(ctx context.Context, id string) error {
	result, err := m.db.ExecContext(ctx, `DELETE FROM notification_templates WHERE template_id=$1`, id)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// --- channels ---

func (m *notificationManager) listChannels(ctx context.Context) ([]notify.Channel, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT channel_id,name,channel_type,endpoint_url,token_endpoint,token_scope,auth_type,encrypted_secret,config,is_default,enabled,revision FROM notification_channels ORDER BY is_default DESC,name,channel_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []notify.Channel{}
	for rows.Next() {
		item, err := scanNotificationChannel(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func scanNotificationChannel(scanner interface{ Scan(...any) error }) (notify.Channel, error) {
	var item notify.Channel
	var config []byte
	var encrypted string
	if err := scanner.Scan(&item.ChannelID, &item.Name, &item.ChannelType, &item.EndpointURL, &item.TokenEndpoint, &item.TokenScope, &item.AuthType, &encrypted, &config, &item.IsDefault, &item.Enabled, &item.Revision); err != nil {
		return notify.Channel{}, err
	}
	item.EncryptedSecret = encrypted
	item.HasSecret = encrypted != ""
	if len(config) > 0 {
		_ = json.Unmarshal(config, &item.Config)
	}
	return item, nil
}

func (m *notificationManager) getChannel(ctx context.Context, id string) (notify.Channel, error) {
	row := m.db.QueryRowContext(ctx, `SELECT channel_id,name,channel_type,endpoint_url,token_endpoint,token_scope,auth_type,encrypted_secret,config,is_default,enabled,revision FROM notification_channels WHERE channel_id=$1`, id)
	return scanNotificationChannel(row)
}

func (m *notificationManager) defaultChannel(ctx context.Context) (notify.Channel, error) {
	row := m.db.QueryRowContext(ctx, `SELECT channel_id,name,channel_type,endpoint_url,token_endpoint,token_scope,auth_type,encrypted_secret,config,is_default,enabled,revision FROM notification_channels WHERE is_default AND enabled`)
	return scanNotificationChannel(row)
}

func (m *notificationManager) upsertChannel(ctx context.Context, item notify.Channel, encryptedSecret string, actor string, creating bool) (notify.Channel, error) {
	if err := notify.ValidateChannel(&item); err != nil {
		return notify.Channel{}, err
	}
	config, err := json.Marshal(item.Config)
	if err != nil {
		return notify.Channel{}, err
	}
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return notify.Channel{}, err
	}
	defer tx.Rollback()
	if item.IsDefault {
		// Clearing the previous default first keeps the partial unique index satisfiable.
		if _, err = tx.ExecContext(ctx, `UPDATE notification_channels SET is_default=false WHERE is_default AND channel_id<>$1`, item.ChannelID); err != nil {
			return notify.Channel{}, err
		}
	}
	if creating {
		_, err = tx.ExecContext(ctx, `INSERT INTO notification_channels(channel_id,name,channel_type,endpoint_url,token_endpoint,token_scope,auth_type,encrypted_secret,config,is_default,enabled,revision,created_by,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,1,$12,$12)`,
			item.ChannelID, item.Name, item.ChannelType, item.EndpointURL, item.TokenEndpoint, item.TokenScope, item.AuthType, encryptedSecret, config, item.IsDefault, item.Enabled, actor)
	} else {
		result, execErr := tx.ExecContext(ctx, `UPDATE notification_channels SET name=$2,channel_type=$3,endpoint_url=$4,token_endpoint=$5,token_scope=$6,auth_type=$7,encrypted_secret=$8,config=$9,is_default=$10,enabled=$11,revision=revision+1,updated_by=$12,updated_at=now() WHERE channel_id=$1`,
			item.ChannelID, item.Name, item.ChannelType, item.EndpointURL, item.TokenEndpoint, item.TokenScope, item.AuthType, encryptedSecret, config, item.IsDefault, item.Enabled, actor)
		if execErr == nil {
			if affected, _ := result.RowsAffected(); affected == 0 {
				return notify.Channel{}, sql.ErrNoRows
			}
		}
		err = execErr
	}
	if err != nil {
		return notify.Channel{}, err
	}
	if err = tx.Commit(); err != nil {
		return notify.Channel{}, err
	}
	return m.getChannel(ctx, item.ChannelID)
}

func (m *notificationManager) deleteChannel(ctx context.Context, id string) error {
	result, err := m.db.ExecContext(ctx, `DELETE FROM notification_channels WHERE channel_id=$1`, id)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// --- outbox ---

func (m *notificationManager) enqueue(ctx context.Context, notificationID, idempotencyKey, accountID, template string, parameters map[string]string, channelID string) error {
	raw, err := json.Marshal(parameters)
	if err != nil {
		return err
	}
	_, err = m.db.ExecContext(ctx, `INSERT INTO notification_outbox(notification_id,idempotency_key,account_id,template,parameters,channel_id) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(idempotency_key) DO NOTHING`,
		notificationID, idempotencyKey, accountID, template, raw, channelID)
	return err
}

// failUnroutable records a notification that cannot be delivered because no
// channel resolves. It must never be left queued: "queued" would be read as
// "will be delivered".
func (m *notificationManager) failUnroutable(ctx context.Context, notificationID, idempotencyKey, accountID, template string, parameters map[string]string, reason string) error {
	raw, err := json.Marshal(parameters)
	if err != nil {
		return err
	}
	_, err = m.db.ExecContext(ctx, `INSERT INTO notification_outbox(notification_id,idempotency_key,account_id,template,parameters,status,last_error) VALUES($1,$2,$3,$4,$5,'failed',$6) ON CONFLICT(idempotency_key) DO NOTHING`,
		notificationID, idempotencyKey, accountID, template, raw, reason)
	return err
}

func (m *notificationManager) listOutbox(ctx context.Context, status string, limit, offset int) ([]notificationOutboxRow, int, error) {
	where := ""
	args := []any{}
	if status != "" {
		where = " WHERE status=$1"
		args = append(args, status)
	}
	var total int
	if err := m.db.QueryRowContext(ctx, `SELECT count(*) FROM notification_outbox`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	rows, err := m.db.QueryContext(ctx, `SELECT `+notificationOutboxColumns+` FROM notification_outbox`+where+fmt.Sprintf(` ORDER BY created_at DESC,notification_id LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := []notificationOutboxRow{}
	for rows.Next() {
		row, err := scanNotificationOutbox(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, row)
	}
	return items, total, rows.Err()
}

func (m *notificationManager) getOutbox(ctx context.Context, id string) (notificationOutboxRow, []notificationAttempt, error) {
	row, err := scanNotificationOutbox(m.db.QueryRowContext(ctx, `SELECT `+notificationOutboxColumns+` FROM notification_outbox WHERE notification_id=$1`, id))
	if err != nil {
		return notificationOutboxRow{}, nil, err
	}
	rows, err := m.db.QueryContext(ctx, `SELECT attempt_id,notification_id,attempt,status,http_status,remote_id,error,to_char(started_at,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),to_char(finished_at,'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') FROM notification_delivery_attempts WHERE notification_id=$1 ORDER BY attempt`, id)
	if err != nil {
		return notificationOutboxRow{}, nil, err
	}
	defer rows.Close()
	attempts := []notificationAttempt{}
	for rows.Next() {
		var item notificationAttempt
		if err := rows.Scan(&item.AttemptID, &item.NotificationID, &item.Attempt, &item.Status, &item.HTTPStatus, &item.RemoteID, &item.Error, &item.StartedAt, &item.FinishedAt); err != nil {
			return notificationOutboxRow{}, nil, err
		}
		attempts = append(attempts, item)
	}
	return row, attempts, rows.Err()
}

func (m *notificationManager) requeue(ctx context.Context, id string) error {
	result, err := m.db.ExecContext(ctx, `UPDATE notification_outbox SET status='queued',next_attempt_at=now(),lease_until=NULL,last_error='',updated_at=now() WHERE notification_id=$1 AND status IN ('failed','cancelled')`, id)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (m *notificationManager) cancel(ctx context.Context, id string) error {
	result, err := m.db.ExecContext(ctx, `UPDATE notification_outbox SET status='cancelled',lease_until=NULL,updated_at=now() WHERE notification_id=$1 AND status IN ('queued','sending','failed')`, id)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// claimDue leases one due row. attempts is incremented at claim time so a crash
// still consumes retry budget and a poisoned row cannot spin forever.
func (m *notificationManager) claimDue(ctx context.Context) (notificationOutboxRow, bool, error) {
	row, err := scanNotificationOutbox(m.db.QueryRowContext(ctx, `UPDATE notification_outbox SET status='sending',attempts=attempts+1,lease_until=now()+interval '60 seconds',updated_at=now() WHERE notification_id=(SELECT notification_id FROM notification_outbox WHERE (status='queued' AND (next_attempt_at IS NULL OR next_attempt_at<=now())) OR (status='sending' AND lease_until<now()) ORDER BY created_at,notification_id FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING `+notificationOutboxColumns))
	if errors.Is(err, sql.ErrNoRows) {
		return notificationOutboxRow{}, false, nil
	}
	if err != nil {
		return notificationOutboxRow{}, false, err
	}
	return row, true, nil
}

func (m *notificationManager) markSent(ctx context.Context, row notificationOutboxRow, payload map[string]any, httpStatus int, remoteID string) error {
	raw, _ := json.Marshal(payload)
	if _, err := m.db.ExecContext(ctx, `UPDATE notification_outbox SET status='sent',lease_until=NULL,last_error='',rendered_payload=$2,remote_id=$3,next_attempt_at=NULL,sent_at=now(),updated_at=now() WHERE notification_id=$1`, row.NotificationID, raw, remoteID); err != nil {
		return err
	}
	return m.recordAttempt(ctx, row, "sent", httpStatus, remoteID, "")
}

func (m *notificationManager) markFailed(ctx context.Context, row notificationOutboxRow, payload map[string]any, httpStatus int, message string) error {
	raw, _ := json.Marshal(payload)
	if _, err := m.db.ExecContext(ctx, `UPDATE notification_outbox SET status='failed',lease_until=NULL,last_error=$2,rendered_payload=$3,next_attempt_at=NULL,updated_at=now() WHERE notification_id=$1`, row.NotificationID, message, raw); err != nil {
		return err
	}
	return m.recordAttempt(ctx, row, "failed", httpStatus, "", message)
}

// markRetry returns the row to the queue. The failed attempt is still recorded,
// so the delivery history shows every try rather than only the last one.
func (m *notificationManager) markRetry(ctx context.Context, row notificationOutboxRow, payload map[string]any, httpStatus int, message string) error {
	raw, _ := json.Marshal(payload)
	next := time.Now().UTC().Add(notify.Backoff(row.Attempts))
	if _, err := m.db.ExecContext(ctx, `UPDATE notification_outbox SET status='queued',lease_until=NULL,last_error=$2,rendered_payload=$3,next_attempt_at=$4,updated_at=now() WHERE notification_id=$1`, row.NotificationID, message, raw, next); err != nil {
		return err
	}
	return m.recordAttempt(ctx, row, "failed", httpStatus, "", message)
}

func (m *notificationManager) recordAttempt(ctx context.Context, row notificationOutboxRow, status string, httpStatus int, remoteID, message string) error {
	_, err := m.db.ExecContext(ctx, `INSERT INTO notification_delivery_attempts(attempt_id,notification_id,attempt,status,http_status,remote_id,error,started_at,finished_at) VALUES($1,$2,$3,$4,$5,$6,$7,now(),now()) ON CONFLICT(attempt_id) DO NOTHING`,
		"attempt-"+shortToken(12), row.NotificationID, row.Attempts, status, httpStatus, remoteID, message)
	return err
}

// --- handlers ---

type notificationTemplateRequest struct {
	TemplateID  string   `json:"template_id"`
	Name        string   `json:"name"`
	ChannelType string   `json:"channel_type"`
	Subject     string   `json:"subject"`
	Body        string   `json:"body"`
	Enabled     *bool    `json:"enabled"`
	Variables   []string `json:"variables"`
}

type notificationChannelRequest struct {
	ChannelID     string               `json:"channel_id"`
	Name          string               `json:"name"`
	ChannelType   string               `json:"channel_type"`
	EndpointURL   string               `json:"endpoint_url"`
	TokenEndpoint string               `json:"token_endpoint"`
	TokenScope    string               `json:"token_scope"`
	AuthType      string               `json:"auth_type"`
	Secret        string               `json:"secret"`
	Config        notify.ChannelConfig `json:"config"`
	IsDefault     bool                 `json:"is_default"`
	Enabled       bool                 `json:"enabled"`
}

type notificationTestRequest struct {
	ChannelID  string            `json:"channel_id"`
	TemplateID string            `json:"template_id"`
	Variables  map[string]string `json:"variables"`
}

func (s *Server) handleNotifications(w http.ResponseWriter, r *http.Request, path string) {
	rest := strings.Trim(strings.TrimPrefix(path, "/notifications"), "/")
	if s.operations.db == nil {
		writeError(w, http.StatusServiceUnavailable, "notifications_unavailable", "通知配置存储不可用")
		return
	}
	m := s.notifications
	switch {
	case rest == "templates":
		s.handleNotificationTemplates(w, r, m)
	case strings.HasPrefix(rest, "templates/"):
		s.handleNotificationTemplate(w, r, m, strings.TrimPrefix(rest, "templates/"))
	case rest == "channels":
		s.handleNotificationChannels(w, r, m)
	case strings.HasPrefix(rest, "channels/"):
		s.handleNotificationChannel(w, r, m, strings.TrimPrefix(rest, "channels/"))
	case rest == "outbox":
		s.handleNotificationOutbox(w, r, m)
	case strings.HasPrefix(rest, "outbox/"):
		s.handleNotificationOutboxItem(w, r, m, strings.TrimPrefix(rest, "outbox/"))
	case rest == "test":
		s.handleNotificationTest(w, r, m)
	default:
		writeError(w, http.StatusNotFound, "not_found", "接口不存在")
	}
}

func (s *Server) handleNotificationTemplates(w http.ResponseWriter, r *http.Request, m *notificationManager) {
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	switch r.Method {
	case http.MethodGet:
		items, err := m.listTemplates(ctx)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "notifications_unavailable", "通知模板读取失败")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "allowed_variables": notify.AllowedVariables})
	case http.MethodPost:
		if s.readOnly {
			writeError(w, http.StatusForbidden, "read_only", "只读模式禁止修改通知模板")
			return
		}
		var request notificationTemplateRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "bad_notification_template", "请求格式不正确")
			return
		}
		item := notify.Template{TemplateID: request.TemplateID, Name: request.Name, ChannelType: request.ChannelType, Subject: request.Subject, Body: request.Body, Enabled: request.Enabled == nil || *request.Enabled}
		saved, err := m.upsertTemplate(ctx, item, sessionFromContext(r.Context()).User.ID, true)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_notification_template", err.Error())
			return
		}
		s.appendAudit(ctx, "notification.template_created", saved.TemplateID, "succeeded")
		writeJSON(w, http.StatusOK, saved)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "该接口不支持此操作")
	}
}

func (s *Server) handleNotificationTemplate(w http.ResponseWriter, r *http.Request, m *notificationManager, id string) {
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	id = strings.TrimSpace(id)
	if id == "" {
		writeError(w, http.StatusNotFound, "not_found", "接口不存在")
		return
	}
	switch r.Method {
	case http.MethodGet:
		item, err := m.getTemplate(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "notification_template_not_found", "通知模板不存在")
			return
		}
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "notifications_unavailable", "通知模板读取失败")
			return
		}
		writeJSON(w, http.StatusOK, item)
	case http.MethodPut:
		if s.readOnly {
			writeError(w, http.StatusForbidden, "read_only", "只读模式禁止修改通知模板")
			return
		}
		var request notificationTemplateRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "bad_notification_template", "请求格式不正确")
			return
		}
		existing, err := m.getTemplate(ctx, id)
		if err != nil {
			writeError(w, http.StatusNotFound, "notification_template_not_found", "通知模板不存在")
			return
		}
		existing.Name = request.Name
		existing.ChannelType = request.ChannelType
		existing.Subject = request.Subject
		existing.Body = request.Body
		if request.Enabled != nil {
			existing.Enabled = *request.Enabled
		}
		saved, err := m.upsertTemplate(ctx, existing, sessionFromContext(r.Context()).User.ID, false)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_notification_template", err.Error())
			return
		}
		s.appendAudit(ctx, "notification.template_updated", saved.TemplateID, "succeeded")
		writeJSON(w, http.StatusOK, saved)
	case http.MethodDelete:
		if s.readOnly {
			writeError(w, http.StatusForbidden, "read_only", "只读模式禁止删除通知模板")
			return
		}
		if err := m.deleteTemplate(ctx, id); err != nil {
			writeError(w, http.StatusNotFound, "notification_template_not_found", "通知模板不存在")
			return
		}
		s.appendAudit(ctx, "notification.template_deleted", id, "succeeded")
		writeJSON(w, http.StatusOK, map[string]any{"template_id": id, "deleted": true})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "该接口不支持此操作")
	}
}

func (s *Server) handleNotificationChannels(w http.ResponseWriter, r *http.Request, m *notificationManager) {
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	switch r.Method {
	case http.MethodGet:
		items, err := m.listChannels(ctx)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "notifications_unavailable", "通知通道读取失败")
			return
		}
		redacted := make([]notify.Channel, 0, len(items))
		for _, item := range items {
			redacted = append(redacted, item.Redacted())
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": redacted})
	case http.MethodPost:
		if s.readOnly {
			writeError(w, http.StatusForbidden, "read_only", "只读模式禁止修改通知通道")
			return
		}
		var request notificationChannelRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "bad_notification_channel", "请求格式不正确")
			return
		}
		item := notify.Channel{ChannelID: request.ChannelID, Name: request.Name, ChannelType: request.ChannelType, EndpointURL: request.EndpointURL, TokenEndpoint: request.TokenEndpoint, TokenScope: request.TokenScope, AuthType: request.AuthType, Config: request.Config, IsDefault: request.IsDefault, Enabled: request.Enabled}
		if err := s.applyNotificationSecret(&item, request.Secret, false); err != nil {
			writeError(w, http.StatusBadRequest, "bad_notification_channel", err.Error())
			return
		}
		saved, err := m.upsertChannel(ctx, item, item.EncryptedSecret, sessionFromContext(r.Context()).User.ID, true)
		if err != nil {
			if isUniqueViolation(err) {
				writeError(w, http.StatusConflict, "notification_channel_exists", "通道标识已存在")
				return
			}
			writeError(w, http.StatusBadRequest, "bad_notification_channel", err.Error())
			return
		}
		s.appendAudit(ctx, "notification.channel_created", saved.ChannelID, "succeeded")
		writeJSON(w, http.StatusOK, saved.Redacted())
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "该接口不支持此操作")
	}
}

func (s *Server) handleNotificationChannel(w http.ResponseWriter, r *http.Request, m *notificationManager, id string) {
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	if strings.HasSuffix(id, "/test") {
		s.handleNotificationChannelTest(w, r, m, strings.TrimSuffix(id, "/test"))
		return
	}
	id = strings.TrimSpace(id)
	if id == "" {
		writeError(w, http.StatusNotFound, "not_found", "接口不存在")
		return
	}
	switch r.Method {
	case http.MethodGet:
		item, err := m.getChannel(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "notification_channel_not_found", "通知通道不存在")
			return
		}
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "notifications_unavailable", "通知通道读取失败")
			return
		}
		writeJSON(w, http.StatusOK, item.Redacted())
	case http.MethodPut:
		if s.readOnly {
			writeError(w, http.StatusForbidden, "read_only", "只读模式禁止修改通知通道")
			return
		}
		var request notificationChannelRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "bad_notification_channel", "请求格式不正确")
			return
		}
		existing, err := m.getChannel(ctx, id)
		if err != nil {
			writeError(w, http.StatusNotFound, "notification_channel_not_found", "通知通道不存在")
			return
		}
		existing.Name = request.Name
		existing.ChannelType = request.ChannelType
		existing.EndpointURL = request.EndpointURL
		existing.TokenEndpoint = request.TokenEndpoint
		existing.TokenScope = request.TokenScope
		existing.AuthType = request.AuthType
		existing.Config = request.Config
		existing.IsDefault = request.IsDefault
		existing.Enabled = request.Enabled
		if err := s.applyNotificationSecret(&existing, request.Secret, true); err != nil {
			writeError(w, http.StatusBadRequest, "bad_notification_channel", err.Error())
			return
		}
		saved, err := m.upsertChannel(ctx, existing, existing.EncryptedSecret, sessionFromContext(r.Context()).User.ID, false)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_notification_channel", err.Error())
			return
		}
		s.appendAudit(ctx, "notification.channel_updated", saved.ChannelID, "succeeded")
		writeJSON(w, http.StatusOK, saved.Redacted())
	case http.MethodDelete:
		if s.readOnly {
			writeError(w, http.StatusForbidden, "read_only", "只读模式禁止删除通知通道")
			return
		}
		if err := m.deleteChannel(ctx, id); err != nil {
			writeError(w, http.StatusNotFound, "notification_channel_not_found", "通知通道不存在")
			return
		}
		s.appendAudit(ctx, "notification.channel_deleted", id, "succeeded")
		writeJSON(w, http.StatusOK, map[string]any{"channel_id": id, "deleted": true})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "该接口不支持此操作")
	}
}

// applyNotificationSecret keeps the stored secret when the request omits it, so
// editing an unrelated field never silently clears credentials.
func (s *Server) applyNotificationSecret(item *notify.Channel, secret string, keepExisting bool) error {
	switch {
	case secret == "-":
		item.EncryptedSecret = ""
		item.Secret = ""
	case strings.TrimSpace(secret) != "":
		sealed, err := s.encryptConnectorSecret(secret)
		if err != nil {
			return err
		}
		item.EncryptedSecret = sealed
		item.Secret = secret
	case keepExisting:
		// retain
	default:
		item.EncryptedSecret = ""
	}
	return nil
}

func (s *Server) handleNotificationChannelTest(w http.ResponseWriter, r *http.Request, m *notificationManager, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "该接口不支持此操作")
		return
	}
	var request notificationTestRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "bad_notification_test", "请求格式不正确")
		return
	}
	request.ChannelID = id
	s.runNotificationTest(w, r, m, request)
}

func (s *Server) handleNotificationTest(w http.ResponseWriter, r *http.Request, m *notificationManager) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "该接口不支持此操作")
		return
	}
	var request notificationTestRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "bad_notification_test", "请求格式不正确")
		return
	}
	s.runNotificationTest(w, r, m, request)
}

func (s *Server) handleNotificationOutbox(w http.ResponseWriter, r *http.Request, m *notificationManager) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "该接口不支持此操作")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	limit, err := boundedInt(r.URL.Query().Get("limit"), 20, 1, 100)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_page", "分页参数不正确")
		return
	}
	cursor, err := cursorOffset(r.URL.Query().Get("cursor"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_page", "分页参数不正确")
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	items, total, err := m.listOutbox(ctx, status, limit, cursor)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "notifications_unavailable", "通知投递记录读取失败")
		return
	}
	page := store.Page{Limit: limit, Total: total}
	if cursor+limit < total {
		next := strconv.Itoa(cursor + limit)
		page.NextCursor = &next
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "page": page})
}

func (s *Server) handleNotificationOutboxItem(w http.ResponseWriter, r *http.Request, m *notificationManager, rest string) {
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	parts := strings.SplitN(strings.Trim(rest, "/"), "/", 2)
	id := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	switch {
	case r.Method == http.MethodGet && action == "":
		row, attempts, err := m.getOutbox(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "notification_not_found", "通知记录不存在")
			return
		}
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "notifications_unavailable", "通知记录读取失败")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"notification": row, "attempts": attempts})
	case r.Method == http.MethodPost && action == "retry":
		if s.readOnly {
			writeError(w, http.StatusForbidden, "read_only", "只读模式禁止重试投递")
			return
		}
		if err := m.requeue(ctx, id); err != nil {
			writeError(w, http.StatusConflict, "notification_not_retryable", "该通知当前不可重试")
			return
		}
		s.appendAudit(ctx, "notification.retry_requested", id, "succeeded")
		writeJSON(w, http.StatusOK, map[string]any{"notification_id": id, "status": "queued"})
	case r.Method == http.MethodPost && action == "cancel":
		if s.readOnly {
			writeError(w, http.StatusForbidden, "read_only", "只读模式禁止取消投递")
			return
		}
		if err := m.cancel(ctx, id); err != nil {
			writeError(w, http.StatusConflict, "notification_not_cancellable", "该通知当前不可取消")
			return
		}
		s.appendAudit(ctx, "notification.cancelled", id, "succeeded")
		writeJSON(w, http.StatusOK, map[string]any{"notification_id": id, "status": "cancelled"})
	default:
		writeError(w, http.StatusNotFound, "not_found", "接口不存在")
	}
}

func (s *Server) runNotificationTest(w http.ResponseWriter, r *http.Request, m *notificationManager, request notificationTestRequest) {
	if s.observeTestRequest(w, r, "拟通知测试", request.ChannelID) { return }
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	channel, err := s.resolveNotificationChannel(ctx, m, request.ChannelID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "notification_channel_unavailable", err.Error())
		return
	}
	subject, body := "通知通道测试", "这是一条通道连通性测试消息。"
	templateID := ""
	if strings.TrimSpace(request.TemplateID) != "" {
		template, err := m.getTemplate(ctx, request.TemplateID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "notification_template_not_found", "通知模板不存在")
			return
		}
		renderedSubject, renderedBody, _ := template.Render(request.Variables)
		subject, body = renderedSubject, renderedBody
		templateID = template.TemplateID
	}
	secret, err := s.decryptConnectorSecret(channel.EncryptedSecret)
	if err != nil {
		writeError(w, http.StatusConflict, "notification_secret_unavailable", "通知通道密钥不可用")
		return
	}
	sender, err := notify.NewSender(channel)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_notification_channel", err.Error())
		return
	}
	result, sendErr := sender.Send(ctx, notify.Request{Channel: channel, Secret: secret, Subject: subject, Body: body, Variables: request.Variables, IdempotencyKey: "notification-test-" + shortToken(10)})
	outcome := "succeeded"
	message := ""
	if sendErr != nil {
		outcome = "failed"
		message = sendErr.Error()
	}
	s.appendAudit(ctx, "notification.test_sent", channel.ChannelID, outcome)
	payload := map[string]any{"channel_id": channel.ChannelID, "template_id": templateID, "status": outcome, "http_status": result.StatusCode}
	if message != "" {
		payload["error"] = message
	} else {
		payload["remote_id"] = result.RemoteID
	}
	writeJSON(w, http.StatusOK, payload)
}

// resolveNotificationChannel prefers the requested channel, then the configured
// default. It never falls back to an implicit endpoint.
func (s *Server) resolveNotificationChannel(ctx context.Context, m *notificationManager, channelID string) (notify.Channel, error) {
	if strings.TrimSpace(channelID) != "" {
		channel, err := m.getChannel(ctx, channelID)
		if errors.Is(err, sql.ErrNoRows) {
			return notify.Channel{}, fmt.Errorf("通知通道不存在")
		}
		if err != nil {
			return notify.Channel{}, err
		}
		if !channel.Enabled {
			return notify.Channel{}, fmt.Errorf("通知通道已停用")
		}
		return channel, nil
	}
	channel, err := m.defaultChannel(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return notify.Channel{}, fmt.Errorf("未配置通知通道")
	}
	if err != nil {
		return notify.Channel{}, err
	}
	return channel, nil
}

// startNotificationWorker drains the delivery outbox. Delivery never happens on
// the policy evaluation path.
func (s *Server) startNotificationWorker() {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			s.processNotificationOutbox(time.Now().UTC())
			<-ticker.C
		}
	}()
}

func (s *Server) processNotificationOutbox(now time.Time) {
	if violationObservationOnly() {
		s.observeQueuedNotifications()
		return
	}
	if s.notifications == nil || s.operations.db == nil {
		return
	}
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		row, found, err := s.notifications.claimDue(ctx)
		if err != nil || !found {
			cancel()
			return
		}
		s.deliverNotification(ctx, row)
		cancel()
	}
}

func (s *Server) deliverNotification(ctx context.Context, row notificationOutboxRow) {
	if violationObservationOnly() {
		s.recordOutboundObservation(ctx, "notification:"+row.NotificationID, "拟提醒", row.AccountID, map[string]any{"notification_id": row.NotificationID, "reason": "observation_only"})
		return
	}
	channel, err := s.resolveNotificationChannel(ctx, s.notifications, row.ChannelID)
	if err != nil {
		_ = s.notifications.markFailed(ctx, row, map[string]any{"account_id": row.AccountID}, 0, err.Error())
		s.appendAudit(ctx, "notification.delivery_failed", row.NotificationID, "failed")
		return
	}
	subject, body, missing := s.renderNotification(ctx, row)
	secret, err := s.decryptConnectorSecret(channel.EncryptedSecret)
	if err != nil {
		_ = s.notifications.markFailed(ctx, row, map[string]any{"account_id": row.AccountID}, 0, "通知通道密钥不可用")
		s.appendAudit(ctx, "notification.delivery_failed", row.NotificationID, "failed")
		return
	}
	sender, err := notify.NewSender(channel)
	if err != nil {
		_ = s.notifications.markFailed(ctx, row, map[string]any{"account_id": row.AccountID}, 0, err.Error())
		s.appendAudit(ctx, "notification.delivery_failed", row.NotificationID, "failed")
		return
	}
	payload := map[string]any{"account_id": row.AccountID, "subject": subject, "body": body, "channel_id": channel.ChannelID, "missing_variables": missing}
	result, sendErr := sender.Send(ctx, notify.Request{Channel: channel, Secret: secret, Subject: subject, Body: body, Variables: row.Parameters, IdempotencyKey: row.IdempotencyKey})
	if sendErr != nil {
		if notify.IsPermanent(sendErr) || row.Attempts >= notify.MaxNotificationTry {
			_ = s.notifications.markFailed(ctx, row, payload, result.StatusCode, sendErr.Error())
			s.appendAudit(ctx, "notification.delivery_failed", row.NotificationID, "failed")
			return
		}
		_ = s.notifications.markRetry(ctx, row, payload, result.StatusCode, sendErr.Error())
		s.appendAudit(ctx, "notification.delivery_retry", row.NotificationID, "queued")
		return
	}
	if len(missing) > 0 {
		payload["missing_variables"] = missing
	}
	_ = s.notifications.markSent(ctx, row, payload, result.StatusCode, result.RemoteID)
	s.appendAudit(ctx, "notification.delivered", row.NotificationID, "succeeded")
}

// renderNotification resolves the outbox template reference. A reference to an
// existing template ID is rendered through the whitelisted variables; any other
// value is treated as a literal body so legacy policies keep working.
func (s *Server) renderNotification(ctx context.Context, row notificationOutboxRow) (string, string, []string) {
	if template, err := s.notifications.getTemplate(ctx, row.Template); err == nil && template.Enabled {
		return template.Render(row.Parameters)
	}
	subject := row.Parameters["policy_name"]
	if subject == "" {
		subject = "策略通知"
	}
	return subject, row.Template, nil
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate key value")
}

// notificationVariablesLocked builds the renderable variable set for a notify
// action. Callers must hold s.operations.mu.
func (s *Server) notificationVariablesLocked(a EnforcementAction) map[string]string {
	now := time.Now().UTC()
	values := map[string]string{
		"account":          a.AccountID,
		"ip":               a.IP,
		"campus":           a.CampusID,
		"student_id":       a.AccountID,
		"occurred_at":      now.Format(time.RFC3339),
		"date":             now.Format("2006-01-02 15:04:05"),
		"policy_name":      "",
		"evidence_summary": "",
	}
	if strings.HasPrefix(a.EndpointID, "mac:") {
		values["mac"] = strings.TrimPrefix(a.EndpointID, "mac:")
	}
	if a.PolicyParameters.ExecutionID != "" {
		if execution, ok := s.operations.doc.PolicyExecutions[a.PolicyParameters.ExecutionID]; ok {
			values["policy_name"] = execution.Definition.Name
			if len(execution.EvidenceIDs) > 0 {
				values["evidence_summary"] = strconv.Itoa(len(execution.EvidenceIDs)) + " 条证据"
			}
		}
	}
	return values
}
