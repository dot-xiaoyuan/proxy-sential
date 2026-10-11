package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"proxy-sentinel/internal/behaviorreport"
	"proxy-sentinel/internal/store"
)

// behaviorReportReader is the slice of storage this feature needs. It is
// asserted from s.reader so the feature stays available in every storage mode
// that implements it and degrades to "unavailable" otherwise.
type behaviorReportReader interface {
	ListBehaviorReportChannels(context.Context) ([]store.BehaviorReportChannel, error)
	GetBehaviorReportChannel(context.Context, string) (store.BehaviorReportChannel, error)
	UpsertBehaviorReportChannel(context.Context, behaviorreport.Channel, string, string, bool) (store.BehaviorReportChannel, error)
	DeleteBehaviorReportChannel(context.Context, string) error
	ListBehaviorReportCandidates(context.Context, time.Time, int) ([]store.BehaviorReportCandidate, error)
	EnqueueBehaviorReport(context.Context, store.BehaviorReportOutboxRow) error
	ClaimBehaviorReportBatch(context.Context, string, int) ([]store.BehaviorReportOutboxRow, error)
	MarkBehaviorReportSent(context.Context, store.BehaviorReportOutboxRow, int, string) error
	MarkBehaviorReportFailed(context.Context, store.BehaviorReportOutboxRow, int, string) error
	MarkBehaviorReportRetry(context.Context, store.BehaviorReportOutboxRow, int, string) error
	ListBehaviorReportOutbox(context.Context, string, int, int) ([]store.BehaviorReportOutboxRow, int, error)
	GetBehaviorReportOutbox(context.Context, string) (store.BehaviorReportOutboxRow, []store.BehaviorReportAttempt, error)
	RequeueBehaviorReport(context.Context, string) error
	CancelBehaviorReport(context.Context, string) error
}

func (s *Server) behaviorReports() (behaviorReportReader, bool) {
	if s.reader == nil {
		return nil, false
	}
	value, ok := s.reader.(behaviorReportReader)
	return value, ok
}

type behaviorReportChannelRequest struct {
	ChannelID          string            `json:"channel_id"`
	Name               string            `json:"name"`
	EndpointURL        string            `json:"endpoint_url"`
	TokenEndpoint      string            `json:"token_endpoint"`
	TokenMethod        string            `json:"token_method"`
	TokenScope         string            `json:"token_scope"`
	AuthType           string            `json:"auth_type"`
	Secret             string            `json:"secret"`
	SourceSystemIP     string            `json:"source_system_ip"`
	SourceSystemName   string            `json:"source_system_name"`
	BatchSize          int               `json:"batch_size"`
	FlushIntervalSecs  int               `json:"flush_interval_seconds"`
	TimeoutSeconds     int               `json:"timeout_seconds"`
	TLSSkipVerify      bool              `json:"tls_skip_verify"`
	FieldMapping       map[string]string `json:"field_mapping"`
	SuccessStatusCodes []int             `json:"success_status_codes"`
	Enabled            bool              `json:"enabled"`
}

type behaviorReportTestRequest struct {
	ChannelID string `json:"channel_id"`
	EventType string `json:"event_type"`
}

func (s *Server) handleBehaviorReports(w http.ResponseWriter, r *http.Request, path string) {
	storage, ok := s.behaviorReports()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "behavior_reports_unavailable", "行为上报存储不可用")
		return
	}
	rest := strings.Trim(strings.TrimPrefix(path, "/behavior-reports"), "/")
	switch {
	case rest == "channels":
		s.handleBehaviorReportChannels(w, r, storage)
	case strings.HasPrefix(rest, "channels/"):
		s.handleBehaviorReportChannel(w, r, storage, strings.TrimPrefix(rest, "channels/"))
	case rest == "outbox":
		s.handleBehaviorReportOutbox(w, r, storage)
	case strings.HasPrefix(rest, "outbox/"):
		s.handleBehaviorReportOutboxItem(w, r, storage, strings.TrimPrefix(rest, "outbox/"))
	default:
		writeError(w, http.StatusNotFound, "not_found", "接口不存在")
	}
}

func (s *Server) handleBehaviorReportChannels(w http.ResponseWriter, r *http.Request, storage behaviorReportReader) {
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	switch r.Method {
	case http.MethodGet:
		items, err := storage.ListBehaviorReportChannels(ctx)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "behavior_reports_unavailable", "上报通道读取失败")
			return
		}
		redacted := make([]store.BehaviorReportChannel, 0, len(items))
		for _, item := range items {
			// has_secret was computed while scanning; only the sealed value is dropped.
			item.EncryptedSecret = ""
			redacted = append(redacted, item)
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": redacted, "event_types": []string{behaviorreport.EventPoisonBehavior, behaviorreport.EventProxyBehavior, behaviorreport.EventAIRelayAudit}})
	case http.MethodPost:
		if s.readOnly {
			writeError(w, http.StatusForbidden, "read_only", "只读模式禁止修改上报通道")
			return
		}
		var request behaviorReportChannelRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "bad_behavior_report_channel", "请求格式不正确")
			return
		}
		channel, encrypted, err := s.behaviorReportChannelFromRequest(request, "")
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_behavior_report_channel", err.Error())
			return
		}
		saved, err := storage.UpsertBehaviorReportChannel(ctx, channel, encrypted, sessionFromContext(ctx).User.ID, true)
		if err != nil {
			if strings.Contains(err.Error(), "duplicate key value") {
				writeError(w, http.StatusConflict, "behavior_report_channel_exists", "通道标识已存在")
				return
			}
			writeError(w, http.StatusBadRequest, "bad_behavior_report_channel", err.Error())
			return
		}
		saved.EncryptedSecret = ""
		s.appendAudit(ctx, "behavior_report.channel_created", saved.ChannelID, "succeeded")
		writeJSON(w, http.StatusOK, saved)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "该接口不支持此操作")
	}
}

func (s *Server) handleBehaviorReportChannel(w http.ResponseWriter, r *http.Request, storage behaviorReportReader, rest string) {
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	if strings.HasSuffix(rest, "/test") {
		s.handleBehaviorReportChannelTest(w, r, storage, strings.TrimSuffix(rest, "/test"))
		return
	}
	if strings.HasSuffix(rest, "/preview") {
		s.handleBehaviorReportChannelPreview(w, r, storage, strings.TrimSuffix(rest, "/preview"))
		return
	}
	id := strings.Trim(strings.TrimSpace(rest), "/")
	if id == "" {
		writeError(w, http.StatusNotFound, "not_found", "接口不存在")
		return
	}
	switch r.Method {
	case http.MethodGet:
		channel, err := storage.GetBehaviorReportChannel(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "behavior_report_channel_not_found", "上报通道不存在")
			return
		}
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "behavior_reports_unavailable", "上报通道读取失败")
			return
		}
		channel.EncryptedSecret = ""
		writeJSON(w, http.StatusOK, channel)
	case http.MethodPut:
		if s.readOnly {
			writeError(w, http.StatusForbidden, "read_only", "只读模式禁止修改上报通道")
			return
		}
		existing, err := storage.GetBehaviorReportChannel(ctx, id)
		if err != nil {
			writeError(w, http.StatusNotFound, "behavior_report_channel_not_found", "上报通道不存在")
			return
		}
		var request behaviorReportChannelRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "bad_behavior_report_channel", "请求格式不正确")
			return
		}
		channel, encrypted, err := s.behaviorReportChannelFromRequest(request, existing.EncryptedSecret)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_behavior_report_channel", err.Error())
			return
		}
		channel.ChannelID = id
		saved, err := storage.UpsertBehaviorReportChannel(ctx, channel, encrypted, sessionFromContext(ctx).User.ID, false)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_behavior_report_channel", err.Error())
			return
		}
		saved.EncryptedSecret = ""
		s.appendAudit(ctx, "behavior_report.channel_updated", saved.ChannelID, "succeeded")
		writeJSON(w, http.StatusOK, saved)
	case http.MethodDelete:
		if s.readOnly {
			writeError(w, http.StatusForbidden, "read_only", "只读模式禁止删除上报通道")
			return
		}
		if err := storage.DeleteBehaviorReportChannel(ctx, id); err != nil {
			writeError(w, http.StatusNotFound, "behavior_report_channel_not_found", "上报通道不存在")
			return
		}
		s.appendAudit(ctx, "behavior_report.channel_deleted", id, "succeeded")
		writeJSON(w, http.StatusOK, map[string]any{"channel_id": id, "deleted": true})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "该接口不支持此操作")
	}
}

func (s *Server) behaviorReportChannelFromRequest(request behaviorReportChannelRequest, existingEncrypted string) (behaviorreport.Channel, string, error) {
	channel := behaviorreport.Channel{
		ChannelID: request.ChannelID, Name: request.Name, EndpointURL: request.EndpointURL,
		TokenEndpoint: request.TokenEndpoint, TokenMethod: request.TokenMethod, TokenScope: request.TokenScope,
		AuthType: request.AuthType, SourceSystemIP: request.SourceSystemIP, SourceSystemName: request.SourceSystemName,
		BatchSize: request.BatchSize, FlushIntervalSecs: request.FlushIntervalSecs, TimeoutSeconds: request.TimeoutSeconds,
		TLSSkipVerify: request.TLSSkipVerify, FieldMapping: request.FieldMapping,
		SuccessStatusCodes: request.SuccessStatusCodes, Enabled: request.Enabled,
	}
	behaviorreport.NormalizeChannel(&channel)
	if err := behaviorreport.ValidateChannel(&channel); err != nil {
		return channel, "", err
	}
	encrypted := existingEncrypted
	switch {
	case request.Secret == "-":
		encrypted = ""
	case strings.TrimSpace(request.Secret) != "":
		sealed, err := s.encryptConnectorSecret(request.Secret)
		if err != nil {
			return channel, "", err
		}
		encrypted = sealed
	}
	return channel, encrypted, nil
}

func (s *Server) handleBehaviorReportChannelPreview(w http.ResponseWriter, r *http.Request, storage behaviorReportReader, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "该接口不支持此操作")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	channel, err := storage.GetBehaviorReportChannel(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "behavior_report_channel_not_found", "上报通道不存在")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "behavior_reports_unavailable", "上报通道读取失败")
		return
	}
	converted := storeBehaviorReportChannel(channel)
	payload, err := converted.Payload([]behaviorreport.Event{{
		ReportID: "preview", EventType: behaviorreport.EventPoisonBehavior, IP: "10.155.9.9",
		AccountID: "preview-account", Target: "10.155.32.11", TargetType: "ip",
		OccurredAt: time.Now().UTC(), Detail: map[string]string{"protocol": "tcp", "rule_id": "preview"},
	}})
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_behavior_report_channel", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"channel_id": channel.ChannelID, "payload": payload})
}

func (s *Server) handleBehaviorReportChannelTest(w http.ResponseWriter, r *http.Request, storage behaviorReportReader, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "该接口不支持此操作")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	channel, err := storage.GetBehaviorReportChannel(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "behavior_report_channel_not_found", "上报通道不存在")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "behavior_reports_unavailable", "上报通道读取失败")
		return
	}
	var request behaviorReportTestRequest
	// An absent body is valid: the test falls back to a synthetic event.
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "bad_behavior_report_test", "请求格式不正确")
		return
	}
	eventType := request.EventType
	if eventType == "" {
		eventType = behaviorreport.EventProxyBehavior
	}
	secret, err := s.decryptConnectorSecret(channel.EncryptedSecret)
	if err != nil {
		writeError(w, http.StatusConflict, "behavior_report_secret_unavailable", "上报通道密钥不可用")
		return
	}
	sender, err := behaviorreport.NewSender(storeBehaviorReportChannel(channel), secret)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_behavior_report_channel", err.Error())
		return
	}
	result, sendErr := sender.Send(ctx, []behaviorreport.Event{{
		ReportID: "behavior-report-test-" + shortToken(10), EventType: eventType, IP: "10.0.0.1",
		AccountID: "test-account", Target: "test-target", TargetType: "ip", OccurredAt: time.Now().UTC(),
		Detail: map[string]string{"test": "true"},
	}})
	outcome := "succeeded"
	message := ""
	if sendErr != nil {
		outcome = "failed"
		message = sendErr.Error()
	}
	s.appendAudit(ctx, "behavior_report.test_sent", channel.ChannelID, outcome)
	payload := map[string]any{"channel_id": channel.ChannelID, "status": outcome, "http_status": result.StatusCode}
	if message != "" {
		payload["error"] = message
	} else {
		payload["remote_id"] = result.RemoteID
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleBehaviorReportOutbox(w http.ResponseWriter, r *http.Request, storage behaviorReportReader) {
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
	items, total, err := storage.ListBehaviorReportOutbox(ctx, strings.TrimSpace(r.URL.Query().Get("status")), limit, cursor)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "behavior_reports_unavailable", "上报队列读取失败")
		return
	}
	page := store.Page{Limit: limit, Total: total}
	if cursor+limit < total {
		next := fmt.Sprintf("%d", cursor+limit)
		page.NextCursor = &next
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "page": page})
}

func (s *Server) handleBehaviorReportOutboxItem(w http.ResponseWriter, r *http.Request, storage behaviorReportReader, rest string) {
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
		row, attempts, err := storage.GetBehaviorReportOutbox(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "behavior_report_not_found", "上报记录不存在")
			return
		}
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "behavior_reports_unavailable", "上报记录读取失败")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"report": row, "attempts": attempts})
	case r.Method == http.MethodPost && action == "retry":
		if s.readOnly {
			writeError(w, http.StatusForbidden, "read_only", "只读模式禁止重试上报")
			return
		}
		if err := storage.RequeueBehaviorReport(ctx, id); err != nil {
			writeError(w, http.StatusConflict, "behavior_report_not_retryable", "该上报当前不可重试")
			return
		}
		s.appendAudit(ctx, "behavior_report.retry_requested", id, "succeeded")
		writeJSON(w, http.StatusOK, map[string]any{"report_id": id, "status": "queued"})
	case r.Method == http.MethodPost && action == "cancel":
		if s.readOnly {
			writeError(w, http.StatusForbidden, "read_only", "只读模式禁止取消上报")
			return
		}
		if err := storage.CancelBehaviorReport(ctx, id); err != nil {
			writeError(w, http.StatusConflict, "behavior_report_not_cancellable", "该上报当前不可取消")
			return
		}
		s.appendAudit(ctx, "behavior_report.cancelled", id, "succeeded")
		writeJSON(w, http.StatusOK, map[string]any{"report_id": id, "status": "cancelled"})
	default:
		writeError(w, http.StatusNotFound, "not_found", "接口不存在")
	}
}

func storeBehaviorReportChannel(channel store.BehaviorReportChannel) behaviorreport.Channel {
	return behaviorreport.Channel{
		ChannelID: channel.ChannelID, Name: channel.Name, EndpointURL: channel.EndpointURL,
		TokenEndpoint: channel.TokenEndpoint, TokenMethod: channel.TokenMethod, TokenScope: channel.TokenScope,
		AuthType: channel.AuthType, SourceSystemIP: channel.SourceSystemIP, SourceSystemName: channel.SourceSystemName,
		BatchSize: channel.BatchSize, FlushIntervalSecs: channel.FlushIntervalSecs, TimeoutSeconds: channel.TimeoutSeconds,
		TLSSkipVerify: channel.TLSSkipVerify, FieldMapping: channel.FieldMapping,
		SuccessStatusCodes: channel.SuccessStatusCodes, Enabled: channel.Enabled, Revision: channel.Revision,
		EncryptedSecret: channel.EncryptedSecret, HasSecret: channel.HasSecret,
	}
}

// startBehaviorReportWorker scans stored observations into the outbox and drains
// it. Reporting is asynchronous and never blocks detection or enforcement.
func (s *Server) startBehaviorReportWorker() {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			s.processBehaviorReports(time.Now().UTC())
			<-ticker.C
		}
	}()
}

func (s *Server) processBehaviorReports(now time.Time) {
	storage, ok := s.behaviorReports()
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	channels, err := storage.ListBehaviorReportChannels(ctx)
	if err != nil {
		return
	}
	enabled := make([]store.BehaviorReportChannel, 0, len(channels))
	for _, channel := range channels {
		if channel.Enabled {
			enabled = append(enabled, channel)
		}
	}
	if len(enabled) == 0 {
		return
	}
	s.enqueueBehaviorReportCandidates(ctx, storage, enabled, now)
	for _, channel := range enabled {
		s.deliverBehaviorReportChannel(ctx, storage, channel)
	}
}

// enqueueBehaviorReportCandidates reports stored observations once per channel.
// The idempotency key includes the channel so two platforms both receive the
// event and a replay never duplicates it.
func (s *Server) enqueueBehaviorReportCandidates(ctx context.Context, storage behaviorReportReader, channels []store.BehaviorReportChannel, now time.Time) {
	candidates, err := storage.ListBehaviorReportCandidates(ctx, now.Add(-10*time.Minute), 500)
	if err != nil {
		return
	}
	for _, candidate := range candidates {
		eventType, ok := behaviorReportEventType(candidate.EventType)
		if !ok {
			continue
		}
		for _, channel := range channels {
			key := behaviorreport.IdempotencyKey(eventType, candidate.EvidenceID, channel.ChannelID, candidate.Window)
			row := store.BehaviorReportOutboxRow{
				ReportID:       "report-" + stableReportID(key),
				IdempotencyKey: key,
				ChannelID:      channel.ChannelID,
				EventType:      eventType,
				SubjectType:    "ip",
				SubjectID:      candidate.IP,
				AccountID:      candidate.AccountID,
				IP:             candidate.IP,
				Target:         candidate.Window,
				TargetType:     "window",
				OccurredAt:     candidate.OccurredAt,
			}
			_ = storage.EnqueueBehaviorReport(ctx, row)
		}
	}
}

func (s *Server) deliverBehaviorReportChannel(ctx context.Context, storage behaviorReportReader, channel store.BehaviorReportChannel) {
	rows, err := storage.ClaimBehaviorReportBatch(ctx, channel.ChannelID, channel.BatchSize)
	if err != nil || len(rows) == 0 {
		return
	}
	secret, err := s.decryptConnectorSecret(channel.EncryptedSecret)
	if err != nil {
		for _, row := range rows {
			_ = storage.MarkBehaviorReportFailed(ctx, row, 0, "上报通道密钥不可用")
		}
		return
	}
	sender, err := behaviorreport.NewSender(storeBehaviorReportChannel(channel), secret)
	if err != nil {
		for _, row := range rows {
			_ = storage.MarkBehaviorReportFailed(ctx, row, 0, err.Error())
		}
		return
	}
	events := make([]behaviorreport.Event, 0, len(rows))
	for _, row := range rows {
		events = append(events, behaviorreport.Event{
			ReportID: row.ReportID, EventType: row.EventType, SubjectType: row.SubjectType,
			SubjectID: row.SubjectID, AccountID: row.AccountID, IP: row.IP,
			Target: row.Target, TargetType: row.TargetType,
			OccurredAt: parseBehaviorReportTime(row.OccurredAt),
			Detail:     map[string]string{"channel_id": channel.ChannelID},
		})
	}
	result, sendErr := sender.Send(ctx, events)
	if sendErr == nil {
		for _, row := range rows {
			_ = storage.MarkBehaviorReportSent(ctx, row, result.StatusCode, result.RemoteID)
		}
		s.appendAudit(ctx, "behavior_report.delivered", channel.ChannelID, "succeeded")
		return
	}
	permanent := behaviorreport.IsPermanent(sendErr)
	for _, row := range rows {
		if permanent || row.Attempts >= behaviorreport.MaxAttempts {
			_ = storage.MarkBehaviorReportFailed(ctx, row, result.StatusCode, sendErr.Error())
			continue
		}
		_ = storage.MarkBehaviorReportRetry(ctx, row, result.StatusCode, sendErr.Error())
	}
	s.appendAudit(ctx, "behavior_report.delivery_failed", channel.ChannelID, "failed")
}

func parseBehaviorReportTime(value string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999Z"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed
		}
	}
	return time.Now().UTC()
}

// behaviorReportEventType maps a stored evidence type onto the reported
// behaviour vocabulary. Unknown types are not reported.
func behaviorReportEventType(evidenceType string) (string, bool) {
	switch evidenceType {
	case "internal_target_access":
		return behaviorreport.EventPoisonBehavior, true
	case "proxy_protocol_transaction":
		return behaviorreport.EventProxyBehavior, true
	case "ai_relay_domain_usage":
		return behaviorreport.EventAIRelayAudit, true
	default:
		return "", false
	}
}

func stableReportID(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:12])
}
