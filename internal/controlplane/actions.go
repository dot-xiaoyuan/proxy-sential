package controlplane

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"proxy-sentinel/internal/actionreceipt"
	"reflect"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/srunapi"
)

type ActionConnector struct {
	CertificatePEM        string            `json:"certificate_pem,omitempty"`
	ConnectorType         string            `json:"connector_type"`
	ConnectorID           string            `json:"connector_id"`
	Name                  string            `json:"name"`
	EndpointURL           string            `json:"endpoint_url"`
	ActionMapping         map[string]string `json:"action_mapping"`
	Mode                  string            `json:"mode"`
	Enabled               bool              `json:"enabled"`
	ShadowReady           bool              `json:"shadow_ready"`
	CircuitOpenUntil      string            `json:"circuit_open_until,omitempty"`
	ConsecutiveFailures   int               `json:"consecutive_failures"`
	ShadowStartedAt       string            `json:"shadow_started_at,omitempty"`
	ShadowValidationSince string            `json:"shadow_validation_since,omitempty"`
	ShadowCandidateCount  int               `json:"shadow_candidate_count"`
	ShadowReviewedCount   int               `json:"shadow_reviewed_count"`
	ShadowAccuracy        float64           `json:"shadow_accuracy"`
	EncryptedSecret       string            `json:"-"`
	UpdatedAt             string            `json:"updated_at"`
}

type EnforcementAction struct {
	PolicyParameters   PolicyActionParameters `json:"policy_parameters,omitempty"`
	ActionID           string                 `json:"action_id"`
	IdempotencyKey     string                 `json:"idempotency_key"`
	CaseID             string                 `json:"case_id,omitempty"`
	ConnectorID        string                 `json:"connector_id"`
	ActionType         string                 `json:"action_type"`
	SubjectType        string                 `json:"subject_type"`
	SubjectID          string                 `json:"subject_id"`
	IP                 string                 `json:"ip,omitempty"`
	AccountID          string                 `json:"account_id,omitempty"`
	EndpointID         string                 `json:"endpoint_id,omitempty"`
	SessionID          string                 `json:"session_id,omitempty"`
	CampusID           string                 `json:"campus_id,omitempty"`
	Status             string                 `json:"status"`
	Mode               string                 `json:"mode"`
	DurationSeconds    int                    `json:"duration_seconds"`
	EvidenceIDs        []string               `json:"evidence_ids"`
	RulesetVersion     string                 `json:"ruleset_version,omitempty"`
	RemoteActionID     string                 `json:"remote_action_id,omitempty"`
	RetryCount         int                    `json:"retry_count"`
	PrecheckRetryCount int                    `json:"precheck_retry_count,omitempty"`
	PrecheckRetryable  bool                   `json:"precheck_retryable,omitempty"`
	ParentActionID     string                 `json:"parent_action_id,omitempty"`
	NextAttemptAt      string                 `json:"next_attempt_at,omitempty"`
	CooldownUntil      string                 `json:"cooldown_until,omitempty"`
	ExpiresAt          string                 `json:"expires_at,omitempty"`
	LastError          string                 `json:"last_error,omitempty"`
	CreatedBy          string                 `json:"created_by"`
	CreatedAt          string                 `json:"created_at"`
	UpdatedAt          string                 `json:"updated_at"`
	Blockers           []string               `json:"blockers,omitempty"`
}

type executeActionRequest struct {
	CaseID          string `json:"case_id"`
	ConnectorID     string `json:"connector_id"`
	ActionType      string `json:"action_type"`
	IP              string `json:"ip"`
	CampusID        string `json:"campus_id"`
	DurationSeconds int    `json:"duration_seconds"`
}

type connectorRequest struct {
	CertificatePEM *string           `json:"certificate_pem,omitempty"`
	ConnectorType  string            `json:"connector_type"`
	ConnectorID    string            `json:"connector_id"`
	Name           string            `json:"name"`
	EndpointURL    string            `json:"endpoint_url"`
	ActionMapping  map[string]string `json:"action_mapping"`
	Mode           string            `json:"mode"`
	Enabled        bool              `json:"enabled"`
	ShadowReady    bool              `json:"shadow_ready"`
	Secret         string            `json:"secret"`
}

func (s *Server) startActionWorker() {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		s.processDueActions(time.Now().UTC())
		for now := range ticker.C {
			s.processAccountPolicies(now.UTC())
			s.processDueActions(now.UTC())
		}
	}()
}

func (s *Server) handleActions(w http.ResponseWriter, r *http.Request) {
	if id, ok := fourKSyncPath(r.URL.Path); ok {
		s.handle4KSync(w, r, id)
		return
	}
	if id, ok := managedIdentityPath(r.URL.Path); ok {
		s.handleManagedIdentity(w, r, id)
		return
	}
	if is4KDatabasePath(r.URL.Path) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		s.handle4KDatabase(w, r, parts[len(parts)-2])
		return
	}

	if r.Method == http.MethodGet && s.operations.db != nil && !s.operations.readView {
		s.actionReadPostgres(w, r)
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/actions"), "/")
	if rest == "callback" && r.Method == http.MethodPost {
		s.handleActionCallback(w, r)
		return
	}
	if rest == "connectors" {
		s.handleConnectors(w, r)
		return
	}
	if rest == "emergency-stop" && r.Method == http.MethodPost {
		s.handleEmergencyStop(w, r)
		return
	}
	if rest == "execute" && r.Method == http.MethodPost {
		s.handleExecuteAction(w, r)
		return
	}
	if r.Method == http.MethodGet && rest == "" {
		s.listActions(w, r)
		return
	}
	parts := strings.Split(rest, "/")
	if r.Method == http.MethodGet && len(parts) == 3 && parts[0] == "connectors" && parts[2] == "account-preview" {
		s.handleNativeAccountPreview(w, r, parts[1])
		return
	}

	if r.Method == http.MethodGet && len(parts) == 2 && parts[1] == "native-observations" {
		s.handleNativeActionObservations(w, r, parts[0])
		return
	}
	if r.Method == http.MethodPost && len(parts) == 3 && parts[0] == "connectors" && parts[2] == "test" {
		s.handleConnectorTest(w, r, parts[1])
		return
	}
	if r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "revoke" {
		s.handleRevokeAction(w, r, parts[0])
		return
	}
	if r.Method == http.MethodGet && len(parts) == 1 && parts[0] != "" {
		s.operations.mu.Lock()
		action, ok := s.operations.doc.Actions[parts[0]]
		s.operations.mu.Unlock()
		if !ok {
			writeError(w, 404, "action_not_found", "action not found")
			return
		}
		writeJSON(w, 200, action)
		return
	}
	writeError(w, 404, "action_endpoint_not_found", "action endpoint not found")
}

func (s *Server) handleConnectors(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && s.operations.db != nil && !s.operations.readView {
		s.saveConnectorPostgres(w, r)
		return
	}
	s.operations.mu.Lock()
	defer s.operations.mu.Unlock()
	if r.Method == http.MethodGet {
		for id, item := range s.operations.doc.Connectors {
			s.refreshConnectorShadowReadinessLocked(&item, time.Now().UTC())
			s.operations.doc.Connectors[id] = item
		}
		items := mapValues(s.operations.doc.Connectors)
		sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
		writeJSON(w, 200, map[string]any{"items": items, "global_stop": s.operations.doc.GlobalStop})
		return
	}
	var request connectorRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&request); err != nil {
		writeError(w, 400, "bad_connector", err.Error())
		return
	}
	if request.ConnectorID == "" || request.Name == "" || request.EndpointURL == "" {
		writeError(w, 400, "bad_connector", "connector_id, name and endpoint_url are required")
		return
	}
	endpoint, err := url.Parse(request.EndpointURL)
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" {
		writeError(w, 400, "bad_connector_url", "endpoint_url must be an absolute HTTP or HTTPS URL")
		return
	}
	if request.Mode != "shadow" && request.Mode != "active" {
		writeError(w, 400, "bad_connector_mode", "mode must be shadow or active")
		return
	}
	existing := s.operations.doc.Connectors[request.ConnectorID]
	if request.ConnectorType == "" {
		request.ConnectorType = existing.ConnectorType
		if request.ConnectorType == "" {
			request.ConnectorType = "hmac"
		}
	}
	if request.ConnectorType != "hmac" && request.ConnectorType != "srun4k" {
		writeError(w, 400, "bad_connector_type", "connector_type must be hmac or srun4k")
		return
	}
	if request.ConnectorType == "srun4k" && request.Secret != "" {
		writeError(w, 400, "native_connector_secret_not_supported", "4K uses database authorization instead of HMAC")
		return
	}
	if request.ConnectorType == "srun4k" {
		// This describes the execution capability exposed by the connector. It is
		// not a policy action: policy authors still choose and order actions.
		request.ActionMapping = map[string]string{
			"account_policy_v1":  "supported",
			"session.disconnect": "online-drop",
		}
	}

	certificate := existing.CertificatePEM
	if request.CertificatePEM != nil {
		certificate = strings.TrimSpace(*request.CertificatePEM)
	}
	if certificate != "" {
		if request.ConnectorType != "srun4k" || endpoint.Scheme != "https" {
			writeError(w, 400, "bad_connector_certificate", "证书固定信任仅适用于HTTPS原生4K连接器")
			return
		}
		client, err := srunapi.NewCertificatePinnedClient([]byte(certificate))
		if err != nil {
			writeError(w, 400, "bad_connector_certificate", "请提供一张有效的PEM格式服务器证书")
			return
		}
		client.CloseIdleConnections()
	}
	s.refreshConnectorShadowReadinessLocked(&existing, time.Now().UTC())
	materialChange := existing.ConnectorID != "" && ((existing.ConnectorType != "" && existing.ConnectorType != request.ConnectorType) || existing.CertificatePEM != certificate || existing.EndpointURL != request.EndpointURL || !reflect.DeepEqual(existing.ActionMapping, request.ActionMapping))
	if materialChange {
		existing.ShadowReady = false
		existing.ShadowValidationSince = time.Now().UTC().Format(time.RFC3339Nano)
		existing.ShadowStartedAt = ""
		existing.ShadowCandidateCount, existing.ShadowReviewedCount, existing.ShadowAccuracy = 0, 0, 0
	}
	runtime, _ := s.nativeRuntime(request.ConnectorID)
	if request.Mode == "active" && !existing.ShadowReady && runtime.TestAccount == "" {
		writeError(w, 409, "shadow_gate_required", "真实模式尚未通过准入验收：至少七天影子复核、准确率不低于95%，且保护对象零误处置。请使用影子模式配置授权和检查接口。")
		return
	}
	encrypted := existing.EncryptedSecret
	if request.Secret != "" {
		value, err := s.encryptConnectorSecret(request.Secret)
		if err != nil {
			writeError(w, 409, "action_master_key_required", err.Error())
			return
		}
		encrypted = value
	}
	if _, nativeConfigured := s.nativeRuntime(request.ConnectorID); encrypted == "" && !nativeConfigured && request.ConnectorType != "srun4k" {
		writeError(w, 400, "connector_secret_required", "secret is required for a new connector")
		return
	}
	if request.ConnectorType == "srun4k" {
		encrypted = ""
	}
	item := ActionConnector{CertificatePEM: certificate, ConnectorType: request.ConnectorType, ConnectorID: request.ConnectorID, Name: request.Name, EndpointURL: request.EndpointURL, ActionMapping: request.ActionMapping, Mode: request.Mode, Enabled: request.Enabled, ShadowReady: existing.ShadowReady, EncryptedSecret: encrypted, CircuitOpenUntil: existing.CircuitOpenUntil, ConsecutiveFailures: existing.ConsecutiveFailures, ShadowStartedAt: existing.ShadowStartedAt, ShadowValidationSince: existing.ShadowValidationSince, ShadowCandidateCount: existing.ShadowCandidateCount, ShadowReviewedCount: existing.ShadowReviewedCount, ShadowAccuracy: existing.ShadowAccuracy, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	s.operations.doc.Connectors[item.ConnectorID] = item
	if err := s.operations.saveLocked(); err != nil {
		writeError(w, 500, "save_connector_failed", err.Error())
		return
	}
	auditMode := item.Mode
	runtime, _ = s.nativeRuntime(item.ConnectorID)
	if item.Mode == "active" && !item.ShadowReady && runtime.TestAccount != "" {
		auditMode = "active_scoped_test_exception"
	}
	s.appendAudit(r.Context(), "enforcement.connector.save", item.ConnectorID, auditMode)
	writeJSON(w, 200, item)
}

func (s *Server) refreshConnectorShadowReadinessLocked(connector *ActionConnector, now time.Time) {
	if s.operations.shadowMetricsPrepared {
		return
	}
	if until, err := time.Parse(time.RFC3339Nano, connector.CircuitOpenUntil); err == nil && !until.After(now) {
		connector.CircuitOpenUntil = ""
		connector.ConsecutiveFailures = 0
	}
	var earliest time.Time
	validationSince, _ := time.Parse(time.RFC3339Nano, connector.ShadowValidationSince)
	candidates, reviewed, correct := 0, 0, 0
	falseAction := false
	for _, action := range s.operations.doc.Actions {
		if action.ConnectorID != connector.ConnectorID || action.Mode != "shadow" || action.Status != "shadow" {
			continue
		}
		created, _ := time.Parse(time.RFC3339Nano, action.CreatedAt)
		if !validationSince.IsZero() && created.Before(validationSince) {
			continue
		}
		candidates++
		if earliest.IsZero() || created.Before(earliest) {
			earliest = created
		}
		if item, ok := s.operations.doc.Cases[action.CaseID]; ok && item.Disposition != "" && item.Disposition != "needs_more_data" {
			reviewed++
			if item.Disposition == "confirmed_proxy" {
				correct++
			} else {
				falseAction = true
			}
		}
	}
	connector.ShadowCandidateCount, connector.ShadowReviewedCount = candidates, reviewed
	if !earliest.IsZero() {
		connector.ShadowStartedAt = earliest.UTC().Format(time.RFC3339Nano)
	}
	connector.ShadowAccuracy = 0
	if reviewed > 0 {
		connector.ShadowAccuracy = float64(correct) / float64(reviewed)
	}
	connector.ShadowReady = candidates > 0 && reviewed == candidates && now.Sub(earliest) >= 7*24*time.Hour && connector.ShadowAccuracy >= .95 && !falseAction
}

func (s *Server) handleEmergencyStop(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, 400, "bad_emergency_stop", err.Error())
		return
	}
	if s.operations.db != nil && !s.operations.readView {
		ctx, cancel := contextWithRequestTimeout(r.Context())
		defer cancel()
		value, _ := json.Marshal(body.Enabled)
		if _, err := s.operations.db.ExecContext(ctx, `INSERT INTO control_plane_settings(setting_key,setting_value) VALUES('global_emergency_stop',$1::jsonb) ON CONFLICT(setting_key) DO UPDATE SET setting_value=EXCLUDED.setting_value`, value); err != nil {
			writeError(w, 503, "save_emergency_stop_failed", err.Error())
			return
		}
		s.appendAudit(r.Context(), "enforcement.emergency_stop", "global", fmt.Sprintf("enabled=%t", body.Enabled))
		writeJSON(w, 200, map[string]any{"global_stop": body.Enabled})
		return
	}
	s.operations.mu.Lock()
	s.operations.doc.GlobalStop = body.Enabled
	err := s.operations.saveLocked()
	s.operations.mu.Unlock()
	if err != nil {
		writeError(w, 500, "save_emergency_stop_failed", err.Error())
		return
	}
	s.appendAudit(r.Context(), "enforcement.emergency_stop", "global", fmt.Sprintf("enabled=%t", body.Enabled))
	writeJSON(w, 200, map[string]any{"global_stop": body.Enabled})
}

func (s *Server) handleConnectorTest(w http.ResponseWriter, r *http.Request, connectorID string) {
	if s.operations.db != nil && !s.operations.readView {
		s.connectorTestPostgres(w, r, connectorID)
		return
	}
	s.operations.mu.Lock()
	connector, ok := s.operations.doc.Connectors[connectorID]
	s.operations.mu.Unlock()
	if !ok {
		writeError(w, 404, "connector_not_found", "connector not found")
		return
	}
	if s.handleNativeConnectorProbe(w, r, connectorID) {
		return
	}
	if connector.ConnectorType == "srun4k" {
		s.handleManaged4KProbe(w, r, connector)
		return
	}

	secret, err := s.decryptConnectorSecret(connector.EncryptedSecret)
	if err != nil {
		writeError(w, 409, "connector_secret_unavailable", err.Error())
		return
	}
	payload, _ := json.Marshal(map[string]any{"type": "connectivity_test", "connector_id": connectorID, "timestamp": time.Now().UTC().Format(time.RFC3339Nano)})
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, connector.EndpointURL, bytes.NewReader(payload))
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Proxy-Sentinel-Timestamp", timestamp)
	request.Header.Set("X-Proxy-Sentinel-Signature", signActionPayload(secret, timestamp, payload))
	request.Header.Set("Idempotency-Key", "connector-test-"+shortToken(8))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		writeError(w, 502, "connector_unreachable", err.Error())
		return
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		s.appendAudit(r.Context(), "enforcement.connector.test", connectorID, fmt.Sprintf("failed:%d", response.StatusCode))
		writeError(w, 502, "connector_test_failed", fmt.Sprintf("northbound endpoint returned %d", response.StatusCode))
		return
	}
	s.appendAudit(r.Context(), "enforcement.connector.test", connectorID, "succeeded")
	writeJSON(w, 200, map[string]any{"connector_id": connectorID, "reachable": true, "checked_at": time.Now().UTC().Format(time.RFC3339Nano)})
}

func (s *Server) handleActionCallback(w http.ResponseWriter, r *http.Request) {
	if s.operations.db != nil && !s.operations.readView {
		s.actionCallbackPostgres(w, r)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil || !json.Valid(body) {
		writeError(w, 400, "bad_action_callback", "callback must contain valid JSON")
		return
	}
	var callback struct {
		ActionID       string `json:"action_id"`
		Status         string `json:"status"`
		RemoteActionID string `json:"remote_action_id"`
		Error          string `json:"error"`
	}
	if json.Unmarshal(body, &callback) != nil || callback.ActionID == "" || !map[string]bool{"succeeded": true, "failed": true, "revoked": true}[callback.Status] {
		writeError(w, 400, "bad_action_callback", "action_id and a supported terminal status are required")
		return
	}
	s.operations.mu.Lock()
	action, ok := s.operations.doc.Actions[callback.ActionID]
	connector := s.operations.doc.Connectors[action.ConnectorID]
	s.operations.mu.Unlock()
	if !ok {
		writeError(w, 404, "action_not_found", "action not found")
		return
	}
	secret, err := s.decryptConnectorSecret(connector.EncryptedSecret)
	if err != nil {
		writeError(w, 401, "callback_signature_invalid", "callback signature cannot be verified")
		return
	}
	timestamp := r.Header.Get("X-Proxy-Sentinel-Timestamp")
	parsed, err := time.Parse(time.RFC3339Nano, timestamp)
	expected := signActionPayload(secret, timestamp, body)
	if err != nil || time.Since(parsed).Abs() > 5*time.Minute || !hmac.Equal([]byte(expected), []byte(r.Header.Get("X-Proxy-Sentinel-Signature"))) {
		writeError(w, 401, "callback_signature_invalid", "callback signature or timestamp is invalid")
		return
	}
	if err := s.finishActionReceipt(action, callback.Status, callback.RemoteActionID, callback.Error); err != nil {
		if errors.Is(err, errActionReceiptConflict) {
			s.appendAudit(r.Context(), "enforcement.callback", callback.ActionID, "receipt_conflict:"+callback.Status)
			writeError(w, http.StatusConflict, "action_receipt_conflict", err.Error())
			return
		}
		writeError(w, 503, "action_storage_failed", err.Error())
		return
	}
	s.appendAudit(r.Context(), "enforcement.callback", callback.ActionID, callback.Status)
	writeJSON(w, 200, map[string]any{"accepted": true, "action_id": callback.ActionID})
}

func (s *Server) handleExecuteAction(w http.ResponseWriter, r *http.Request) {
	if s.operations.db != nil && !s.operations.readView {
		s.executeActionPostgres(w, r)
		return
	}
	var request executeActionRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&request); err != nil {
		writeError(w, 400, "bad_action", err.Error())
		return
	}
	request.ActionType = firstNonEmptyString(request.ActionType, "quarantine")
	if !map[string]bool{"quarantine": true, "throttle": true, "disconnect": true, "release": true, "status": true}[request.ActionType] {
		writeError(w, 400, "unsupported_action_type", "action_type must be quarantine, throttle, disconnect, release or status")
		return
	}
	if request.DurationSeconds <= 0 {
		request.DurationSeconds = 1800
	}
	idempotency := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idempotency == "" {
		writeError(w, 400, "idempotency_key_required", "Idempotency-Key header is required")
		return
	}
	s.operations.mu.Lock()
	for _, existing := range s.operations.doc.Actions {
		if existing.IdempotencyKey == idempotency {
			s.operations.mu.Unlock()
			writeJSON(w, 200, existing)
			return
		}
	}
	connector, connectorOK := s.operations.doc.Connectors[request.ConnectorID]
	if connectorOK {
		s.refreshConnectorShadowReadinessLocked(&connector, time.Now().UTC())
		s.operations.doc.Connectors[request.ConnectorID] = connector
	}
	globalStop := s.operations.doc.GlobalStop
	caseItem, caseOK := s.operations.doc.Cases[request.CaseID]
	s.operations.mu.Unlock()
	snapshot, err := s.reader.GetIPRisk(r.Context(), request.IP)
	if err != nil {
		writeError(w, 404, "risk_not_found", err.Error())
		return
	}
	evidenceItems, err := s.reader.GetIPEvidence(r.Context(), request.IP, 100)
	if err != nil {
		writeError(w, 500, "read_action_evidence_failed", err.Error())
		return
	}
	blockers := []string{}
	if snapshot.IP != request.IP {
		blockers = append(blockers, "risk_subject_mismatch")
	}
	if snapshot.Level != "high" && snapshot.Level != "confirmed" {
		blockers = append(blockers, "risk_level_not_actionable")
	}
	if connector.Mode == "active" && (!caseOK || request.CaseID == "") {
		blockers = append(blockers, "case_required_for_active_action")
	}
	if caseOK {
		if request.CampusID == "" {
			request.CampusID = caseItem.CampusID
		}
		if caseItem.IP != "" && caseItem.IP != request.IP {
			blockers = append(blockers, "case_subject_mismatch")
		}
		if caseItem.Disposition == "false_positive" || caseItem.Disposition == "benign" || caseItem.Disposition == "needs_more_data" || caseItem.Status == "closed" || caseItem.Status == "resolved" {
			blockers = append(blockers, "manual_exception_applied")
		}
		if caseItem.IdentityConflict || caseItem.IdentityBlocker != "" {
			blockers = append(blockers, "case_identity_not_actionable")
		}
	}
	if exception, exceptionErr := s.exceptions.apply(r.Context(), &snapshot, request.CampusID); exceptionErr != nil {
		writeError(w, 500, "check_campus_exception_failed", exceptionErr.Error())
		return
	} else if exception != nil {
		blockers = append(blockers, "campus_exception_applied")
	}
	if activeExceptions, exceptionErr := s.exceptions.list(r.Context(), true); exceptionErr != nil {
		writeError(w, 500, "check_campus_exception_failed", exceptionErr.Error())
		return
	} else if matchEvidenceException(activeExceptions, evidenceItems, request.CampusID) != nil {
		blockers = appendUnique(blockers, "campus_exception_applied")
	}
	if err := s.checkActionWhitelist(r.Context(), EnforcementAction{ActionType: request.ActionType, AccountID: snapshot.AccountID, IP: request.IP, CampusID: request.CampusID}); err != nil {
		blockers = appendUnique(blockers, err.Error())
	}
	if snapshot.Score < 90 {
		blockers = append(blockers, "risk_score_below_90")
	}
	if snapshot.Confidence < .90 {
		blockers = append(blockers, "risk_confidence_below_0_90")
	}
	blockers = append(blockers, riskActionProofBlockers(snapshot, evidenceItems, snapshot.EvidenceIDs, time.Now().UTC())...)
	if snapshot.ReviewStatus == "false_positive" || snapshot.ReviewStatus == "benign" {
		blockers = append(blockers, "manual_exception_applied")
	}
	activeSessionID := ""
	if snapshot.AccountID == "" || snapshot.EndpointID == "" {
		blockers = append(blockers, "active_identity_session_required")
	} else {
		identityNow := time.Now().UTC()
		session, identityErr := s.currentRiskActionSession(r.Context(), snapshot, caseItem.AuthSessionID, identityNow)
		if identityErr != nil {
			blockers = append(blockers, "active_identity_session_required")
		} else {
			activeSessionID = session.ID
		}
	}
	if !connectorOK || !connector.Enabled {
		blockers = append(blockers, "enabled_connector_required")
	}
	if connector.Mode == "active" && !connector.ShadowReady {
		blockers = append(blockers, "shadow_gate_required")
	}
	if until, parseErr := time.Parse(time.RFC3339Nano, connector.CircuitOpenUntil); parseErr == nil && until.After(time.Now().UTC()) {
		blockers = append(blockers, "connector_circuit_open")
	}
	if globalStop {
		blockers = append(blockers, "global_emergency_stop")
	}
	now := time.Now().UTC()
	campusCount, hourCount := 0, 0
	if s.operations.db != nil && s.operations.readView {
		var cooling bool
		campusCount, hourCount, cooling, err = s.actionAdmissionCounts(r.Context(), snapshot.AccountID, snapshot.EndpointID, request.CampusID, now)
		if err != nil {
			writeError(w, 503, "action_storage_failed", err.Error())
			return
		}
		if cooling {
			blockers = append(blockers, "subject_cooldown_active")
		}
	} else {
		s.operations.mu.Lock()
		for _, previous := range s.operations.doc.Actions {
			sameSubject := snapshot.AccountID != "" && previous.AccountID == snapshot.AccountID || snapshot.EndpointID != "" && previous.EndpointID == snapshot.EndpointID
			if sameSubject && (previous.Status == "succeeded" || previous.Status == "revoked" || previous.Status == "expired") {
				if until, e := time.Parse(time.RFC3339Nano, previous.CooldownUntil); e == nil && until.After(now) {
					blockers = append(blockers, "subject_cooldown_active")
				}
			}
		}
		for _, previous := range s.operations.doc.Actions {
			created, _ := time.Parse(time.RFC3339Nano, previous.CreatedAt)
			if previous.Mode == "active" && (previous.Status == "pending" || previous.Status == "running" || previous.Status == "succeeded") && now.Sub(created) <= time.Hour {
				hourCount++
				if request.CampusID != "" && previous.CampusID == request.CampusID && now.Sub(created) <= 10*time.Minute {
					campusCount++
				}
			}
		}
		s.operations.mu.Unlock()
	}
	if campusCount >= 5 {
		blockers = append(blockers, "campus_circuit_open")
	}
	if hourCount >= 20 {
		blockers = append(blockers, "global_circuit_open")
	}
	actor := sessionFromContext(r.Context()).User.ID
	status := "pending"
	mode := connector.Mode
	if len(blockers) > 0 {
		status = "blocked"
	}
	if mode == "shadow" && len(blockers) == 0 {
		status = "shadow"
	}
	action := EnforcementAction{ActionID: "action-" + shortToken(10), IdempotencyKey: idempotency, CaseID: request.CaseID, ConnectorID: request.ConnectorID, ActionType: request.ActionType, SubjectType: "account", SubjectID: firstNonEmptyString(snapshot.AccountID, snapshot.EndpointID, request.IP), IP: request.IP, AccountID: snapshot.AccountID, EndpointID: snapshot.EndpointID, SessionID: activeSessionID, CampusID: request.CampusID, Status: status, Mode: mode, DurationSeconds: request.DurationSeconds, EvidenceIDs: snapshot.EvidenceIDs, RulesetVersion: caseItem.RulesetVersion, CooldownUntil: now.Add(24 * time.Hour).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Duration(request.DurationSeconds) * time.Second).Format(time.RFC3339Nano), CreatedBy: actor, CreatedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano), Blockers: blockers}
	s.operations.mu.Lock()
	if campusCount >= 5 || hourCount >= 20 {
		connector.CircuitOpenUntil = now.Add(30 * time.Minute).Format(time.RFC3339Nano)
		s.operations.doc.Connectors[connector.ConnectorID] = connector
	}
	s.operations.doc.Actions[action.ActionID] = action
	err = s.operations.saveLocked()
	s.operations.mu.Unlock()
	if err != nil {
		writeError(w, 500, "save_action_failed", err.Error())
		return
	}
	if status == "pending" {
		s.enqueueActionDelivery(action.ActionID, false)
	}
	s.appendAudit(r.Context(), "enforcement.execute", action.ActionID, status)
	writeJSON(w, http.StatusAccepted, action)
}

func (s *Server) deliverAction(actionID string, revoke bool) {
	if s.operations.db != nil && !s.operations.readView {
		s.deliverActionPostgres(actionID, revoke)
		return
	}
	if s.deliverNativeAction(actionID, revoke) {
		return
	}
	s.operations.mu.Lock()
	preview := s.operations.doc.Actions[actionID]
	s.operations.mu.Unlock()
	if !actionDispatchDue(preview, time.Now().UTC()) {
		return
	}
	if err := s.validatePolicyDelivery(preview); err != nil {
		s.recordActionPrecheckFailure(preview, err)
		return
	}
	s.operations.mu.Lock()
	action, ok := s.operations.doc.Actions[actionID]
	connector := s.operations.doc.Connectors[action.ConnectorID]
	if !ok {
		s.operations.mu.Unlock()
		return
	}
	if action.Status != "pending" {
		s.operations.mu.Unlock()
		return
	}
	if operationFingerprint("action", action) != operationFingerprint("action", preview) {
		s.operations.mu.Unlock()
		return
	}
	if s.operations.lockErr != nil {
		s.operations.mu.Unlock()
		return
	}
	action.PrecheckRetryable = false
	action.NextAttemptAt = ""
	action.LastError = ""
	if s.operations.doc.GlobalStop || !connector.Enabled || connector.Mode != "active" || (action.PolicyParameters.ExecutionID != "" && !connector.ShadowReady) {
		action.Status = "blocked"
		action.LastError = "连接器或紧急停止状态已变更，动作已阻塞"
		action.Blockers = append(action.Blockers, "connector_or_global_stop_changed")
		action.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		s.operations.doc.Actions[actionID] = action
		_ = s.operations.saveLocked()
		s.operations.mu.Unlock()
		return
	}
	action.Status = "running"
	action.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	s.operations.doc.Actions[actionID] = action
	if err := s.operations.saveLocked(); err != nil {
		s.operations.mu.Unlock()
		return
	}
	s.operations.mu.Unlock()
	s.deliverActionRequest(action, connector, revoke)
}

func (s *Server) deliverActionRequest(action EnforcementAction, connector ActionConnector, revoke bool) {
	if connector.ConnectorType == "srun4k" {
		s.recordActionPrecheckFailure(action, errors.New("native runtime or action capability unavailable"))
		return
	}
	secret, err := s.decryptConnectorSecret(connector.EncryptedSecret)
	if err != nil {
		s.finishDeliveredAction(action, "failed", "", err.Error())
		return
	}
	payload := map[string]any{"action_id": action.ActionID, "idempotency_key": action.IdempotencyKey, "case_id": action.CaseID, "action": action.ActionType, "revoke": revoke, "subject": map[string]any{"account_id": action.AccountID, "endpoint_id": action.EndpointID, "ip": action.IP, "campus_id": action.CampusID, "session_id": action.SessionID}, "duration_seconds": action.DurationSeconds, "evidence_ids": action.EvidenceIDs, "ruleset_version": action.RulesetVersion, "expires_at": action.ExpiresAt}
	if action.PolicyParameters.ExecutionID != "" {
		payload["policy"] = action.PolicyParameters
	}
	data, _ := json.Marshal(payload)
	mapped := connector.ActionMapping[action.ActionType]
	if mapped != "" {
		payload["action"] = mapped
		data, _ = json.Marshal(payload)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, connector.EndpointURL, bytes.NewReader(data))
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Proxy-Sentinel-Timestamp", timestamp)
	req.Header.Set("X-Proxy-Sentinel-Signature", signActionPayload(secret, timestamp, data))
	req.Header.Set("Idempotency-Key", action.IdempotencyKey)
	resp, requestErr := http.DefaultClient.Do(req)
	var responseBody []byte
	statusCode := 0
	lastError := ""
	if resp != nil {
		statusCode = resp.StatusCode
		var readErr error
		responseBody, readErr = io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
		_ = resp.Body.Close()
		if readErr != nil && requestErr == nil {
			requestErr = fmt.Errorf("incomplete action receipt: %w", readErr)
		}
	}

	if requestErr == nil && statusCode >= 200 && statusCode < 300 {
		remoteID, err := actionreceipt.Completed(responseBody, revoke)
		if err == nil {
			attemptErr := s.recordActionAttempt(action, data, responseBody, statusCode, "")
			s.finishDeliveredAction(action, map[bool]string{true: "revoked", false: "succeeded"}[revoke], remoteID, "")
			s.auditActionAttemptWriteError(action, attemptErr)
			return
		}
		requestErr = err
	}

	if requestErr != nil {
		lastError = requestErr.Error()
	} else {
		lastError = fmt.Sprintf("status=%d body=%s", statusCode, strings.TrimSpace(string(responseBody)))
	}
	attemptErr := s.recordActionAttempt(action, data, responseBody, statusCode, lastError)
	s.auditDeliveryResultError(action, "retry", s.scheduleActionRetryForAttempt(action, lastError))
	s.auditActionAttemptWriteError(action, attemptErr)
}

func signActionPayload(secret, timestamp string, data []byte) string {
	signature := hmac.New(sha256.New, []byte(secret))
	_, _ = signature.Write([]byte(timestamp + "."))
	_, _ = signature.Write(data)
	return "sha256=" + fmt.Sprintf("%x", signature.Sum(nil))
}

func (s *Server) recordActionAttempt(action EnforcementAction, requestBody, responseBody []byte, statusCode int, errorText string) error {
	if s.operations.db == nil {
		return nil
	}
	// Receipt storage has its own budget: the HTTP deadline may already have
	// expired, and an attempt-table lock must not hold the delivery worker.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := s.operations.db.ExecContext(ctx, `INSERT INTO enforcement_action_attempts(attempt_id,action_id,attempt_number,request_body,response_body,http_status,error_text,created_at) VALUES($1,$2,$3,$4,NULLIF($5,'null'::jsonb),NULLIF($6,0),NULLIF($7,''),now()) ON CONFLICT(attempt_id) DO NOTHING`, "attempt-"+shortToken(10), action.ActionID, action.RetryCount+1, json.RawMessage(requestBody), nullableJSON(responseBody), statusCode, errorText)
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (s *Server) auditActionAttemptWriteError(action EnforcementAction, err error) {
	if err == nil {
		return
	}
	outcome := "attempt_storage_failed"
	if errors.Is(err, context.DeadlineExceeded) {
		outcome = "attempt_storage_timeout"
	}
	// The actual transport outcome is already processed. Losing its diagnostic
	// row cannot turn a confirmed recovery into another remote request.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if auditErr := s.writeAudit(ctx, "enforcement.delivery_attempt", action.ActionID, outcome); auditErr != nil {
		log.Printf("action attempt storage audit did not complete: action=%q outcome=%q", action.ActionID, outcome)
	}
}

func nullableJSON(value []byte) any {
	if len(bytes.TrimSpace(value)) == 0 || !json.Valid(value) {
		return json.RawMessage("null")
	}
	return json.RawMessage(value)
}

func (s *Server) scheduleActionRetry(id, lastError string) error {
	if s.operations.db != nil && !s.operations.readView {
		return s.scheduleActionRetryPostgres(id, lastError)
	}
	s.operations.mu.Lock()
	defer s.operations.mu.Unlock()
	return s.scheduleActionRetryLocked(id, lastError)
}

func (s *Server) scheduleActionRetryLocked(id, lastError string) error {
	action, exists := s.operations.doc.Actions[id]
	if !exists {
		return fmt.Errorf("action not found")
	}
	// A late transport failure must not undo a completed callback.
	if action.Status != "running" && action.Status != "pending" {
		if s.operations.db != nil {
			return s.operations.saveLocked()
		}
		return nil
	}
	action.RetryCount++
	action.LastError = lastError
	action.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if action.RetryCount >= actionTransportRetryLimit {
		action.Status = "failed"
		action.NextAttemptAt = ""
		connector := s.operations.doc.Connectors[action.ConnectorID]
		connector.ConsecutiveFailures++
		if connector.ConsecutiveFailures >= 5 {
			connector.CircuitOpenUntil = time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339Nano)
		}
		s.operations.doc.Connectors[action.ConnectorID] = connector
	} else {
		action.Status = "pending"
		action.NextAttemptAt = time.Now().UTC().Add(time.Duration(1<<uint(action.RetryCount-1)) * time.Second).Format(time.RFC3339Nano)
	}
	s.operations.doc.Actions[id] = action
	return s.operations.saveLocked()
}

func (s *Server) finishAction(id, status, remoteID, lastError string) error {
	if s.operations.db != nil && !s.operations.readView {
		return s.finishActionPostgres(id, status, remoteID, lastError)
	}
	s.operations.mu.Lock()
	defer s.operations.mu.Unlock()
	return s.finishActionLocked(id, status, remoteID, lastError)
}

func (s *Server) finishActionLocked(id, status, remoteID, lastError string) error {
	action, exists := s.operations.doc.Actions[id]
	if !exists {
		return fmt.Errorf("action not found")
	}
	if action.Status == status && (remoteID == "" || remoteID == action.RemoteActionID) && action.LastError == lastError {
		if s.operations.db != nil {
			return s.operations.saveLocked()
		}
		return nil
	}

	action.Status = status
	action.RemoteActionID = firstNonEmptyString(remoteID, action.RemoteActionID)
	action.LastError = lastError
	action.NextAttemptAt = ""
	action.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if status == "succeeded" || status == "revoked" {
		connector := s.operations.doc.Connectors[action.ConnectorID]
		connector.ConsecutiveFailures = 0
		connector.CircuitOpenUntil = ""
		s.operations.doc.Connectors[action.ConnectorID] = connector
	}
	if status == "failed" {
		connector := s.operations.doc.Connectors[action.ConnectorID]
		connector.ConsecutiveFailures++
		if connector.ConsecutiveFailures >= 5 {
			connector.CircuitOpenUntil = time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339Nano)
		}
		s.operations.doc.Connectors[action.ConnectorID] = connector
	}
	if action.ParentActionID != "" && (status == "succeeded" || status == "revoked") {
		parent := s.operations.doc.Actions[action.ParentActionID]
		if action.CreatedBy == "system-expiry" {
			parent.Status = "expired"
		} else {
			parent.Status = "revoked"
		}
		parent.UpdatedAt = action.UpdatedAt
		s.operations.doc.Actions[parent.ActionID] = parent
	}
	s.operations.doc.Actions[id] = action
	return s.operations.saveLocked()
}

func (s *Server) handleRevokeAction(w http.ResponseWriter, r *http.Request, id string) {
	if s.operations.db != nil && !s.operations.readView {
		s.revokeActionPostgres(w, r, id)
		return
	}
	if s.handleNativeCancel(w, r, id) {
		return
	}
	s.operations.mu.Lock()
	action, ok := s.operations.doc.Actions[id]
	if !ok {
		s.operations.mu.Unlock()
		writeError(w, 404, "action_not_found", "action not found")
		return
	}
	if existing, found, requeued := s.existingReleaseActionLocked(action); found {
		if requeued {
			if err := s.operations.saveLocked(); err != nil {
				s.operations.mu.Unlock()
				writeError(w, 500, "save_revoke_failed", err.Error())
				return
			}
			existing = s.operations.doc.Actions[existing.ActionID]
		}
		s.operations.mu.Unlock()
		if requeued {
			s.enqueueActionDelivery(existing.ActionID, true)
			s.appendAudit(r.Context(), "enforcement.revoke.retry", id, "accepted:"+existing.ActionID)
			writeJSON(w, http.StatusAccepted, existing)
		} else {
			writeJSON(w, http.StatusOK, existing)
		}
		return
	}
	if action.Status != "succeeded" {
		s.operations.mu.Unlock()
		writeError(w, 409, "action_not_revocable", "only succeeded actions can be revoked")
		return
	}
	reversal := s.newReleaseAction(action, "manual-revoke", time.Now().UTC())
	s.operations.doc.Actions[reversal.ActionID] = reversal
	if err := s.operations.saveLocked(); err != nil {
		s.operations.mu.Unlock()
		writeError(w, 500, "save_revoke_failed", err.Error())
		return
	}
	s.operations.mu.Unlock()
	s.enqueueActionDelivery(reversal.ActionID, true)
	s.appendAudit(r.Context(), "enforcement.revoke", id, "accepted")
	writeJSON(w, 202, reversal)
}

func (s *Server) newReleaseAction(parent EnforcementAction, actor string, now time.Time) EnforcementAction {
	return EnforcementAction{PolicyParameters: parent.PolicyParameters, ActionID: "action-" + shortToken(10), ParentActionID: parent.ActionID, IdempotencyKey: parent.IdempotencyKey + ":release", CaseID: parent.CaseID, ConnectorID: parent.ConnectorID, ActionType: "release", SubjectType: parent.SubjectType, SubjectID: parent.SubjectID, IP: parent.IP, AccountID: parent.AccountID, EndpointID: parent.EndpointID, SessionID: parent.SessionID, CampusID: parent.CampusID, Status: "pending", Mode: parent.Mode, EvidenceIDs: parent.EvidenceIDs, RulesetVersion: parent.RulesetVersion, CreatedBy: actor, CreatedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano)}
}

func (s *Server) processDueActions(now time.Time) {
	if s.operations.db != nil && !s.operations.readView {
		if err := s.processDueActionsPostgres(now); err != nil {
			s.operations.setHealthError(err)
		}
		return
	}
	type delivery struct {
		id     string
		revoke bool
	}
	deliver := []delivery{}
	changed := false
	s.operations.mu.Lock()
	for id, action := range s.operations.doc.Actions {
		if action.Status == "running" {
			lease := 90 * time.Second
			if action.PolicyParameters.NativeSelected {
				lease = 45 * time.Second
			}
			updated, err := time.Parse(time.RFC3339Nano, action.UpdatedAt)
			if err == nil && !updated.Add(lease).After(now) {
				action.Status = "pending"
				action.NextAttemptAt = ""
				s.operations.doc.Actions[id] = action
				changed = true
			}
		}
		if action.Status == "pending" {
			due, err := time.Parse(time.RFC3339Nano, action.NextAttemptAt)
			if action.NextAttemptAt == "" || err != nil || !due.After(now) {
				deliver = append(deliver, delivery{id: id, revoke: action.ActionType == "release"})
			}
		}
		if action.Status != "succeeded" || action.ExpiresAt == "" {
			continue
		}
		expires, err := time.Parse(time.RFC3339Nano, action.ExpiresAt)
		if err != nil || expires.After(now) {
			continue
		}
		if connector := s.operations.doc.Connectors[action.ConnectorID]; connector.ConnectorType == "srun4k" && action.PolicyParameters.Operation == "disable_account" {
			action.Status = "expired"
			action.UpdatedAt = formatDBTime(now)
			s.operations.doc.Actions[id] = action
			changed = true
			continue
		}
		hasRelease := false
		for _, existing := range s.operations.doc.Actions {
			if existing.ParentActionID == id && existing.ActionType == "release" {
				hasRelease = true
				break
			}
		}
		if !hasRelease {
			release := s.newReleaseAction(action, "system-expiry", now)
			s.operations.doc.Actions[release.ActionID] = release
			deliver = append(deliver, delivery{id: release.ActionID, revoke: true})
			changed = true
		}
	}
	var saveErr error
	if changed || s.operations.db != nil {
		saveErr = s.operations.saveLocked()
	}
	s.operations.mu.Unlock()
	if saveErr != nil {
		return
	}
	for _, item := range deliver {
		s.enqueueActionDelivery(item.id, item.revoke)
	}
}

func (s *Server) listActions(w http.ResponseWriter, r *http.Request) {
	s.operations.mu.Lock()
	items := mapValues(s.operations.doc.Actions)
	s.operations.mu.Unlock()
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt > items[j].CreatedAt })
	limit, _ := boundedInt(r.URL.Query().Get("limit"), 20, 1, 50)
	cursor, _ := cursorOffset(r.URL.Query().Get("cursor"))
	paged, page := paginate(items, cursor, limit)
	writeJSON(w, 200, map[string]any{"items": paged, "page": page})
}

func (s *Server) encryptConnectorSecret(value string) (string, error) {
	if len(s.actionMasterKey) < 16 {
		return "", fmt.Errorf("--action-master-key must contain at least 16 characters")
	}
	key := sha256.Sum256(s.actionMasterKey)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(value), nil)
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}
func (s *Server) decryptConnectorSecret(value string) (string, error) {
	data, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	key := sha256.Sum256(s.actionMasterKey)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(data) < gcm.NonceSize() {
		return "", fmt.Errorf("invalid encrypted connector secret")
	}
	plain, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
	return string(plain), err
}
