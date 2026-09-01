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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/store"
)

type ActionConnector struct {
	ConnectorID     string            `json:"connector_id"`
	Name            string            `json:"name"`
	EndpointURL     string            `json:"endpoint_url"`
	ActionMapping   map[string]string `json:"action_mapping"`
	Mode            string            `json:"mode"`
	Enabled         bool              `json:"enabled"`
	ShadowReady     bool              `json:"shadow_ready"`
	EncryptedSecret string            `json:"-"`
	UpdatedAt       string            `json:"updated_at"`
}

type EnforcementAction struct {
	ActionID        string   `json:"action_id"`
	IdempotencyKey  string   `json:"idempotency_key"`
	CaseID          string   `json:"case_id,omitempty"`
	ConnectorID     string   `json:"connector_id"`
	ActionType      string   `json:"action_type"`
	SubjectType     string   `json:"subject_type"`
	SubjectID       string   `json:"subject_id"`
	IP              string   `json:"ip,omitempty"`
	AccountID       string   `json:"account_id,omitempty"`
	EndpointID      string   `json:"endpoint_id,omitempty"`
	SessionID       string   `json:"session_id,omitempty"`
	CampusID        string   `json:"campus_id,omitempty"`
	Status          string   `json:"status"`
	Mode            string   `json:"mode"`
	DurationSeconds int      `json:"duration_seconds"`
	EvidenceIDs     []string `json:"evidence_ids"`
	RulesetVersion  string   `json:"ruleset_version,omitempty"`
	RemoteActionID  string   `json:"remote_action_id,omitempty"`
	RetryCount      int      `json:"retry_count"`
	CooldownUntil   string   `json:"cooldown_until,omitempty"`
	ExpiresAt       string   `json:"expires_at,omitempty"`
	LastError       string   `json:"last_error,omitempty"`
	CreatedBy       string   `json:"created_by"`
	CreatedAt       string   `json:"created_at"`
	UpdatedAt       string   `json:"updated_at"`
	Blockers        []string `json:"blockers,omitempty"`
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
	ConnectorID   string            `json:"connector_id"`
	Name          string            `json:"name"`
	EndpointURL   string            `json:"endpoint_url"`
	ActionMapping map[string]string `json:"action_mapping"`
	Mode          string            `json:"mode"`
	Enabled       bool              `json:"enabled"`
	ShadowReady   bool              `json:"shadow_ready"`
	Secret        string            `json:"secret"`
}

func (s *Server) handleActions(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/actions"), "/")
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
	if r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "revoke" {
		s.handleRevokeAction(w, r, parts[0])
		return
	}
	writeError(w, 404, "action_endpoint_not_found", "action endpoint not found")
}

func (s *Server) handleConnectors(w http.ResponseWriter, r *http.Request) {
	s.operations.mu.Lock()
	defer s.operations.mu.Unlock()
	if r.Method == http.MethodGet {
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
	if request.Mode == "active" && !request.ShadowReady {
		writeError(w, 409, "shadow_gate_required", "active mode requires shadow_ready=true")
		return
	}
	existing := s.operations.doc.Connectors[request.ConnectorID]
	encrypted := existing.EncryptedSecret
	if request.Secret != "" {
		value, err := s.encryptConnectorSecret(request.Secret)
		if err != nil {
			writeError(w, 409, "action_master_key_required", err.Error())
			return
		}
		encrypted = value
	}
	if encrypted == "" {
		writeError(w, 400, "connector_secret_required", "secret is required for a new connector")
		return
	}
	item := ActionConnector{ConnectorID: request.ConnectorID, Name: request.Name, EndpointURL: request.EndpointURL, ActionMapping: request.ActionMapping, Mode: request.Mode, Enabled: request.Enabled, ShadowReady: request.ShadowReady, EncryptedSecret: encrypted, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	s.operations.doc.Connectors[item.ConnectorID] = item
	if err := s.operations.saveLocked(); err != nil {
		writeError(w, 500, "save_connector_failed", err.Error())
		return
	}
	writeJSON(w, 200, item)
}

func (s *Server) handleEmergencyStop(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, 400, "bad_emergency_stop", err.Error())
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
	writeJSON(w, 200, map[string]any{"global_stop": body.Enabled})
}

func (s *Server) handleExecuteAction(w http.ResponseWriter, r *http.Request) {
	var request executeActionRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&request); err != nil {
		writeError(w, 400, "bad_action", err.Error())
		return
	}
	request.ActionType = firstNonEmptyString(request.ActionType, "quarantine")
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
	globalStop := s.operations.doc.GlobalStop
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
	if snapshot.Score < 90 {
		blockers = append(blockers, "risk_score_below_90")
	}
	if snapshot.Confidence < .90 {
		blockers = append(blockers, "risk_confidence_below_0_90")
	}
	hasStrong := false
	for _, item := range evidenceItems {
		if item.Type == "vpn_proxy_rule_match" && item.Confidence >= .90 {
			hasStrong = true
			break
		}
	}
	if !hasStrong {
		blockers = append(blockers, "explicit_proxy_rule_required")
	}
	if snapshot.ReviewStatus == "false_positive" || snapshot.ReviewStatus == "benign" {
		blockers = append(blockers, "manual_exception_applied")
	}
	if snapshot.AccountID == "" || snapshot.EndpointID == "" {
		blockers = append(blockers, "active_identity_session_required")
	} else {
		identityNow := time.Now().UTC()
		profile, found, identityErr := s.reader.GetEndpointIdentity(r.Context(), snapshot.EndpointID, store.Query{From: identityNow.Add(-24 * time.Hour).Format(time.RFC3339Nano), To: identityNow.Format(time.RFC3339Nano), Limit: 50})
		if identityErr != nil {
			blockers = append(blockers, "identity_data_unavailable")
		} else if !found || !hasCurrentIdentitySession(profile.Sessions, snapshot.AccountID, request.IP) {
			blockers = append(blockers, "active_identity_session_required")
		}
	}
	if !connectorOK || !connector.Enabled {
		blockers = append(blockers, "enabled_connector_required")
	}
	if connector.Mode == "active" && !connector.ShadowReady {
		blockers = append(blockers, "shadow_gate_required")
	}
	if globalStop {
		blockers = append(blockers, "global_emergency_stop")
	}
	now := time.Now().UTC()
	s.operations.mu.Lock()
	for _, previous := range s.operations.doc.Actions {
		if previous.SubjectID == firstNonEmptyString(snapshot.AccountID, snapshot.EndpointID, request.IP) && previous.Status == "succeeded" {
			if until, e := time.Parse(time.RFC3339Nano, previous.CooldownUntil); e == nil && until.After(now) {
				blockers = append(blockers, "subject_cooldown_active")
			}
		}
	}
	campusCount, hourCount := 0, 0
	for _, previous := range s.operations.doc.Actions {
		created, _ := time.Parse(time.RFC3339Nano, previous.CreatedAt)
		if previous.Status == "succeeded" && now.Sub(created) <= time.Hour {
			hourCount++
			if request.CampusID != "" && previous.CampusID == request.CampusID && now.Sub(created) <= 10*time.Minute {
				campusCount++
			}
		}
	}
	s.operations.mu.Unlock()
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
	action := EnforcementAction{ActionID: "action-" + shortToken(10), IdempotencyKey: idempotency, CaseID: request.CaseID, ConnectorID: request.ConnectorID, ActionType: request.ActionType, SubjectType: "account", SubjectID: firstNonEmptyString(snapshot.AccountID, snapshot.EndpointID, request.IP), IP: request.IP, AccountID: snapshot.AccountID, EndpointID: snapshot.EndpointID, CampusID: request.CampusID, Status: status, Mode: mode, DurationSeconds: request.DurationSeconds, EvidenceIDs: snapshot.EvidenceIDs, CooldownUntil: now.Add(24 * time.Hour).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Duration(request.DurationSeconds) * time.Second).Format(time.RFC3339Nano), CreatedBy: actor, CreatedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano), Blockers: blockers}
	s.operations.mu.Lock()
	s.operations.doc.Actions[action.ActionID] = action
	err = s.operations.saveLocked()
	s.operations.mu.Unlock()
	if err != nil {
		writeError(w, 500, "save_action_failed", err.Error())
		return
	}
	if status == "pending" {
		go s.deliverAction(action.ActionID, false)
	}
	s.appendAudit(r.Context(), "enforcement.execute", action.ActionID, status)
	writeJSON(w, http.StatusAccepted, action)
}

func hasCurrentIdentitySession(sessions []store.AccountSession, accountID, ip string) bool {
	for _, session := range sessions {
		ended := session.EndedAt != "" || session.SessionStatus == "ended" || session.SessionStatus == "stop" || session.SessionStatus == "logout"
		if !ended && session.AccountID == accountID && session.IP == ip && session.IdentityConfidence >= .8 {
			return true
		}
	}
	return false
}

func (s *Server) deliverAction(actionID string, revoke bool) {
	s.operations.mu.Lock()
	action, ok := s.operations.doc.Actions[actionID]
	connector := s.operations.doc.Connectors[action.ConnectorID]
	if !ok {
		s.operations.mu.Unlock()
		return
	}
	if s.operations.doc.GlobalStop || !connector.Enabled || connector.Mode != "active" {
		action.Status = "blocked"
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
	_ = s.operations.saveLocked()
	s.operations.mu.Unlock()
	secret, err := s.decryptConnectorSecret(connector.EncryptedSecret)
	if err != nil {
		s.finishAction(actionID, "failed", "", err.Error())
		return
	}
	payload := map[string]any{"action_id": action.ActionID, "idempotency_key": action.IdempotencyKey, "case_id": action.CaseID, "action": action.ActionType, "revoke": revoke, "subject": map[string]any{"account_id": action.AccountID, "endpoint_id": action.EndpointID, "ip": action.IP, "campus_id": action.CampusID}, "duration_seconds": action.DurationSeconds, "evidence_ids": action.EvidenceIDs, "expires_at": action.ExpiresAt}
	data, _ := json.Marshal(payload)
	mapped := connector.ActionMapping[action.ActionType]
	if mapped != "" {
		payload["action"] = mapped
		data, _ = json.Marshal(payload)
	}
	lastError := ""
	for attempt := 0; attempt < 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, connector.EndpointURL, bytes.NewReader(data))
		signature := hmac.New(sha256.New, []byte(secret))
		_, _ = signature.Write(data)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Proxy-Sentinel-Signature", "sha256="+fmt.Sprintf("%x", signature.Sum(nil)))
		req.Header.Set("Idempotency-Key", action.IdempotencyKey)
		resp, requestErr := http.DefaultClient.Do(req)
		if requestErr == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			var result struct {
				RemoteActionID string `json:"action_id"`
			}
			_ = json.Unmarshal(body, &result)
			cancel()
			s.finishAction(actionID, map[bool]string{true: "revoked", false: "succeeded"}[revoke], result.RemoteActionID, "")
			return
		}
		if resp != nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			lastError = fmt.Sprintf("status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
		} else {
			lastError = requestErr.Error()
		}
		cancel()
		time.Sleep(time.Duration(1<<attempt) * time.Second)
	}
	s.finishAction(actionID, "failed", "", lastError)
}

func (s *Server) finishAction(id, status, remoteID, lastError string) {
	s.operations.mu.Lock()
	defer s.operations.mu.Unlock()
	action := s.operations.doc.Actions[id]
	action.Status = status
	action.RemoteActionID = firstNonEmptyString(remoteID, action.RemoteActionID)
	action.LastError = lastError
	action.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if status == "failed" {
		action.RetryCount = 3
	}
	s.operations.doc.Actions[id] = action
	_ = s.operations.saveLocked()
}

func (s *Server) handleRevokeAction(w http.ResponseWriter, r *http.Request, id string) {
	s.operations.mu.Lock()
	action, ok := s.operations.doc.Actions[id]
	s.operations.mu.Unlock()
	if !ok {
		writeError(w, 404, "action_not_found", "action not found")
		return
	}
	if action.Status != "succeeded" {
		writeError(w, 409, "action_not_revocable", "only succeeded actions can be revoked")
		return
	}
	go s.deliverAction(id, true)
	s.appendAudit(r.Context(), "enforcement.revoke", id, "accepted")
	writeJSON(w, 202, action)
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
