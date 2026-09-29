package controlplane

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"proxy-sentinel/internal/proxyprotocol"
	"proxy-sentinel/internal/sharedaccess"
	"reflect"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/store"
)

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request, path string) {
	if s.operations == nil {
		writeError(w, 503, "policies_unavailable", "策略存储不可用")
		return
	}
	if strings.HasPrefix(path, "/policy-executions/") {
		if r.Method == http.MethodGet && strings.HasSuffix(path, "/approval-preview") {
			s.handlePolicyApprovalPreview(w, r, strings.TrimSuffix(strings.TrimPrefix(path, "/policy-executions/"), "/approval-preview"))
			return
		}

		s.handlePolicyExecutionMutation(w, r, path)
		return
	}
	if strings.HasPrefix(path, "/accounts/") && strings.HasSuffix(path, "/quota") {
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/accounts/"), "/quota")
		s.policySimulation(w, r, id, "")
		return
	}
	if path == "/policy-executions" && r.Method == http.MethodGet {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		items, err := s.operations.readPolicyExecutions(ctx, r.URL.Query().Get("account_id"))
		if err != nil {
			writeError(w, 503, "policy_storage_failed", err.Error())
			return
		}
		sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
		rows := []proxyprotocol.Result{}
		var evidenceSessions []policy.Session
		needsProxyEvidence := false
		for _, item := range items {
			if len(item.EvidenceIDs) > 0 && (item.Definition.Trigger == "explicit_proxy" || item.Definition.Trigger == "") {
				needsProxyEvidence = true
				break
			}
		}
		if needsProxyEvidence {
			rows, err = s.proxyRows(ctx)
			if err != nil {
				writeError(w, 503, "proxy_evidence_unavailable", err.Error())
				return
			}
			if len(rows) > 0 {
				if reader, ok := s.reader.(store.PolicyIdentityReader); ok {
					evidenceSessions, err = s.policySessions(ctx, reader, time.Now().UTC())
					if err != nil {
						writeError(w, 503, "identity_unavailable", err.Error())
						return
					}
				}
			}
		}
		views := []struct {
			policy.Execution
			ProxyEvidence []proxyprotocol.Result `json:"proxy_evidence"`
		}{}
		for _, e := range items {
			proof := []proxyprotocol.Result{}
			for _, row := range rows {
				for _, id := range e.EvidenceIDs {
					if row.ID == id {
						proof = append(proof, proxyprotocol.Attribute(row, evidenceSessions))
					}
				}
			}
			views = append(views, struct {
				policy.Execution
				ProxyEvidence []proxyprotocol.Result `json:"proxy_evidence"`
			}{e, proof})
		}
		writeJSON(w, 200, map[string]any{"items": views})
		return
	}
	id := strings.TrimPrefix(path, "/policies/")
	if strings.HasSuffix(id, "/simulate") && r.Method == http.MethodPost {
		s.policySimulation(w, r, "", strings.TrimSuffix(id, "/simulate"))
		return
	}
	if path == "/policies" && r.Method == http.MethodGet {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		items, err := s.operations.readPolicyDefinitions(ctx)
		if err != nil {
			writeError(w, 503, "policy_storage_failed", err.Error())
			return
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].Priority != items[j].Priority {
				return items[i].Priority > items[j].Priority
			}
			return items[i].ID < items[j].ID
		})
		writeJSON(w, 200, map[string]any{"items": items})
		return
	}
	if (path == "/policies" && r.Method == http.MethodPost) || (strings.HasPrefix(path, "/policies/") && r.Method == http.MethodPut) {
		var p policy.Definition
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil {
			writeError(w, 400, "invalid_policy", err.Error())
			return
		}
		creating := r.Method == http.MethodPost
		if creating {
			if p.ID == "" {
				p.ID = policy.StableID(p.Name, time.Now().UTC().String())
			}
			p.Enabled = false
			p.Mode = "observe"
		} else if p.ID != id {
			writeError(w, 400, "invalid_policy", "策略 ID 与路径不一致")
			return
		}
		if err := p.Validate(); err != nil {
			writeError(w, 400, "invalid_policy", err.Error())
			return
		}
		if s.operations.db != nil {
			ctx, cancel := contextWithRequestTimeout(r.Context())
			defer cancel()
			saved, err := s.operations.writePolicyDefinition(ctx, p, creating)
			if err == errPolicyConflict {
				writeError(w, 409, "policy_conflict", err.Error())
				return
			}
			if err != nil {
				writeError(w, 503, "policy_storage_failed", err.Error())
				return
			}
			s.appendAudit(r.Context(), "policies.write", saved.ID, "success")
			writeJSON(w, 200, saved)
			return
		}
		s.operations.mu.Lock()
		old, exists := s.operations.doc.Policies[p.ID]
		if s.operations.lockErr != nil {
			err := s.operations.lockErr
			s.operations.mu.Unlock()
			writeError(w, 503, "policy_storage_failed", err.Error())
			return
		}
		if creating && exists || !creating && !exists {
			s.operations.mu.Unlock()
			writeError(w, 409, "policy_conflict", "策略已存在或待更新策略不存在")
			return
		}
		p.Revision = old.Revision + 1
		s.operations.doc.Policies[p.ID] = p
		err := s.operations.saveLocked()
		if err != nil {
			if exists {
				s.operations.doc.Policies[p.ID] = old
			} else {
				delete(s.operations.doc.Policies, p.ID)
			}
		}
		s.operations.mu.Unlock()
		if err != nil {
			writeError(w, 503, "policy_storage_failed", err.Error())
			return
		}
		s.appendAudit(r.Context(), "policies.write", p.ID, "success")
		writeJSON(w, 200, p)
		return
	}
	writeError(w, 405, "method_not_allowed", "不支持的策略操作")
}

func (s *Server) policySimulation(w http.ResponseWriter, r *http.Request, account, id string) {
	at := time.Now().UTC()
	if r.Method == http.MethodPost {
		var body struct {
			AccountID string     `json:"account_id"`
			At        *time.Time `json:"at"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			writeError(w, 400, "invalid_simulation", err.Error())
			return
		}
		account = body.AccountID
		if body.At != nil {
			at = *body.At
		}
	}
	if account == "" {
		writeError(w, 400, "account_required", "需要账号 ID")
		return
	}
	reader, ok := s.reader.(store.PolicyIdentityReader)
	if !ok {
		writeError(w, 503, "identity_unavailable", "身份数据源不支持配额查询")
		return
	}
	sessions, err := s.policySessions(r.Context(), reader, at)
	if err != nil {
		writeError(w, 503, "identity_unavailable", err.Error())
		return
	}
	defs, err := s.operations.readPolicyDefinitions(r.Context())
	if err != nil {
		writeError(w, 503, "policy_storage_failed", err.Error())
		return
	}
	found := false
	for _, definition := range defs {
		if definition.ID == id {
			found = true
			break
		}
	}
	if id != "" && !found {
		writeError(w, 404, "policy_not_found", "策略不存在")
		return
	}
	selected, explanations := policy.Select(defs, account, sessions, at)
	sharedRows, sharedErr := s.sharedWindows(r.Context(), at)
	evaluations := []map[string]any{}
	for _, p := range defs {
		if id != "" && p.ID != id {
			continue
		}
		input := policy.Input{AccountID: account, Reasons: []string{"risk_evidence_not_evaluated"}}
		item := map[string]any{"policy_id": p.ID}
		if p.Trigger == "quota_exceeded" {
			q := policy.EvaluateQuota(account, sessions, p.Limits, at)
			item["quota"] = q
			input.Known = q.State != "unknown"
			input.Violated = q.State == "exceeded"
			input.Reasons = q.Reasons
		}
		if p.Trigger == "explicit_proxy" {
			input = s.proxyPolicyInput(r.Context(), p, account, sessions, at)
			rows, err := s.proxyRows(r.Context())
			if err != nil {
				writeError(w, 503, "proxy_evidence_unavailable", err.Error())
				return
			}
			proof := []proxyprotocol.Result{}
			for _, row := range rows {
				for _, id := range input.EvidenceIDs {
					if row.ID == id {
						proof = append(proof, proxyprotocol.Attribute(row, sessions))
					}
				}
			}
			item["proxy_evidence"] = proof
		}
		if p.Trigger == "shared_access" {
			input = policy.Input{AccountID: account, Reasons: []string{"shared_evidence_unavailable"}}
			if sharedErr == nil {
				rows := sharedaccess.AccountResults(account, sharedRows, s.sharedConfig, sessions, at, time.Duration(p.WindowSeconds)*time.Second)
				item["shared_evaluation"] = rows
				input = sharedaccess.Input(account, rows, p.Mode)
			} else {
				item["shared_error"] = sharedErr.Error()
			}
		}
		item["input"] = input
		evaluations = append(evaluations, item)
	}
	sort.Slice(evaluations, func(i, j int) bool {
		return evaluations[i]["policy_id"].(string) < evaluations[j]["policy_id"].(string)
	})
	accountSessions := []policy.Session{}
	for _, session := range sessions {
		if session.AccountID == account {
			accountSessions = append(accountSessions, session)
		}
	}
	writeJSON(w, 200, map[string]any{"account_id": account, "at": at, "inventory": policy.EvaluateQuota(account, sessions, policy.Limits{}, at), "sessions": accountSessions, "selected": selected, "explanations": explanations, "evaluations": evaluations})
}

func (s *Server) handlePolicyExecutionMutation(w http.ResponseWriter, r *http.Request, path string) {
	if s.operations.db != nil && !s.operations.readView {
		s.mutatePolicyExecutionPostgres(w, r, path)
		return
	}
	parts := strings.Split(strings.TrimPrefix(path, "/policy-executions/"), "/")
	if len(parts) != 2 || r.Method != http.MethodPost || (parts[1] != "approve" && parts[1] != "revoke") {
		writeError(w, 405, "invalid_execution_operation", "操作不支持")
		return
	}
	var confirmation struct {
		Fingerprint string `json:"fingerprint"`
	}
	if parts[1] == "approve" && r.Body != nil && r.ContentLength != 0 {
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		dec.DisallowUnknownFields()
		if dec.Decode(&confirmation) != nil {
			writeError(w, 400, "bad_approval", "确认请求格式错误")
			return
		}
		var trailing any
		if dec.Decode(&trailing) != io.EOF {
			writeError(w, 400, "bad_approval", "确认请求存在多余内容")
			return
		}

	}
	var approvalSessions []policy.Session
	var approvalSharedRows []sharedaccess.Window
	var approvalSharedErr error
	if parts[1] == "approve" {
		approvalSharedRows, approvalSharedErr = s.sharedWindows(r.Context(), time.Now().UTC())
		if reader, ok := s.reader.(store.PolicyIdentityReader); ok {
			var err error
			approvalSessions, err = s.policySessions(r.Context(), reader, time.Now().UTC())
			if err != nil {
				writeError(w, 503, "identity_unavailable", err.Error())
				return
			}
		}
	}
	s.operations.mu.Lock()
	e, ok := s.operations.doc.PolicyExecutions[parts[0]]
	if s.operations.lockErr != nil {
		err := s.operations.lockErr
		s.operations.mu.Unlock()
		writeError(w, 503, "policy_storage_failed", err.Error())
		return
	}
	if !ok {
		s.operations.mu.Unlock()
		writeError(w, 404, "execution_not_found", "执行轮次不存在")
		return
	}
	before := e
	actionsBefore := make(map[string]EnforcementAction, len(s.operations.doc.Actions))
	for id, a := range s.operations.doc.Actions {
		actionsBefore[id] = a
	}
	e.Stages = append([]policy.StageState(nil), e.Stages...)
	now := time.Now().UTC()
	if parts[1] == "revoke" {
		s.releasePolicyActionsLocked(e, now, "manual-revoke")
		e = policy.Revoke(e, now)
	} else {
		definitions := []policy.Definition{}
		for _, p := range s.operations.doc.Policies {
			definitions = append(definitions, p)
		}
		if e.Definition.Mode != "manual" || validateCurrentPolicySelection(e, definitions, approvalSessions, now) != nil {
			s.operations.mu.Unlock()
			writeError(w, 409, "policy_review_invalid", "策略已变化或不再适用，请重新试算")
			return
		}
		if e.Definition.Trigger == "quota_exceeded" && policy.EvaluateQuota(e.AccountID, approvalSessions, e.Definition.Limits, now).State != "exceeded" {
			s.operations.mu.Unlock()
			writeError(w, 409, "quota_review_invalid", "当前配额违规无法确认")
			return
		}
		if e.Definition.Trigger == "shared_access" {
			input := sharedaccess.Input(e.AccountID, sharedaccess.AccountResults(e.AccountID, approvalSharedRows, s.sharedConfig, approvalSessions, now, time.Duration(e.Definition.WindowSeconds)*time.Second), e.Definition.Mode)
			if approvalSharedErr != nil || !input.Known || !input.Violated || !reflect.DeepEqual(input.EvidenceIDs, e.EvidenceIDs) {
				s.operations.mu.Unlock()
				writeError(w, 409, "shared_review_invalid", "共享证据已变化、过期或账号身份无法确认，请重新试算")
				return
			}
		}
		if e.Definition.Trigger == "explicit_proxy" {
			defs := []policy.Definition{}
			for _, p := range s.operations.doc.Policies {
				defs = append(defs, p)
			}
			chosen, _ := policy.Select(defs, e.AccountID, approvalSessions, now)
			selected := false
			for _, p := range chosen {
				if p.ID == e.PolicyID && p.Revision == e.Definition.Revision && p.Mode == "manual" {
					selected = true
				}
			}
			if !selected {
				s.operations.mu.Unlock()
				writeError(w, 409, "proxy_policy_changed", "策略已变更或账号已豁免，请重新试算")
				return
			}
			input := s.proxyPolicyInput(r.Context(), e.Definition, e.AccountID, approvalSessions, now)
			if e.Definition.Mode != "manual" || !input.Known || !input.Violated || !reflect.DeepEqual(input.EvidenceIDs, e.EvidenceIDs) {
				s.operations.mu.Unlock()
				writeError(w, 409, "proxy_review_invalid", "证据已过期、身份变化或需重新复核")
				return
			}
		}
		found := false
		for i := range e.Stages {
			if e.Stages[i].Status == "awaiting_approval" {
				if e.Definition.Trigger == "shared_access" && (i >= len(e.Definition.Stages) || e.Definition.Stages[i].Action != "disconnect") {
					s.operations.mu.Unlock()
					writeError(w, 409, "shared_action_unavailable", "共享证据当前仅支持人工确认下线")
					return
				}
				if i < len(e.Definition.Stages) && (e.Definition.Stages[i].Action == "disconnect" || confirmation.Fingerprint != "") {
					preview, err := buildPolicyApprovalPreview(e, approvalSessions, now)
					if err != nil || confirmation.Fingerprint == "" || preview.Fingerprint != confirmation.Fingerprint {
						s.operations.mu.Unlock()
						writeError(w, 409, "approval_changed", "确认内容已变化，请重新预览会话、策略与证据")
						return
					}
				}

				if i < len(e.Definition.Stages) && e.Definition.Stages[i].Action == "disconnect" {
					bindings, err := policy.SessionApprovalBindings(e.AccountID, approvalSessions, now)
					if err != nil || len(bindings) == 0 {
						s.operations.mu.Unlock()
						writeError(w, 409, "session_approval_unavailable", "账号会话身份不完整，请刷新后重新确认")
						return
					}
					if err := s.resetUnsentDisconnectsLocked(&e, i, confirmation.Fingerprint, now); err != nil {
						s.operations.mu.Unlock()
						writeError(w, 409, "prior_action_uncertain", "已有动作结果尚未核清，不能通过重新确认重发")
						return
					}
					e.Stages[i].ApprovedSessionBindings = bindings
				}

				e.Stages[i].ApprovedEvidenceIDs = append([]string{}, e.EvidenceIDs...)
				e.Stages[i].Status = "pending_action"
				e.State = "pending_action"
				if i < len(e.Definition.Stages) && e.Definition.Stages[i].Action == "disconnect" {
					s.createPolicyActionsLocked(&e, i, approvalSessions, now)
					e.State = e.Stages[i].Status
				}
				found = true
				break
			}
		}
		if !found {
			s.operations.mu.Unlock()
			writeError(w, 409, "no_pending_approval", "没有待确认阶段")
			return
		}
	}
	s.operations.doc.PolicyExecutions[e.ID] = e
	err := s.operations.saveLocked()
	if err != nil {
		s.operations.doc.PolicyExecutions[e.ID] = before
		s.operations.doc.Actions = actionsBefore
	}
	s.operations.mu.Unlock()
	if err != nil {
		writeError(w, 503, "policy_storage_failed", err.Error())
		return
	}
	s.appendAudit(r.Context(), "policies."+parts[1], e.ID, "success")
	writeJSON(w, 200, e)
}
