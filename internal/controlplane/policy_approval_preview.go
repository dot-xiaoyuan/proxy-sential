package controlplane

import (
	"encoding/json"
	"fmt"
	"net/http"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/store"
	"sort"
	"time"
)

type policyApprovalPreview struct {
	Fingerprint string           `json:"fingerprint"`
	AccountID   string           `json:"account_id"`
	StageIndex  int              `json:"stage_index"`
	Stage       policy.Stage     `json:"stage"`
	EvidenceIDs []string         `json:"evidence_ids"`
	Sessions    []policy.Session `json:"sessions"`
}

func buildPolicyApprovalPreview(e policy.Execution, ss []policy.Session, now time.Time) (policyApprovalPreview, error) {
	bindings, err := policy.SessionApprovalBindings(e.AccountID, ss, now)
	if err != nil || len(bindings) == 0 {
		return policyApprovalPreview{}, fmt.Errorf("current account sessions unavailable")
	}
	for i, st := range e.Stages {
		if st.Status != "awaiting_approval" || i >= len(e.Definition.Stages) {
			continue
		}
		evidence := append([]string{}, e.EvidenceIDs...)
		sort.Strings(evidence)
		// StableID serializes its arguments, so include the full serialized definition
		// via the policy's existing canonical JSON helper below.
		fingerprint := policy.StableID(e.ID, fmt.Sprint(e.Episode), st.Key, fmt.Sprint(i), approvalJSON(e.Definition), approvalJSON(evidence), approvalJSON(bindings))
		rows := []policy.Session{}
		for _, s := range ss {
			if s.AccountID == e.AccountID && s.State(now) == "active" {
				rows = append(rows, s)
			}
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].ID == rows[j].ID {
				return rows[i].IP < rows[j].IP
			}
			return rows[i].ID < rows[j].ID
		})
		return policyApprovalPreview{Fingerprint: fingerprint, AccountID: e.AccountID, StageIndex: i, Stage: e.Definition.Stages[i], EvidenceIDs: evidence, Sessions: rows}, nil
	}
	return policyApprovalPreview{}, fmt.Errorf("no pending approval stage")
}

func (s *Server) handlePolicyApprovalPreview(w http.ResponseWriter, r *http.Request, id string) {
	reader, ok := s.reader.(store.PolicyIdentityReader)
	if !ok {
		writeError(w, 503, "identity_unavailable", "身份来源不可用")
		return
	}
	now := time.Now().UTC()
	ss, err := s.policySessions(r.Context(), reader, now)
	if err != nil {
		writeError(w, 503, "identity_unavailable", "身份清单读取失败")
		return
	}
	e, exists, err := s.operations.readPolicyExecution(r.Context(), id)
	if err != nil {
		writeError(w, 503, "policy_storage_failed", err.Error())
		return
	}
	if !exists {
		writeError(w, 404, "execution_not_found", "执行轮次不存在")
		return
	}
	if entries, err := s.whitelist.list(r.Context()); err != nil {
		writeError(w, 503, "whitelist_unavailable", "白名单读取失败")
		return
	} else if policy.MatchAccountWhitelist(entries, e.AccountID, ss, now) != nil {
		writeError(w, 409, "whitelist_suppressed", "命中白名单，策略动作已禁止")
		return
	}
	preview, err := buildPolicyApprovalPreview(e, ss, now)
	if err != nil {
		writeError(w, 409, "approval_preview_unavailable", "会话身份不完整或没有待确认阶段")
		return
	}
	writeJSON(w, 200, preview)
}

func approvalJSON(value any) string { body, _ := json.Marshal(value); return string(body) }
