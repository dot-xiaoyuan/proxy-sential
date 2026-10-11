package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/poison"
	"proxy-sentinel/internal/store"
)

const destinationTargetObservationLimit = 200000

type destinationTargetRequest struct {
	RuleID             string   `json:"rule_id"`
	Name               string   `json:"name"`
	Enabled            bool     `json:"enabled"`
	BehaviorType       string   `json:"behavior_type"`
	TargetType         string   `json:"target_type"`
	Targets            []string `json:"targets"`
	WindowSeconds      int      `json:"window_seconds"`
	Threshold          int      `json:"threshold"`
	Direction          string   `json:"direction"`
	PushEnabled        bool     `json:"push_enabled"`
	PushWithoutAccount bool     `json:"push_without_account"`
}

func (s *Server) destinationTargetStore() (store.DestinationTargetStore, bool) {
	if s.reader == nil {
		return nil, false
	}
	value, ok := s.reader.(store.DestinationTargetStore)
	return value, ok
}

func (s *Server) destinationTargetObservations(ctx context.Context, since time.Time) ([]poison.Observation, error) {
	reader, ok := s.reader.(interface {
		ListDestinationObservations(context.Context, time.Time, int) ([]poison.Observation, error)
	})
	if !ok {
		return nil, fmt.Errorf("destination observations unavailable")
	}
	return reader.ListDestinationObservations(ctx, since, destinationTargetObservationLimit)
}

func (s *Server) handleDestinationTargets(w http.ResponseWriter, r *http.Request, path string) {
	store_, ok := s.destinationTargetStore()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "destination_targets_unavailable", "内网目标访问存储不可用")
		return
	}
	rest := strings.Trim(strings.TrimPrefix(path, "/destination-targets"), "/")
	switch {
	case rest == "rules":
		s.handleDestinationTargetRules(w, r, store_)
	case strings.HasPrefix(rest, "rules/"):
		s.handleDestinationTargetRule(w, r, store_, strings.TrimPrefix(rest, "rules/"))
	case rest == "findings":
		s.handleDestinationTargetFindings(w, r, store_)
	default:
		writeError(w, http.StatusNotFound, "not_found", "接口不存在")
	}
}

func (s *Server) handleDestinationTargetRules(w http.ResponseWriter, r *http.Request, storage store.DestinationTargetStore) {
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	switch r.Method {
	case http.MethodGet:
		rules, err := storage.ListDestinationTargetRules(ctx)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "destination_targets_unavailable", "规则读取失败")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": rules, "behavior_types": []string{poison.BehaviorConfiguredRange, poison.BehaviorHighFrequency}})
	case http.MethodPost:
		if s.readOnly {
			writeError(w, http.StatusForbidden, "read_only", "只读模式禁止修改检测规则")
			return
		}
		var request destinationTargetRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "bad_destination_target_rule", "请求格式不正确")
			return
		}
		rule := poison.Rule{RuleID: request.RuleID, Name: request.Name, Enabled: request.Enabled, BehaviorType: request.BehaviorType, TargetType: request.TargetType, Targets: request.Targets, WindowSeconds: request.WindowSeconds, Threshold: request.Threshold, Direction: request.Direction}
		if err := poison.ValidateRule(&rule); err != nil {
			writeError(w, http.StatusBadRequest, "bad_destination_target_rule", err.Error())
			return
		}
		writer, ok := storage.(interface {
			UpsertDestinationTargetRule(context.Context, poison.Rule, bool, bool, string, bool) (store.DestinationTargetRule, error)
		})
		if !ok {
			writeError(w, http.StatusServiceUnavailable, "destination_targets_unavailable", "规则写入不可用")
			return
		}
		saved, err := writer.UpsertDestinationTargetRule(ctx, rule, request.PushEnabled, request.PushWithoutAccount, sessionFromContext(ctx).User.ID, true)
		if err != nil {
			if strings.Contains(err.Error(), "duplicate key value") {
				writeError(w, http.StatusConflict, "destination_target_rule_exists", "规则标识已存在")
				return
			}
			writeError(w, http.StatusBadRequest, "bad_destination_target_rule", err.Error())
			return
		}
		s.appendAudit(ctx, "destination_target.rule_created", saved.RuleID, "succeeded")
		writeJSON(w, http.StatusOK, saved)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "该接口不支持此操作")
	}
}

func (s *Server) handleDestinationTargetRule(w http.ResponseWriter, r *http.Request, storage store.DestinationTargetStore, rest string) {
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	parts := strings.SplitN(strings.Trim(rest, "/"), "/", 2)
	id := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	if id == "" {
		writeError(w, http.StatusNotFound, "not_found", "接口不存在")
		return
	}
	if action == "preview" {
		s.handleDestinationTargetPreview(w, r, storage, id)
		return
	}
	if action != "" {
		writeError(w, http.StatusNotFound, "not_found", "接口不存在")
		return
	}
	writer, ok := storage.(interface {
		GetDestinationTargetRule(context.Context, string) (store.DestinationTargetRule, error)
		UpsertDestinationTargetRule(context.Context, poison.Rule, bool, bool, string, bool) (store.DestinationTargetRule, error)
		DeleteDestinationTargetRule(context.Context, string) error
	})
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "destination_targets_unavailable", "规则写入不可用")
		return
	}
	switch r.Method {
	case http.MethodGet:
		rule, err := writer.GetDestinationTargetRule(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "destination_target_rule_not_found", "规则不存在")
			return
		}
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "destination_targets_unavailable", "规则读取失败")
			return
		}
		writeJSON(w, http.StatusOK, rule)
	case http.MethodPut:
		if s.readOnly {
			writeError(w, http.StatusForbidden, "read_only", "只读模式禁止修改检测规则")
			return
		}
		if _, err := writer.GetDestinationTargetRule(ctx, id); err != nil {
			writeError(w, http.StatusNotFound, "destination_target_rule_not_found", "规则不存在")
			return
		}
		var request destinationTargetRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "bad_destination_target_rule", "请求格式不正确")
			return
		}
		rule := poison.Rule{RuleID: id, Name: request.Name, Enabled: request.Enabled, BehaviorType: request.BehaviorType, TargetType: request.TargetType, Targets: request.Targets, WindowSeconds: request.WindowSeconds, Threshold: request.Threshold, Direction: request.Direction}
		if err := poison.ValidateRule(&rule); err != nil {
			writeError(w, http.StatusBadRequest, "bad_destination_target_rule", err.Error())
			return
		}
		saved, err := writer.UpsertDestinationTargetRule(ctx, rule, request.PushEnabled, request.PushWithoutAccount, sessionFromContext(ctx).User.ID, false)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_destination_target_rule", err.Error())
			return
		}
		s.appendAudit(ctx, "destination_target.rule_updated", saved.RuleID, "succeeded")
		writeJSON(w, http.StatusOK, saved)
	case http.MethodDelete:
		if s.readOnly {
			writeError(w, http.StatusForbidden, "read_only", "只读模式禁止删除检测规则")
			return
		}
		if err := writer.DeleteDestinationTargetRule(ctx, id); err != nil {
			writeError(w, http.StatusNotFound, "destination_target_rule_not_found", "规则不存在")
			return
		}
		s.appendAudit(ctx, "destination_target.rule_deleted", id, "succeeded")
		writeJSON(w, http.StatusOK, map[string]any{"rule_id": id, "deleted": true})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "该接口不支持此操作")
	}
}

func (s *Server) handleDestinationTargetFindings(w http.ResponseWriter, r *http.Request, storage store.DestinationTargetStore) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "该接口不支持此操作")
		return
	}
	reader, ok := storage.(interface {
		ListDestinationTargetFindings(context.Context, string, string, int, int) ([]store.DestinationTargetFinding, int, error)
	})
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "destination_targets_unavailable", "发现记录读取不可用")
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
	items, total, err := reader.ListDestinationTargetFindings(ctx, strings.TrimSpace(r.URL.Query().Get("rule_id")), strings.TrimSpace(r.URL.Query().Get("subject_ip")), limit, cursor)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "destination_targets_unavailable", "发现记录读取失败")
		return
	}
	page := store.Page{Limit: limit, Total: total}
	if cursor+limit < total {
		next := fmt.Sprintf("%d", cursor+limit)
		page.NextCursor = &next
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "page": page})
}

// preview evaluates a rule against the trailing window without persisting
// findings or enforcing anything.
func (s *Server) handleDestinationTargetPreview(w http.ResponseWriter, r *http.Request, storage store.DestinationTargetStore, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "该接口不支持此操作")
		return
	}
	reader, ok := storage.(interface {
		GetDestinationTargetRule(context.Context, string) (store.DestinationTargetRule, error)
	})
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "destination_targets_unavailable", "规则读取不可用")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	rule, err := reader.GetDestinationTargetRule(ctx, id)
	if err != nil {
		writeError(w, http.StatusNotFound, "destination_target_rule_not_found", "规则不存在")
		return
	}
	converted := destinationTargetRuleToPoison(rule)
	enabled := converted.Enabled
	converted.Enabled = true
	observations, err := s.destinationTargetObservations(ctx, time.Now().UTC().Add(-time.Duration(converted.WindowSeconds)*time.Second))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "destination_targets_unavailable", "观测数据读取失败")
		return
	}
	findings := poison.Evaluate(converted, observations)
	items := make([]map[string]any, 0, len(findings))
	for _, finding := range findings {
		items = append(items, map[string]any{
			"subject_ip":          finding.SubjectIP,
			"matched_targets":     finding.MatchedTargets,
			"unique_destinations": finding.UniqueDestinations,
			"hit_count":           finding.HitCount,
			"direction":           finding.Direction,
			"first_seen":          finding.FirstSeen.UTC().Format(time.RFC3339),
			"last_seen":           finding.LastSeen.UTC().Format(time.RFC3339),
		})
	}
	converted.Enabled = enabled
	writeJSON(w, http.StatusOK, map[string]any{"rule_id": rule.RuleID, "rule_enabled": rule.Enabled, "observations": len(observations), "window_seconds": converted.WindowSeconds, "items": items})
}

func destinationTargetRuleToPoison(rule store.DestinationTargetRule) poison.Rule {
	return poison.Rule{RuleID: rule.RuleID, Name: rule.Name, Enabled: rule.Enabled, BehaviorType: rule.BehaviorType, TargetType: rule.TargetType, Targets: rule.Targets, WindowSeconds: rule.WindowSeconds, Threshold: rule.Threshold, Direction: rule.Direction}
}

// startDestinationTargetWorker evaluates internal-destination access off the
// hot path. Findings are derived evidence: they never enforce on their own.
func (s *Server) startDestinationTargetWorker() {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			s.processDestinationTargets(time.Now().UTC())
			<-ticker.C
		}
	}()
}

func (s *Server) processDestinationTargets(now time.Time) {
	storage, ok := s.destinationTargetStore()
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	rules, err := storage.ListDestinationTargetRules(ctx)
	if err != nil {
		return
	}
	enabled := make([]store.DestinationTargetRule, 0, len(rules))
	longest := time.Duration(0)
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		enabled = append(enabled, rule)
		if window := time.Duration(rule.WindowSeconds) * time.Second; window > longest {
			longest = window
		}
	}
	if len(enabled) == 0 {
		_ = storage.ExpireDestinationTargetFindings(ctx, now.Add(-7*24*time.Hour))
		return
	}
	observations, err := s.destinationTargetObservations(ctx, now.Add(-longest))
	if err != nil {
		return
	}
	accounts := s.destinationTargetAccounts(ctx, now)
	findings := make([]store.DestinationTargetFinding, 0)
	evidenceItems := make([]evidence.Evidence, 0)
	for _, rule := range enabled {
		converted := destinationTargetRuleToPoison(rule)
		for _, finding := range poison.Evaluate(converted, observations) {
			record := store.DestinationTargetFinding{
				FindingID:          poison.FindingID(finding.RuleID, finding.SubjectIP, finding.LastSeen),
				RuleID:             finding.RuleID,
				RuleName:           rule.Name,
				SubjectIP:          finding.SubjectIP,
				AccountID:          accounts[finding.SubjectIP],
				BehaviorType:       finding.BehaviorType,
				MatchedTargets:     finding.MatchedTargets,
				UniqueDestinations: finding.UniqueDestinations,
				HitCount:           finding.HitCount,
				Direction:          finding.Direction,
				WindowStart:        finding.WindowStart.UTC().Format(time.RFC3339),
				WindowEnd:          finding.WindowEnd.UTC().Format(time.RFC3339),
				FirstSeen:          finding.FirstSeen.UTC().Format(time.RFC3339),
				LastSeen:           finding.LastSeen.UTC().Format(time.RFC3339),
			}
			findings = append(findings, record)
			evidenceItems = append(evidenceItems, destinationTargetEvidence(record))
		}
	}
	if len(findings) == 0 {
		_ = storage.ExpireDestinationTargetFindings(ctx, now.Add(-7*24*time.Hour))
		return
	}
	if err := storage.WriteDestinationTargetFindings(ctx, findings); err != nil {
		return
	}
	if len(evidenceItems) > 0 {
		if writer, ok := s.reader.(interface {
			WriteEvidence(context.Context, []evidence.Evidence) error
		}); ok {
			_ = writer.WriteEvidence(ctx, evidenceItems)
		}
	}
	_ = storage.ExpireDestinationTargetFindings(ctx, now.Add(-7*24*time.Hour))
}

func (s *Server) destinationTargetAccounts(ctx context.Context, now time.Time) map[string]string {
	accounts := map[string]string{}
	reader, ok := s.reader.(store.PolicyIdentityReader)
	if !ok {
		return accounts
	}
	sessions, err := s.policySessions(ctx, reader, now)
	if err != nil {
		return accounts
	}
	for _, session := range sessions {
		if session.IP == "" || session.AccountID == "" {
			continue
		}
		if _, exists := accounts[session.IP]; !exists {
			accounts[session.IP] = session.AccountID
		}
	}
	return accounts
}

// destinationTargetEvidence is deliberately weak: reaching internal targets is
// an operational clue, not proof of proxy or shared access, so the score is
// capped and the risk engine treats it as weak evidence.
func destinationTargetEvidence(finding store.DestinationTargetFinding) evidence.Evidence {
	score := 10 + finding.UniqueDestinations
	if score > 30 {
		score = 30
	}
	severity := "low"
	if finding.UniqueDestinations >= 20 {
		severity = "medium"
	}
	samples := append([]string{}, finding.MatchedTargets...)
	if len(samples) > 5 {
		samples = samples[:5]
	}
	samples = append(samples, "rule="+finding.RuleID, fmt.Sprintf("hits=%d", finding.HitCount))
	reason := fmt.Sprintf("在观测窗口内访问 %d 个内网目标，共 %d 次；该线索单独不足以认定代理或共享", finding.UniqueDestinations, finding.HitCount)
	return evidence.Evidence{
		EvidenceID: finding.FindingID,
		IP:         finding.SubjectIP,
		AccountID:  finding.AccountID,
		Type:       "internal_target_access",
		Window:     finding.WindowStart + "~" + finding.WindowEnd,
		Score:      score,
		Confidence: 0.6,
		Severity:   severity,
		Reason:     reason,
		Samples:    samples,
		CreatedAt:  finding.LastSeen,
	}
}
