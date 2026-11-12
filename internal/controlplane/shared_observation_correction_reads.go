package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

func sharedCorrectionLookup(ids []string) (string, []any) {
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		placeholders[i] = "$" + strconv.Itoa(i+1)
		args[i] = id
	}
	return `SELECT decision_id,classification,reason FROM shared_observation_decision_corrections WHERE decision_id IN (` + strings.Join(placeholders, ",") + `)`, args
}

// Enrich only the bounded page. Legacy record-only actions stay explicitly
// unreviewed until a saved-evidence correction is appended; new episode rows
// passed the current strong-evidence gate but are not a human conclusion.
func annotateSharedActionReview(ctx context.Context, q operationsQuerier, actions map[string]EnforcementAction) error {
	ids := make([]string, 0, len(actions))
	byDecision := make(map[string][]string)
	for actionID, action := range actions {
		if action.Mode != "record_only" || action.CreatedBy != "shared_observation" {
			continue
		}
		if action.PolicyParameters.EpisodeID != "" {
			action.EvidenceReviewStatus = "rule_verified"
		} else {
			action.EvidenceReviewStatus = "pending_review"
		}
		if decisionID := action.PolicyParameters.DecisionID; decisionID != "" {
			if _, seen := byDecision[decisionID]; !seen {
				ids = append(ids, decisionID)
			}
			byDecision[decisionID] = append(byDecision[decisionID], actionID)
		}
		actions[actionID] = action
	}
	if len(ids) == 0 {
		return nil
	}
	query, args := sharedCorrectionLookup(ids)
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("read shared action corrections: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var decisionID, classification, reason string
		if err := rows.Scan(&decisionID, &classification, &reason); err != nil {
			return err
		}
		for _, actionID := range byDecision[decisionID] {
			action := actions[actionID]
			action.EvidenceReviewStatus = classification
			action.EvidenceReviewReason = reason
			actions[actionID] = action
		}
	}
	return rows.Err()
}

func annotateSharedDecisionReview(ctx context.Context, q operationsQuerier, ids []string, items []json.RawMessage) ([]json.RawMessage, error) {
	if len(ids) != len(items) {
		return nil, fmt.Errorf("shared decision page identifiers do not match items")
	}
	lookup := make(map[string][]int)
	selectIDs := make([]string, 0, len(ids))
	for i, raw := range items {
		var decision struct {
			Trigger     string `json:"trigger"`
			Result      string `json:"result"`
			ExecutionID string `json:"execution_id"`
		}
		if err := json.Unmarshal(raw, &decision); err != nil {
			return nil, err
		}
		if decision.Trigger != "shared_access" || decision.Result != "matched" {
			continue
		}
		status := "pending_review"
		if strings.HasPrefix(decision.ExecutionID, "shared-observe-episode-") {
			status = "rule_verified"
		}
		var err error
		items[i], err = addSharedReviewFields(raw, status, "")
		if err != nil {
			return nil, err
		}
		if _, seen := lookup[ids[i]]; !seen {
			selectIDs = append(selectIDs, ids[i])
		}
		lookup[ids[i]] = append(lookup[ids[i]], i)
	}
	if len(selectIDs) == 0 {
		return items, nil
	}
	query, args := sharedCorrectionLookup(selectIDs)
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("read shared decision corrections: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, classification, reason string
		if err := rows.Scan(&id, &classification, &reason); err != nil {
			return nil, err
		}
		for _, i := range lookup[id] {
			items[i], err = addSharedReviewFields(items[i], classification, reason)
			if err != nil {
				return nil, err
			}
		}
	}
	return items, rows.Err()
}

func addSharedReviewFields(raw []byte, status, reason string) (json.RawMessage, error) {
	var item map[string]json.RawMessage
	if err := json.Unmarshal(raw, &item); err != nil {
		return nil, err
	}
	item["evidence_review_status"], _ = json.Marshal(status)
	if reason != "" {
		item["evidence_review_reason"], _ = json.Marshal(reason)
	}
	encoded, err := json.Marshal(item)
	return encoded, err
}
