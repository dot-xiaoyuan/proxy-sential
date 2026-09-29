package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"proxy-sentinel/internal/policy"
	"time"
)

func loadEmergencyStop(ctx context.Context, q operationsQuerier, doc *operationsDocument) error {
	var raw []byte
	err := q.QueryRowContext(ctx, `SELECT setting_value FROM control_plane_settings WHERE setting_key='global_emergency_stop'`).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, &doc.GlobalStop)
}

func (s *Server) deliverActionPostgres(id string, revoke bool) {
	ctx, cancel := contextWithRequestTimeout(context.Background())
	defer cancel()
	doc := emptyOperationsDocument()
	if err := loadActionsScoped(ctx, s.operations.db, &doc, ` WHERE action_id=$1`, []any{id}); err != nil {
		return
	}
	preview, exists := doc.Actions[id]
	if !exists || preview.Status != "pending" {
		return
	}
	_, native := s.nativeActions[preview.ConnectorID]
	if native || preview.PolicyParameters.NativeSelected || preview.PolicyParameters.NativeIntent != nil {
		// Native reconciliation retains its stricter durable intent journal.
		s.deliverNativeAction(id, revoke)
		return
	}
	if err := s.validatePolicyDelivery(preview); err != nil {
		_ = s.finishAction(id, "blocked", "", err.Error())
		return
	}
	view, tx, err := s.targetActionMutation(ctx, id)
	if err != nil {
		return
	}
	defer tx.Rollback()
	if err = loadEmergencyStop(ctx, tx, &view.operations.doc); err != nil {
		return
	}
	view.operations.recordBaseline = operationFingerprints(view.operations.doc)
	action := view.operations.doc.Actions[id]
	connector := view.operations.doc.Connectors[action.ConnectorID]
	if action.Status != "pending" {
		return
	}
	// Validation ran without holding database locks. Reject an edited intent
	// rather than sending a payload that was not admitted by that validation.
	if operationFingerprint("action", action) != operationFingerprint("action", preview) {
		return
	}
	if view.operations.doc.GlobalStop || !connector.Enabled || connector.Mode != "active" || (action.PolicyParameters.ExecutionID != "" && !connector.ShadowReady) {
		action.Status = "blocked"
		action.Blockers = append(action.Blockers, "connector_or_global_stop_changed")
	} else {
		action.Status = "running"
	}
	action.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	view.operations.doc.Actions[id] = action
	if err = view.operations.saveLocked(); err != nil || action.Status != "running" {
		return
	}
	// The transaction is committed before the external request. Its receipt and
	// retries each use a fresh target transaction, never this detached view.
	s.deliverActionRequest(action, connector, revoke)
}

func (s *Server) scheduleActionRetryPostgres(id, lastError string) error {
	ctx, cancel := contextWithRequestTimeout(context.Background())
	defer cancel()
	view, tx, err := s.targetActionMutation(ctx, id)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return view.scheduleActionRetry(id, lastError)
}

func (s *Server) policyDeliveryState(ctx context.Context, action EnforcementAction) (policy.Execution, ActionConnector, []policy.Definition, error) {
	if s.operations.db != nil && !s.operations.readView {
		ex, found, err := s.operations.readPolicyExecution(ctx, action.PolicyParameters.ExecutionID)
		if err != nil {
			return ex, ActionConnector{}, nil, err
		}
		if !found {
			return ex, ActionConnector{}, nil, fmt.Errorf("policy execution unavailable")
		}
		definitions, err := s.operations.readPolicyDefinitions(ctx)
		if err != nil {
			return ex, ActionConnector{}, nil, err
		}
		doc := emptyOperationsDocument()
		err = loadConnectorsScoped(ctx, s.operations.db, &doc, ` WHERE connector_id=$1`, []any{action.ConnectorID})
		return ex, doc.Connectors[action.ConnectorID], definitions, err
	}
	s.operations.mu.Lock()
	defer s.operations.mu.Unlock()
	definitions := make([]policy.Definition, 0, len(s.operations.doc.Policies))
	for _, p := range s.operations.doc.Policies {
		definitions = append(definitions, p)
	}
	return s.operations.doc.PolicyExecutions[action.PolicyParameters.ExecutionID], s.operations.doc.Connectors[action.ConnectorID], definitions, s.operations.lockErr
}

func (s *Server) processDueActionsPostgres(now time.Time) error {
	ctx, cancel := contextWithRequestTimeout(context.Background())
	defer cancel()
	rows, err := s.operations.db.QueryContext(ctx, `SELECT action_id FROM enforcement_actions a WHERE
 (status='pending' AND (next_attempt_at IS NULL OR next_attempt_at<=$1)) OR
 (status='running' AND updated_at<=$1-CASE WHEN policy_parameters->>'native_selected'='true' THEN interval '45 seconds' ELSE interval '90 seconds' END) OR
 (status='succeeded' AND expires_at<=$1 AND NOT EXISTS(SELECT 1 FROM enforcement_actions child WHERE child.parent_action_id=a.action_id AND child.action_type='release'))
 ORDER BY created_at,action_id LIMIT 64`, now)
	if err != nil {
		return err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		view, tx, err := s.targetActionMutation(ctx, id)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return err
		}
		// A connector lock serializes releases and receipts for this subject. Read
		// existing children so expiry cannot manufacture a second release intent.
		parents := make([]string, 0, len(view.operations.doc.Actions))
		for parent := range view.operations.doc.Actions {
			parents = append(parents, parent)
		}
		err = loadActionsScoped(ctx, tx, &view.operations.doc, ` WHERE parent_action_id=ANY($1::text[])`, []any{parents})
		if err == nil {
			err = loadEmergencyStop(ctx, tx, &view.operations.doc)
		}
		if err != nil {
			tx.Rollback()
			return err
		}
		view.operations.recordBaseline = operationFingerprints(view.operations.doc)
		view.operations.recordVersionBaseline = operationRecordVersions(view.operations.doc)
		view.processDueActions(now)
		err = view.operations.lockErr
		tx.Rollback()
		if err != nil {
			return err
		}
	}
	return nil
}
