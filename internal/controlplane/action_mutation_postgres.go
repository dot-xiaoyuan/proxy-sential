package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Connector then stable action-ID ordering is shared by receipt updates. No
// network call or unrelated operations reload runs inside these transactions.
func (s *Server) targetActionMutation(ctx context.Context, id string) (*Server, *sql.Tx, error) {
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	failed := true
	defer func() {
		if failed {
			tx.Rollback()
		}
	}()
	var connector, parent string
	if err = tx.QueryRowContext(ctx, `SELECT connector_id,coalesce(parent_action_id,'') FROM enforcement_actions WHERE action_id=$1`, id).Scan(&connector, &parent); err != nil {
		return nil, nil, err
	}
	var connectorID string
	if err = tx.QueryRowContext(ctx, `SELECT connector_id FROM enforcement_connectors WHERE connector_id=$1 FOR UPDATE`, connector).Scan(&connectorID); err != nil {
		return nil, nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT action_id FROM enforcement_actions WHERE action_id=ANY($1::text[]) ORDER BY action_id FOR UPDATE`, []string{id, parent})
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var ignored string
		if err = rows.Scan(&ignored); err != nil {
			rows.Close()
			return nil, nil, err
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, err
	}
	doc := emptyOperationsDocument()
	if err = loadActionsScoped(ctx, tx, &doc, ` WHERE action_id=ANY($1::text[])`, []any{[]string{id, parent}}); err != nil {
		return nil, nil, err
	}
	if action, ok := doc.Actions[id]; !ok || action.ConnectorID != connector || action.ParentActionID != parent {
		return nil, nil, fmt.Errorf("action identity changed during transition")
	}
	if err = loadConnectorsScoped(ctx, tx, &doc, ` WHERE connector_id=$1`, []any{connector}); err != nil {
		return nil, nil, err
	}
	view := *s
	view.operations = &operationsState{db: s.operations.db, tx: tx, doc: doc, readView: true, recordBaseline: operationFingerprints(doc), recordVersionBaseline: operationRecordVersions(doc)}
	failed = false
	return &view, tx, nil
}

func (s *Server) finishActionPostgres(id, status, remoteID, lastError string) error {
	ctx, cancel := contextWithRequestTimeout(context.Background())
	defer cancel()
	view, tx, err := s.targetActionMutation(ctx, id)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return view.finishAction(id, status, remoteID, lastError)
}

func (s *Server) actionCallbackPostgres(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	var target struct {
		ActionID string `json:"action_id"`
	}
	if err != nil || len(raw) > 1<<20 || json.Unmarshal(raw, &target) != nil || target.ActionID == "" {
		writeError(w, 400, "bad_action_callback", "valid callback JSON and action_id are required")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	view, tx, err := s.targetActionMutation(ctx, target.ActionID)
	if err == sql.ErrNoRows {
		writeError(w, 404, "action_not_found", "action or connector not found")
		return
	}
	if err != nil {
		writeError(w, 503, "action_storage_failed", err.Error())
		return
	}
	defer tx.Rollback()
	r = r.Clone(ctx)
	r.Body = io.NopCloser(bytes.NewReader(raw))
	view.handleActionCallback(w, r)
}

func (s *Server) revokeActionPostgres(w http.ResponseWriter, r *http.Request, id string) {
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	view, tx, err := s.targetActionMutation(ctx, id)
	if err == sql.ErrNoRows {
		writeError(w, 404, "action_not_found", "action or connector not found")
		return
	}
	if err != nil {
		writeError(w, 503, "action_storage_failed", err.Error())
		return
	}
	defer tx.Rollback()
	if err = loadActionsScoped(ctx, tx, &view.operations.doc, ` WHERE parent_action_id=$1`, []any{id}); err != nil {
		writeError(w, 503, "action_storage_failed", err.Error())
		return
	}
	view.operations.recordBaseline = operationFingerprints(view.operations.doc)
	view.operations.recordVersionBaseline = operationRecordVersions(view.operations.doc)
	view.handleRevokeAction(w, r.WithContext(ctx), id)
}
