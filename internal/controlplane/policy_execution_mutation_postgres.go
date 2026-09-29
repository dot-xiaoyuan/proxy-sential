package controlplane

import (
	"database/sql"
	"net/http"
	"sort"
	"strings"
)

func (s *Server) mutatePolicyExecutionPostgres(w http.ResponseWriter, r *http.Request, path string) {
	parts := strings.Split(strings.TrimPrefix(path, "/policy-executions/"), "/")
	if len(parts) != 2 || r.Method != http.MethodPost || (parts[1] != "approve" && parts[1] != "revoke") {
		writeError(w, 405, "invalid_execution_operation", "操作不支持")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	initial, found, err := s.operations.readPolicyExecution(ctx, parts[0])
	if err != nil {
		writeError(w, 503, "policy_storage_failed", err.Error())
		return
	}
	if !found {
		writeError(w, 404, "execution_not_found", "执行轮次不存在")
		return
	}
	connectors := map[string]bool{}
	for _, stage := range initial.Definition.Stages {
		if stage.ConnectorID != "" {
			connectors[stage.ConnectorID] = true
		}
	}
	rows, err := s.operations.db.QueryContext(ctx, `SELECT DISTINCT connector_id FROM enforcement_actions WHERE policy_parameters->>'execution_id'=$1`, parts[0])
	if err != nil {
		writeError(w, 503, "policy_storage_failed", err.Error())
		return
	}
	for rows.Next() {
		var id sql.NullString
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			writeError(w, 503, "policy_storage_failed", err.Error())
			return
		}
		if id.Valid {
			connectors[id.String] = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		writeError(w, 503, "policy_storage_failed", err.Error())
		return
	}
	ids := make([]string, 0, len(connectors))
	for id := range connectors {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		writeError(w, 503, "policy_storage_failed", err.Error())
		return
	}
	defer tx.Rollback()
	fail := func(err error) { writeError(w, 503, "policy_storage_failed", err.Error()) }
	rows, err = tx.QueryContext(ctx, `SELECT connector_id FROM enforcement_connectors WHERE connector_id=ANY($1::text[]) ORDER BY connector_id FOR UPDATE`, ids)
	if err != nil {
		fail(err)
		return
	}
	for rows.Next() {
		var ignored string
		if err = rows.Scan(&ignored); err != nil {
			rows.Close()
			fail(err)
			return
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		fail(err)
		return
	}
	doc := emptyOperationsDocument()
	if err = loadPolicyDocumentsScoped(ctx, tx, &doc, "account_policy_executions", ` WHERE id=$1 FOR UPDATE`, []any{parts[0]}); err != nil {
		fail(err)
		return
	}
	current, found := doc.PolicyExecutions[parts[0]]
	if !found {
		writeError(w, 404, "execution_not_found", "执行轮次不存在")
		return
	}
	for _, stage := range current.Definition.Stages {
		if stage.ConnectorID != "" && !connectors[stage.ConnectorID] {
			writeError(w, 409, "policy_changed", "执行轮次已变化，请重新获取后提交")
			return
		}
	}
	if err = loadActionsScoped(ctx, tx, &doc, ` WHERE policy_parameters->>'execution_id'=$1 ORDER BY action_id FOR UPDATE`, []any{parts[0]}); err != nil {
		fail(err)
		return
	}
	for _, action := range doc.Actions {
		if action.ConnectorID != "" && !connectors[action.ConnectorID] {
			writeError(w, 409, "policy_changed", "关联动作已变化，请重新获取后提交")
			return
		}
	}
	if err = loadConnectorsScoped(ctx, tx, &doc, ` WHERE connector_id=ANY($1::text[])`, []any{ids}); err != nil {
		fail(err)
		return
	}
	if err = loadPolicyDocumentsScoped(ctx, tx, &doc, "account_policy_definitions", "", nil); err != nil {
		fail(err)
		return
	}
	if err = loadEmergencyStop(ctx, tx, &doc); err != nil {
		fail(err)
		return
	}
	view := *s
	view.operations = &operationsState{db: s.operations.db, tx: tx, doc: doc, readView: true, recordBaseline: operationFingerprints(doc), recordVersionBaseline: operationRecordVersions(doc)}
	view.handlePolicyExecutionMutation(w, r.WithContext(ctx), path)
}
