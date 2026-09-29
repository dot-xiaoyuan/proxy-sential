package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

func (s *Server) executeActionPostgres(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	var request executeActionRequest
	if err != nil || len(raw) > 1<<20 || json.Unmarshal(raw, &request) != nil {
		writeError(w, 400, "bad_action", "valid action JSON is required")
		return
	}
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		writeError(w, 400, "idempotency_key_required", "Idempotency-Key header is required")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		writeError(w, 503, "action_storage_failed", err.Error())
		return
	}
	defer tx.Rollback()
	fail := func(err error) { writeError(w, 503, "action_storage_failed", err.Error()) }
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "enforcement-idempotency:"+key); err != nil {
		fail(err)
		return
	}
	doc := emptyOperationsDocument()
	if err = loadActionsScoped(ctx, tx, &doc, ` WHERE idempotency_key=$1`, []any{key}); err != nil {
		fail(err)
		return
	}
	if len(doc.Actions) > 0 {
		for _, action := range doc.Actions {
			writeJSON(w, 200, action)
			return
		}
	}
	var connectorID string
	err = tx.QueryRowContext(ctx, `SELECT connector_id FROM enforcement_connectors WHERE connector_id=$1 FOR UPDATE`, request.ConnectorID).Scan(&connectorID)
	if err != nil && err != sql.ErrNoRows {
		fail(err)
		return
	}
	if err = loadConnectorsScoped(ctx, tx, &doc, ` WHERE connector_id=$1`, []any{request.ConnectorID}); err != nil {
		fail(err)
		return
	}
	// This shared counter protects the existing global/campus admission budgets;
	// it serializes new submissions, not page reads or unrelated configuration.
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('enforcement-admission-budget',0))`); err != nil {
		fail(err)
		return
	}
	if request.CaseID != "" {
		var header []byte
		err = tx.QueryRowContext(ctx, `SELECT to_jsonb(c)||jsonb_build_object('ip',coalesce(host(c.ip),''),'nas_ip',coalesce(host(c.nas_ip),'')) FROM risk_cases c WHERE case_id=$1`, request.CaseID).Scan(&header)
		if err != nil && err != sql.ErrNoRows {
			fail(err)
			return
		}
		if err == nil {
			var item RiskCase
			if err = json.Unmarshal(header, &item); err != nil {
				fail(err)
				return
			}
			doc.Cases[item.CaseID] = item
		}
	}
	if err = loadEmergencyStop(ctx, tx, &doc); err != nil {
		fail(err)
		return
	}
	baseline := operationFingerprints(doc)
	versions := operationRecordVersions(doc)
	if connector, ok := doc.Connectors[request.ConnectorID]; ok {
		if err = prepareConnectorShadowMetrics(ctx, tx, &connector); err != nil {
			fail(err)
			return
		}
		doc.Connectors[connector.ConnectorID] = connector
	}
	view := *s
	view.operations = &operationsState{db: s.operations.db, tx: tx, doc: doc, readView: true, shadowMetricsPrepared: true, recordBaseline: baseline, recordVersionBaseline: versions}
	r = r.Clone(ctx)
	r.Body = io.NopCloser(bytes.NewReader(raw))
	view.handleExecuteAction(w, r)
}

func prepareConnectorShadowMetrics(ctx context.Context, q operationsQuerier, connector *ActionConnector) error {
	var earliest sql.NullTime
	var candidates, reviewed, correct int
	var falseAction bool
	err := q.QueryRowContext(ctx, `SELECT min(a.created_at),count(*),count(*) FILTER(WHERE c.disposition IS NOT NULL AND c.disposition NOT IN('','needs_more_data')),count(*) FILTER(WHERE c.disposition='confirmed_proxy'),coalesce(bool_or(c.disposition IS NOT NULL AND c.disposition NOT IN('','needs_more_data','confirmed_proxy')),false) FROM enforcement_actions a LEFT JOIN risk_cases c ON c.case_id=a.case_id WHERE a.connector_id=$1 AND a.mode='shadow' AND a.status='shadow' AND ($2::timestamptz IS NULL OR a.created_at>=$2::timestamptz)`, connector.ConnectorID, optionalConnectorTime(connector.ShadowValidationSince)).Scan(&earliest, &candidates, &reviewed, &correct, &falseAction)
	if err != nil {
		return err
	}
	connector.ShadowCandidateCount, connector.ShadowReviewedCount = candidates, reviewed
	connector.ShadowAccuracy = 0
	if reviewed > 0 {
		connector.ShadowAccuracy = float64(correct) / float64(reviewed)
	}
	if earliest.Valid {
		connector.ShadowStartedAt = formatDBTime(earliest.Time)
	}
	connector.ShadowReady = candidates > 0 && reviewed == candidates && earliest.Valid && time.Since(earliest.Time) >= 7*24*time.Hour && connector.ShadowAccuracy >= .95 && !falseAction
	if until, err := time.Parse(time.RFC3339Nano, connector.CircuitOpenUntil); err == nil && !until.After(time.Now()) {
		connector.CircuitOpenUntil = ""
		connector.ConsecutiveFailures = 0
	}
	return nil
}

func (s *Server) actionAdmissionCounts(ctx context.Context, account, endpoint, campus string, now time.Time) (int, int, bool, error) {
	var campusCount, hourCount int
	var cooling bool
	err := s.operations.tx.QueryRowContext(ctx, `SELECT
 count(*) FILTER(WHERE mode='active' AND status IN('pending','running','succeeded') AND created_at>=$4-interval '1 hour'),
 count(*) FILTER(WHERE mode='active' AND status IN('pending','running','succeeded') AND $3<>'' AND campus_id=$3 AND created_at>=$4-interval '10 minutes'),
 coalesce(bool_or(status IN('succeeded','revoked','expired') AND cooldown_until>$4 AND (($1<>'' AND account_id=$1) OR ($2<>'' AND endpoint_id=$2))),false)
 FROM enforcement_actions WHERE created_at>=$4-interval '1 hour' OR (cooldown_until>$4 AND (($1<>'' AND account_id=$1) OR ($2<>'' AND endpoint_id=$2)))`, account, endpoint, campus, now).Scan(&hourCount, &campusCount, &cooling)
	return campusCount, hourCount, cooling, err
}
