package controlplane

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

func (s *Server) saveConnectorPostgres(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	var request connectorRequest
	if err != nil || len(raw) > 1<<20 || json.Unmarshal(raw, &request) != nil || request.ConnectorID == "" {
		writeError(w, 400, "bad_connector", "valid connector_id and JSON are required")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		writeError(w, 503, "save_connector_failed", err.Error())
		return
	}
	defer tx.Rollback()
	fail := func(err error) { writeError(w, 503, "save_connector_failed", err.Error()) }
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "enforcement-connector:"+request.ConnectorID); err != nil {
		fail(err)
		return
	}
	var id string
	err = tx.QueryRowContext(ctx, `SELECT connector_id FROM enforcement_connectors WHERE connector_id=$1 FOR UPDATE`, request.ConnectorID).Scan(&id)
	if err != nil && err != sql.ErrNoRows {
		fail(err)
		return
	}
	doc := emptyOperationsDocument()
	if err = loadConnectorsScoped(ctx, tx, &doc, ` WHERE connector_id=$1`, []any{request.ConnectorID}); err != nil {
		fail(err)
		return
	}
	baseline := operationFingerprints(doc)
	versionBaseline := operationRecordVersions(doc)
	if connector, ok := doc.Connectors[request.ConnectorID]; ok {
		var earliest sql.NullTime
		var candidates, reviewed, correct int
		var falseAction bool
		err = tx.QueryRowContext(ctx, `SELECT min(a.created_at),count(*),count(*) FILTER(WHERE c.disposition IS NOT NULL AND c.disposition NOT IN('','needs_more_data')),count(*) FILTER(WHERE c.disposition='confirmed_proxy'),coalesce(bool_or(c.disposition IS NOT NULL AND c.disposition NOT IN('','needs_more_data','confirmed_proxy')),false) FROM enforcement_actions a LEFT JOIN risk_cases c ON c.case_id=a.case_id WHERE a.connector_id=$1 AND a.mode='shadow' AND a.status='shadow' AND ($2::timestamptz IS NULL OR a.created_at>=$2::timestamptz)`, request.ConnectorID, optionalConnectorTime(connector.ShadowValidationSince)).Scan(&earliest, &candidates, &reviewed, &correct, &falseAction)
		if err != nil {
			fail(err)
			return
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
		doc.Connectors[request.ConnectorID] = connector
	}
	view := *s
	view.operations = &operationsState{db: s.operations.db, tx: tx, doc: doc, readView: true, shadowMetricsPrepared: true, recordBaseline: baseline, recordVersionBaseline: versionBaseline}
	r = r.Clone(ctx)
	r.Body = io.NopCloser(bytes.NewReader(raw))
	view.handleConnectors(w, r)
}

func optionalConnectorTime(raw string) any {
	if raw == "" {
		return nil
	}
	return raw
}

func (s *Server) connectorTestPostgres(w http.ResponseWriter, r *http.Request, id string) {
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	doc := emptyOperationsDocument()
	if err := loadConnectorsScoped(ctx, s.operations.db, &doc, ` WHERE connector_id=$1`, []any{id}); err != nil {
		writeError(w, 503, "connector_storage_failed", err.Error())
		return
	}
	view := *s
	view.operations = &operationsState{db: s.operations.db, doc: doc, readView: true}
	// Do not hold a database transaction or a connector lock during network I/O.
	view.handleConnectorTest(w, r, id)
}
