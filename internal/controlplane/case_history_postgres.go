package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"proxy-sentinel/internal/store"
	"strconv"
)

type caseHistorySource struct{ table, id, projection string }

var caseHistorySources = map[string]caseHistorySource{
	"evidence": {"risk_case_evidence_snapshots", "snapshot_id", "to_jsonb(t)"},
	"comments": {"risk_case_comments", "comment_id", "to_jsonb(t)"},
	"timeline": {"risk_case_timeline", "event_id", "to_jsonb(t)||jsonb_build_object('type',t.event_type,'before',t.before_value,'after',t.after_value)"},
}

func (s *Server) caseHistoryPostgres(w http.ResponseWriter, r *http.Request, id, kind string) {
	source, ok := caseHistorySources[kind]
	if !ok {
		writeError(w, 400, "bad_history_kind", "unknown history kind")
		return
	}
	limit, err := boundedInt(r.URL.Query().Get("limit"), 20, 1, 50)
	if err != nil {
		writeError(w, 400, "bad_page", err.Error())
		return
	}
	offset, err := cursorOffset(r.URL.Query().Get("cursor"))
	if err != nil {
		writeError(w, 400, "bad_page", err.Error())
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	var exists bool
	if err = s.operations.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM risk_cases WHERE case_id=$1)", id).Scan(&exists); err != nil {
		writeError(w, 503, "case_history_unavailable", err.Error())
		return
	}
	if !exists {
		writeError(w, 404, "case_not_found", "case not found")
		return
	}
	query := "SELECT (SELECT count(*) FROM " + source.table + " WHERE case_id=$1),COALESCE(jsonb_agg(" + source.projection + " ORDER BY created_at DESC," + source.id + " DESC),'[]'::jsonb) FROM (SELECT * FROM " + source.table + " WHERE case_id=$1 ORDER BY created_at DESC," + source.id + " DESC LIMIT $2 OFFSET $3) t"
	var total int
	var raw []byte
	if err = s.operations.db.QueryRowContext(ctx, query, id, limit, offset).Scan(&total, &raw); err != nil {
		writeError(w, 503, "case_history_unavailable", err.Error())
		return
	}
	var next *string
	if offset+limit < total {
		value := strconv.Itoa(offset + limit)
		next = &value
	}
	writeJSON(w, 200, map[string]any{"items": json.RawMessage(raw), "page": store.Page{Limit: limit, Total: total, NextCursor: next}})
}

func (s *Server) getCasePostgres(w http.ResponseWriter, r *http.Request, id string) {
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	tx, err := s.operations.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		writeError(w, 503, "case_unavailable", err.Error())
		return
	}
	defer tx.Rollback()
	item, err := readCaseWithinTransaction(ctx, tx, id, false)
	if err == sql.ErrNoRows {
		writeError(w, 404, "case_not_found", "case not found")
		return
	}
	if err != nil {
		writeError(w, 503, "case_unavailable", err.Error())
		return
	}
	if err = tx.Commit(); err != nil {
		writeError(w, 503, "case_unavailable", err.Error())
		return
	}
	writeJSON(w, 200, item)
}

func readCaseWithinTransaction(ctx context.Context, tx *sql.Tx, id string, forUpdate bool) (RiskCase, error) {
	var raw []byte
	query := `SELECT ` + caseAssessmentProjection + ` FROM risk_cases c WHERE case_id=$1`
	if forUpdate {
		query += " FOR UPDATE"
	}
	err := tx.QueryRowContext(ctx, query, id).Scan(&raw)
	if err == sql.ErrNoRows {
		return RiskCase{}, sql.ErrNoRows
	}
	if err != nil {
		return RiskCase{}, err
	}
	var item RiskCase
	if item, err = decodeCaseAssessment(raw); err != nil {
		return RiskCase{}, err
	}
	item.HistoryPage = map[string]store.Page{}
	for _, kind := range []string{"evidence", "comments", "timeline"} {
		source := caseHistorySources[kind]
		query := "SELECT (SELECT count(*) FROM " + source.table + " WHERE case_id=$1),COALESCE(jsonb_agg(" + source.projection + " ORDER BY created_at," + source.id + "),'[]'::jsonb) FROM (SELECT * FROM " + source.table + " WHERE case_id=$1 ORDER BY created_at DESC," + source.id + " DESC LIMIT 20) t"
		var total int
		if err = tx.QueryRowContext(ctx, query, id).Scan(&total, &raw); err != nil {
			return RiskCase{}, err
		}
		switch kind {
		case "evidence":
			err = json.Unmarshal(raw, &item.EvidenceHistory)
			if len(item.EvidenceHistory) > 0 {
				item.EvidenceSnapshot = item.EvidenceHistory[len(item.EvidenceHistory)-1].Evidence
			}
		case "comments":
			err = json.Unmarshal(raw, &item.Comments)
		case "timeline":
			err = json.Unmarshal(raw, &item.Timeline)
		}
		if err != nil {
			return RiskCase{}, err
		}
		var next *string
		if total > 20 {
			value := "20"
			next = &value
		}
		item.HistoryPage[kind] = store.Page{Limit: 20, Total: total, NextCursor: next}
	}
	// Generic legacy cases preserve their discovery snapshot. Specialized
	// shared/router cases expose the newest snapshot of their own kind so old
	// generic snapshots cannot replace the current decision basis.
	var original []byte
	if item.RiskKind == "shared_access" || item.RiskKind == "router_observation" {
		key := map[string]string{"shared_access": "shared_access", "router_observation": "router_observation"}[item.RiskKind]
		err = tx.QueryRowContext(ctx, `SELECT evidence FROM risk_case_evidence_snapshots WHERE case_id=$1 AND evidence ? $2 ORDER BY created_at DESC,snapshot_id DESC LIMIT 1`, id, key).Scan(&original)
	} else {
		err = tx.QueryRowContext(ctx, `SELECT evidence FROM risk_case_evidence_snapshots WHERE case_id=$1 ORDER BY created_at,snapshot_id LIMIT 1`, id).Scan(&original)
	}
	if err != nil && err != sql.ErrNoRows {
		return RiskCase{}, err
	}
	if err == nil {
		if err = json.Unmarshal(original, &item.EvidenceSnapshot); err != nil {
			return RiskCase{}, err
		}
	}

	return item, nil
}
