package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Case queue reads must not invoke evidence aggregation or acquire the operations
// mutation lock, which reloads unrelated actions, timelines and configuration.
func (s *Server) listCasesPostgres(w http.ResponseWriter, r *http.Request) {
	limit, err := boundedInt(r.URL.Query().Get("limit"), 20, 1, 50)
	if err != nil {
		writeError(w, 400, "bad_limit", err.Error())
		return
	}
	cursor, err := cursorOffset(r.URL.Query().Get("cursor"))
	if err != nil {
		writeError(w, 400, "bad_cursor", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	items, total, err := queryCaseQueue(ctx, s.operations.db, r, limit, cursor)
	if err != nil {
		writeError(w, 503, "case_queue_unavailable", err.Error())
		return
	}
	page := Page{Limit: limit, Total: total}
	if offset := cursor + len(items); offset < total {
		next := fmt.Sprint(offset)
		page.NextCursor = &next
	}
	writeJSON(w, 200, map[string]any{"items": items, "page": page})
}
func queryCaseQueue(ctx context.Context, db *sql.DB, r *http.Request, limit, offset int) ([]RiskCase, int, error) {
	args := []any{}
	riskKinds := "(c.ruleset_version LIKE 'shared-behavior/%' OR c.ruleset_version LIKE 'router-observation/%')"
	if strings.EqualFold(r.URL.Query().Get("include_router_observations"), "false") {
		riskKinds = "c.ruleset_version LIKE 'shared-behavior/%'"
	}
	conditions := []string{riskKinds}
	if r.URL.Query().Get("status") == "" {
		conditions = append(conditions, "c.status NOT IN ('resolved','closed')")
	}
	for _, column := range []string{"status", "assignee_id", "campus_id", "department", "person_type", "ssid", "vlan", "ap"} {
		if value := r.URL.Query().Get(column); value != "" {
			args = append(args, value)
			conditions = append(conditions, fmt.Sprintf("c.%s=$%d", column, len(args)))
		}
	}
	if value := r.URL.Query().Get("nas_ip"); value != "" {
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf("host(c.nas_ip)=$%d", len(args)))
	}
	if q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q"))); q != "" {
		args = append(args, q)
		conditions = append(conditions, fmt.Sprintf("strpos(lower(concat_ws(' ',c.case_id,host(c.ip),c.account_id,c.endpoint_id,c.department)),$%d)>0", len(args)))
	}
	where := strings.Join(conditions, " AND ")
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	var total int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM risk_cases c WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, limit, offset)
	rows, err := tx.QueryContext(ctx, fmt.Sprintf(`SELECT `+caseAssessmentProjection+` FROM risk_cases c WHERE %s ORDER BY c.priority,c.updated_at DESC,c.case_id LIMIT $%d OFFSET $%d`, where, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	items := []RiskCase{}
	for rows.Next() {
		var raw []byte
		var item RiskCase
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, 0, err
		}
		if item, err = decodeCaseAssessment(raw); err != nil {
			rows.Close()
			return nil, 0, err
		}
		items = append(items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, 0, err
	}
	if err = tx.Commit(); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}
