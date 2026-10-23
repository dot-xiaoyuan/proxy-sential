package controlplane

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/violation"
)

func (s *Server) handleViolationRead(w http.ResponseWriter, r *http.Request, path string) {
	if r.Method != http.MethodGet {
		writeError(w, 405, "method_not_allowed", "只支持查询")
		return
	}
	if s.operations == nil || s.operations.db == nil {
		writeError(w, 503, "violation_store_unavailable", "观察数据暂不可用")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 {
			writeError(w, 400, "invalid_limit", "分页大小无效")
			return
		}
		limit = n
	}
	switch {
	case path == "/violation-cases":
		account := strings.TrimSpace(r.URL.Query().Get("account_id"))
		rows, err := s.operations.db.QueryContext(ctx, `SELECT case_id,account_id,assessment_id,status,first_seen,last_seen,simulated_notice_times,prior_sanctions,COALESCE(last_violation,'epoch'::timestamptz)
			FROM violation_cases WHERE ($1='' OR account_id=$1) AND ($2='' OR case_id<$2) ORDER BY case_id DESC LIMIT $3`, account, r.URL.Query().Get("cursor"), limit+1)
		if err != nil {
			writeError(w, 503, "violation_query_failed", "案件查询失败")
			return
		}
		defer rows.Close()
		items := []violation.Case{}
		for rows.Next() {
			c, scanErr := scanViolationCase(rows)
			if scanErr != nil {
				writeError(w, 503, "violation_query_failed", "案件查询失败")
				return
			}
			items = append(items, c)
		}
		if rows.Err() != nil {
			writeError(w, 503, "violation_query_failed", "案件查询失败")
			return
		}
		next := ""
		if len(items) > limit {
			items = items[:limit]
			next = items[len(items)-1].CaseID
		}
		writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next, "observation_only": true})
	case strings.HasPrefix(path, "/violation-cases/") && strings.HasSuffix(path, "/timeline"):
		id, err := url.PathUnescape(strings.TrimSuffix(strings.TrimPrefix(path, "/violation-cases/"), "/timeline"))
		if err != nil || id == "" || strings.Contains(id, "/") {
			writeError(w, 400, "bad_case_id", "案件编号无效")
			return
		}
		rows, err := s.operations.db.QueryContext(ctx, `SELECT observation_key,kind,facts,observed_at FROM violation_observations
			WHERE case_id=$1 ORDER BY observed_at DESC,observation_key DESC LIMIT $2`, id, limit)
		if err != nil {
			writeError(w, 503, "violation_query_failed", "案件时间线查询失败")
			return
		}
		defer rows.Close()
		type event struct {
			Key   string          `json:"observation_key"`
			Kind  string          `json:"kind"`
			Facts json.RawMessage `json:"facts"`
			At    time.Time       `json:"observed_at"`
		}
		items := []event{}
		for rows.Next() {
			var v event
			if rows.Scan(&v.Key, &v.Kind, &v.Facts, &v.At) != nil {
				writeError(w, 503, "violation_query_failed", "案件时间线查询失败")
				return
			}
			items = append(items, v)
		}
		writeJSON(w, 200, map[string]any{"items": items, "observation_only": true})
	case strings.HasPrefix(path, "/violation-cases/"):
		idPath := strings.TrimPrefix(path, "/violation-cases/")
		id, err := url.PathUnescape(idPath)
		if err != nil || id == "" || strings.Contains(id, "/") {
			writeError(w, 400, "bad_case_id", "案件编号无效")
			return
		}
		row := s.operations.db.QueryRowContext(ctx, `SELECT case_id,account_id,assessment_id,status,first_seen,last_seen,simulated_notice_times,prior_sanctions,COALESCE(last_violation,'epoch'::timestamptz) FROM violation_cases WHERE case_id=$1`, id)
		c, err := scanViolationCase(row)
		if err == sql.ErrNoRows {
			writeError(w, 404, "case_not_found", "案件不存在")
			return
		}
		if err != nil {
			writeError(w, 503, "violation_query_failed", "案件查询失败")
			return
		}
		writeJSON(w, 200, c)
	case path == "/violation-observations":
		account := strings.TrimSpace(r.URL.Query().Get("account_id"))
		cursorTime, cursorKey := time.Time{}, ""
		if cursor := r.URL.Query().Get("cursor"); cursor != "" {
			parts := strings.SplitN(cursor, "|", 2)
			if len(parts) != 2 {
				writeError(w, 400, "invalid_cursor", "游标无效")
				return
			}
			var parseErr error
			cursorTime, parseErr = time.Parse(time.RFC3339Nano, parts[0])
			if parseErr != nil || parts[1] == "" {
				writeError(w, 400, "invalid_cursor", "游标无效")
				return
			}
			cursorKey = parts[1]
		}
		rows, err := s.operations.db.QueryContext(ctx, `SELECT observation_key,kind,target,facts,observed_at FROM violation_observations
			WHERE ($1='' OR target=$1) AND ($2::timestamptz IS NULL OR (observed_at,observation_key)<($2::timestamptz,$3))
			ORDER BY observed_at DESC,observation_key DESC LIMIT $4`, account, nullableObservationCursor(cursorTime), cursorKey, limit+1)
		if err != nil {
			writeError(w, 503, "violation_query_failed", "观察记录查询失败")
			return
		}
		defer rows.Close()
		type observation struct {
			Key    string          `json:"observation_key"`
			Kind   string          `json:"kind"`
			Target string          `json:"target"`
			Facts  json.RawMessage `json:"facts"`
			At     time.Time       `json:"observed_at"`
		}
		items := []observation{}
		for rows.Next() {
			var o observation
			if rows.Scan(&o.Key, &o.Kind, &o.Target, &o.Facts, &o.At) != nil {
				writeError(w, 503, "violation_query_failed", "观察记录查询失败")
				return
			}
			items = append(items, o)
		}
		if rows.Err() != nil {
			writeError(w, 503, "violation_query_failed", "观察记录查询失败")
			return
		}
		next := ""
		if len(items) > limit {
			items = items[:limit]
			last := items[len(items)-1]
			next = last.At.UTC().Format(time.RFC3339Nano) + "|" + last.Key
		}
		writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next, "observation_only": true})
	case path == "/violation-dashboard":
		rows, err := s.operations.db.QueryContext(ctx, `SELECT kind,count(*) FROM violation_observations WHERE observed_at>=now()-interval '7 days' GROUP BY kind`)
		if err != nil {
			writeError(w, 503, "violation_query_failed", "统计查询失败")
			return
		}
		defer rows.Close()
		counts := map[string]int64{}
		for rows.Next() {
			var kind string
			var n int64
			if rows.Scan(&kind, &n) == nil {
				counts[kind] = n
			}
		}
		writeJSON(w, 200, map[string]any{"window": "7d", "counts": counts, "observation_only": true})
	default:
		writeError(w, 404, "not_found", "接口不存在")
	}
}

func nullableObservationCursor(at time.Time) any {
	if at.IsZero() {
		return nil
	}
	return at
}

type violationScanner interface{ Scan(...any) error }

func scanViolationCase(scanner violationScanner) (violation.Case, error) {
	var c violation.Case
	var raw []byte
	err := scanner.Scan(&c.CaseID, &c.AccountID, &c.AssessmentID, &c.Status, &c.FirstSeen, &c.LastSeen, &raw, &c.PriorSanctions, &c.LastViolation)
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(raw, &c.NoticeTimes)
	return c, err
}
