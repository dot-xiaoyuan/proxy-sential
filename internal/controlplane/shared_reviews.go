package controlplane

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/legacy4k"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/sharedaccess"
	"proxy-sentinel/internal/store"
)

func reviewGeneration(result sharedaccess.Result, sessions []policy.Session) string {
	values := []string{}
	seen := map[string]bool{}
	for _, session := range sessions {
		if session.AccountID == result.AccountID && session.CampusID == result.CampusID && session.AccessDomain == result.AccessDomain && session.State(result.ObservedAt) == "active" {
			raw, _ := json.Marshal([]string{session.Source, session.ID, session.StartedAt.UTC().Format(time.RFC3339Nano)})
			if !seen[string(raw)] {
				values = append(values, string(raw))
				seen[string(raw)] = true
			}
		}
	}
	sort.Strings(values)
	if len(values) == 0 {
		return ""
	}
	return legacy4k.StableID(strings.Join(values, "\n"))
}
func (s *Server) persistSharedReview(ctx context.Context, result sharedaccess.Result, window sharedaccess.Window, generation string) error {
	if result.AccountID == "" || generation == "" || result.State == "not_matched" {
		return nil
	}
	identity, _ := json.Marshal([]string{"review", result.AccountID, result.CampusID, result.AccessDomain, generation, "1"})
	id := legacy4k.StableID(string(identity))
	evidenceKey := legacy4k.StableID(result.ID + ":" + result.ConfigVersion + ":" + generation)
	raw, _ := json.Marshal(result)
	coverage, blockers := "unknown", []string{"capture_coverage_not_verified"}
	if window.CoverageVerified && window.Complete {
		coverage = "verified"
		blockers = []string{}
	} else if len(window.Conflicts) > 0 {
		coverage = "insufficient"
		blockers = append([]string{}, window.Conflicts...)
	}
	proof, _ := json.Marshal(map[string]any{"result": result, "window": window, "coverage_state": coverage, "blockers": blockers})
	evidenceKey = legacy4k.StableID(string(proof))
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO shared_access_reviews(review_id,account_id,campus_id,access_domain,session_generation,latest_result) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(review_id) DO NOTHING`, id, result.AccountID, result.CampusID, result.AccessDomain, generation, raw)
	if err != nil {
		return err
	}
	var version int64
	var currentRaw []byte
	if err = tx.QueryRowContext(ctx, `SELECT latest_version,latest_result FROM shared_access_reviews WHERE review_id=$1 FOR UPDATE`, id).Scan(&version, &currentRaw); err != nil {
		return err
	}
	var exists bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM shared_access_review_evidence WHERE review_id=$1 AND evidence_key=$2)`, id, evidenceKey).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return tx.Commit()
	}
	// History revisions are independent of the version selected as current evidence.
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(max(version),0) FROM shared_access_review_evidence WHERE review_id=$1`, id).Scan(&version); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO shared_access_review_evidence(review_id,version,evidence_key,evidence) VALUES($1,$2,$3,$4)`, id, version+1, evidenceKey, proof)
	if err != nil {
		return err
	}
	var current sharedaccess.Result
	if err = json.Unmarshal(currentRaw, &current); err != nil {
		return err
	}
	// Stable ID ordering resolves equal observation times without arrival-order drift.
	if result.ObservedAt.Before(current.ObservedAt) || (result.ObservedAt.Equal(current.ObservedAt) && result.ID < current.ID) {
		return tx.Commit()
	}
	_, err = tx.ExecContext(ctx, `UPDATE shared_access_reviews SET latest_version=$2,latest_result=$3,coverage_state=$4,updated_at=now() WHERE review_id=$1`, id, version+1, raw, coverage)
	if err != nil {
		return err
	}
	return tx.Commit()
}

type sharedReviewRuntime struct{ Position int }

func (s *Server) startSharedReviewWorker() {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			s.materializeSharedReviews()
			<-ticker.C
		}
	}()
}
func (s *Server) materializeSharedReviews() {
	if len(s.sharedConfig.Sources) == 0 || s.sharedReviews == nil {
		return
	}
	reader, ok := s.reader.(store.PolicyIdentityReader)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	now := time.Now().UTC()
	sessions, err := s.policySessions(ctx, reader, now)
	if err != nil {
		return
	}
	windows, err := s.sharedWindows(ctx, now)
	if err != nil {
		return
	}
	// Bound writes per cycle. Unknown coverage never closes an episode, increases
	// punishment rounds or grants an action; evidence revisions are append-only.
	if len(windows) == 0 {
		s.sharedReviews.Position = 0
		return
	}
	position := s.sharedReviews.Position % len(windows)
	for i := 0; i < len(windows) && i < 100; i++ {
		window := windows[(position+i)%len(windows)]
		result := sharedaccess.Evaluate(window, s.sharedConfig, sessions, now, 10*time.Minute)
		generation := reviewGeneration(result, sessions)
		if err := s.persistSharedReview(ctx, result, window, generation); err != nil {
			s.sharedReviews.Position = (position + i) % len(windows)
			return
		}
		s.sharedReviews.Position = (position + i + 1) % len(windows)
	}

}

type reviewCursor struct {
	At time.Time `json:"at"`
	ID string    `json:"id"`
}

func decodeReviewCursor(value string) (reviewCursor, error) {
	var result reviewCursor
	if value == "" {
		return result, nil
	}
	if len(value) > 1024 {
		return result, fmt.Errorf("invalid cursor")
	}
	raw, e := base64.RawURLEncoding.DecodeString(value)
	if e != nil || json.Unmarshal(raw, &result) != nil || result.At.IsZero() || result.ID == "" {
		return result, fmt.Errorf("invalid cursor")
	}
	return result, nil
}
func encodeReviewCursor(at time.Time, id string) string {
	raw, _ := json.Marshal(reviewCursor{at, id})
	return base64.RawURLEncoding.EncodeToString(raw)
}
func (s *Server) handleSharedReviews(w http.ResponseWriter, r *http.Request, path string) {
	if s.operations.db == nil {
		writeError(w, 503, "review_storage_unavailable", "复核队列需要 PostgreSQL 存储")
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(path, "/shared-access/reviews"), "/"), "/")
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	if r.Method == "POST" && len(parts) == 2 && (parts[1] == "disconnect-preview" || parts[1] == "disconnect") {
		s.handleSharedDisconnect(w, r, ctx, parts[0], parts[1] == "disconnect-preview")
		return
	}
	if r.Method == "POST" && len(parts) == 2 && parts[1] == "conclusion" {
		s.saveSharedConclusion(w, r, ctx, parts[0])
		return
	}
	if r.Method != "GET" {
		writeError(w, 405, "method_not_allowed", "不支持该请求方法")
		return
	}
	limit := 20
	if value := r.URL.Query().Get("limit"); value != "" {
		var e error
		limit, e = strconv.Atoi(value)
		if e != nil || limit < 1 || limit > 100 {
			writeError(w, 400, "bad_pagination", "limit 必须为1至100")
			return
		}
	}
	if parts[0] == "" {
		cursor, err := decodeReviewCursor(r.URL.Query().Get("cursor"))
		if err != nil {
			writeError(w, 400, "bad_cursor", "分页游标无效")
			return
		}
		rows, err := s.operations.db.QueryContext(ctx, `SELECT review_id,account_id,campus_id,access_domain,session_generation,episode,state,latest_version,latest_result,coverage_state,created_at,updated_at FROM shared_access_reviews WHERE ($1::timestamptz IS NULL OR (created_at,review_id)<($1,$2)) ORDER BY created_at DESC,review_id DESC LIMIT $3`, func() any {
			if cursor.At.IsZero() {
				return nil
			}
			return cursor.At
		}(), cursor.ID, limit+1)
		if err != nil {
			writeError(w, 503, "reviews_unavailable", "复核列表读取失败")
			return
		}
		defer rows.Close()
		items := []map[string]any{}
		next := ""
		for rows.Next() {
			item, _, _, err := scanSharedReview(rows)
			if err != nil {
				writeError(w, 503, "reviews_unavailable", "复核记录无效")
				return
			}
			if len(items) == limit {
				last := items[len(items)-1]
				next = encodeReviewCursor(last["created_at"].(time.Time), last["review_id"].(string))
				break
			}
			items = append(items, item)
		}
		if rows.Err() != nil {
			writeError(w, 503, "reviews_unavailable", "复核列表不完整")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
		return
	}
	if len(parts) == 1 {
		item, _, _, err := scanSharedReview(s.operations.db.QueryRowContext(ctx, `SELECT review_id,account_id,campus_id,access_domain,session_generation,episode,state,latest_version,latest_result,coverage_state,created_at,updated_at FROM shared_access_reviews WHERE review_id=$1`, parts[0]))
		if err != nil {
			if err == sql.ErrNoRows {
				writeError(w, 404, "review_not_found", "复核记录不存在")
			} else {
				writeError(w, 503, "review_unavailable", "复核详情读取失败")
			}
			return
		}
		var conclusion, reason, operator string
		var version int64
		var created time.Time
		err = s.operations.db.QueryRowContext(ctx, `SELECT evidence_version,operator_id,conclusion,reason,created_at FROM shared_access_review_conclusions WHERE review_id=$1 ORDER BY conclusion_id DESC LIMIT 1`, parts[0]).Scan(&version, &operator, &conclusion, &reason, &created)
		if err != nil && err != sql.ErrNoRows {
			writeError(w, 503, "review_unavailable", "人工结论读取失败")
			return
		}
		if err == nil {
			item["last_conclusion"] = map[string]any{"evidence_version": version, "operator_id": operator, "conclusion": conclusion, "reason": reason, "created_at": created}
		}
		writeJSON(w, 200, item)
		return
	}
	if len(parts) == 2 && parts[1] == "executions" {
		s.sharedReviewExecutions(w, r, ctx, parts[0], limit)
		return
	}
	if len(parts) == 2 && parts[1] == "evidence" {
		var exists bool
		if err := s.operations.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM shared_access_reviews WHERE review_id=$1)`, parts[0]).Scan(&exists); err != nil {
			writeError(w, 503, "review_unavailable", "复核记录读取失败")
			return
		}
		if !exists {
			writeError(w, 404, "review_not_found", "复核记录不存在")
			return
		}
		cursor := int64(0)
		if value := r.URL.Query().Get("cursor"); value != "" {
			var err error
			cursor, err = strconv.ParseInt(value, 10, 64)
			if err != nil || cursor <= 0 {
				writeError(w, 400, "bad_cursor", "历史游标无效")
				return
			}
		}
		rows, err := s.operations.db.QueryContext(ctx, `SELECT version,evidence,created_at FROM shared_access_review_evidence WHERE review_id=$1 AND ($2::bigint=0 OR version<$2) ORDER BY version DESC LIMIT $3`, parts[0], cursor, limit+1)
		if err != nil {
			writeError(w, 503, "evidence_unavailable", "证据历史读取失败")
			return
		}
		defer rows.Close()
		items := []map[string]any{}
		next := ""
		for rows.Next() {
			var version int64
			var evidence json.RawMessage
			var at time.Time
			if rows.Scan(&version, &evidence, &at) != nil {
				writeError(w, 503, "evidence_unavailable", "证据记录无效")
				return
			}
			if len(items) == limit {
				next = strconv.FormatInt(items[len(items)-1]["version"].(int64), 10)
				break
			}
			items = append(items, map[string]any{"version": version, "evidence": evidence, "created_at": at})
		}
		if rows.Err() != nil {
			writeError(w, 503, "evidence_unavailable", "证据历史不完整")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
		return
	}
	writeError(w, 404, "review_endpoint_not_found", "复核接口不存在")
}

type sharedReviewScanner interface{ Scan(...any) error }

func scanSharedReview(row sharedReviewScanner) (map[string]any, time.Time, string, error) {
	var id, account, campus, domain, generation, state, coverage string
	var episode int
	var version int64
	var result json.RawMessage
	var created, updated time.Time
	err := row.Scan(&id, &account, &campus, &domain, &generation, &episode, &state, &version, &result, &coverage, &created, &updated)
	return map[string]any{"review_id": id, "account_id": account, "campus_id": campus, "access_domain": domain, "session_generation": generation, "episode": episode, "state": state, "latest_version": version, "latest_result": result, "coverage_state": coverage, "created_at": created, "updated_at": updated}, created, id, err
}
func (s *Server) saveSharedConclusion(w http.ResponseWriter, r *http.Request, ctx context.Context, id string) {
	var req struct {
		Version    int64  `json:"evidence_version"`
		Conclusion string `json:"conclusion"`
		Reason     string `json:"reason"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	d.DisallowUnknownFields()
	var extra any
	if d.Decode(&req) != nil || d.Decode(&extra) != io.EOF || req.Version <= 0 || (req.Conclusion != "shared" && req.Conclusion != "normal" && req.Conclusion != "insufficient") || strings.TrimSpace(req.Reason) == "" || len(req.Reason) > 4096 {
		writeError(w, 400, "bad_conclusion", "需要有效依据版本、复核结论及理由")
		return
	}
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		writeError(w, 503, "review_unavailable", "复核结论保存失败")
		return
	}
	defer tx.Rollback()
	var version int64
	var currentRaw []byte
	if err = tx.QueryRowContext(ctx, `SELECT latest_version,latest_result FROM shared_access_reviews WHERE review_id=$1 FOR UPDATE`, id).Scan(&version, &currentRaw); err != nil {
		if err == sql.ErrNoRows {
			writeError(w, 404, "review_not_found", "复核记录不存在")
		} else {
			writeError(w, 503, "review_unavailable", "复核记录读取失败")
		}
		return
	}
	if version != req.Version {
		writeError(w, 409, "evidence_changed", "依据已变化，请重新复核")
		return
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO shared_access_review_conclusions(review_id,evidence_version,operator_id,conclusion,reason) VALUES($1,$2,$3,$4,$5)`, id, req.Version, sessionFromContext(ctx).User.ID, req.Conclusion, req.Reason)
	if err == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(audit_id,actor,action,target,outcome,created_at) VALUES($1,$2,'shared_access.review.conclude',$3,$4,now())`, "shared-review-"+shortToken(16), sessionFromContext(ctx).User.ID, id, req.Conclusion)
	}
	if err != nil || tx.Commit() != nil {
		writeError(w, 503, "review_unavailable", "复核结论保存失败")
		return
	}
	writeJSON(w, 200, map[string]any{"review_id": id, "evidence_version": req.Version, "conclusion": req.Conclusion, "enforcement_ready": false})
}

func (s *Server) sharedReviewExecutions(w http.ResponseWriter, r *http.Request, ctx context.Context, id string, limit int) {
	cursor, err := decodeReviewCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		writeError(w, 400, "bad_cursor", "执行游标无效")
		return
	}
	var exists bool
	if s.operations.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM shared_access_reviews WHERE review_id=$1)`, id).Scan(&exists) != nil {
		writeError(w, 503, "review_unavailable", "复核记录读取失败")
		return
	}
	if !exists {
		writeError(w, 404, "review_not_found", "复核记录不存在")
		return
	}
	rows, err := s.operations.db.QueryContext(ctx, `SELECT x.action_id,x.evidence_version,x.created_at,a.status,a.mode FROM shared_access_review_executions x JOIN enforcement_actions a USING(action_id) WHERE x.review_id=$1 AND ($2::timestamptz IS NULL OR (x.created_at,x.action_id)<($2,$3)) ORDER BY x.created_at DESC,x.action_id DESC LIMIT $4`, id, func() any {
		if cursor.At.IsZero() {
			return nil
		}
		return cursor.At
	}(), cursor.ID, limit+1)
	if err != nil {
		writeError(w, 503, "executions_unavailable", "执行记录读取失败")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	next := ""
	for rows.Next() {
		var action, status, mode string
		var version int64
		var at time.Time
		if rows.Scan(&action, &version, &at, &status, &mode) != nil {
			writeError(w, 503, "executions_unavailable", "执行记录无效")
			return
		}
		if len(items) == limit {
			last := items[len(items)-1]
			next = encodeReviewCursor(last["created_at"].(time.Time), last["action_id"].(string))
			break
		}
		items = append(items, map[string]any{"action_id": action, "evidence_version": version, "created_at": at, "status": status, "mode": mode})
	}
	if rows.Err() != nil {
		writeError(w, 503, "executions_unavailable", "执行记录不完整")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
}
