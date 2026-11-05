package controlplane

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"proxy-sentinel/internal/pagination"
)

// Snapshot bounds append-only membership, not mutable result fields. Existing
// review/version cursors retain their format; clients carry snapshot separately.
func readPaginationSnapshot(r *http.Request) (time.Time, error) {
	if raw := r.URL.Query().Get("snapshot"); raw != "" {
		at, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return time.Time{}, fmt.Errorf("snapshot 必须为 RFC3339 时间")
		}
		return at.UTC(), nil
	}
	return time.Now().UTC(), nil
}

func (s *Server) sharedReviewPagination(w http.ResponseWriter, r *http.Request, parts []string) bool {
	operation := parts[len(parts)-1]
	if operation != "metadata" && operation != "position" {
		return false
	}
	if !(len(parts) == 1 || (len(parts) == 3 && (parts[1] == "evidence" || parts[1] == "executions"))) {
		return false
	}
	snapshot, err := readPaginationSnapshot(r)
	if err != nil {
		writeError(w, 400, "bad_snapshot", err.Error())
		return true
	}
	limit, err := boundedInt(r.URL.Query().Get("limit"), 20, 1, 100)
	if err != nil {
		writeError(w, 400, "bad_pagination", err.Error())
		return true
	}
	page, err := boundedInt(r.URL.Query().Get("page"), 1, 1, 1_000_000_000)
	if err != nil {
		writeError(w, 400, "bad_pagination", err.Error())
		return true
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	table := "shared_access_reviews"
	where := "created_at <= $1"
	args := []any{snapshot}
	keys := "created_at,review_id"
	order := "created_at DESC,review_id DESC"
	evidence := false
	if len(parts) == 3 {
		var exists bool
		if err = s.operations.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM shared_access_reviews WHERE review_id=$1)`, parts[0]).Scan(&exists); err != nil {
			writeError(w, 503, "review_unavailable", "复核记录读取失败")
			return true
		}
		if !exists {
			writeError(w, 404, "review_not_found", "复核记录不存在")
			return true
		}
		args = []any{parts[0], snapshot}
		where = "review_id=$1 AND created_at <= $2"
		if parts[1] == "evidence" {
			table = "shared_access_review_evidence"
			keys = "version"
			order = "version DESC"
			evidence = true
		} else {
			table = "shared_access_review_executions x JOIN enforcement_actions a USING(action_id)"
			where = "x.review_id=$1 AND x.created_at <= $2"
			keys = "x.created_at,x.action_id"
			order = "x.created_at DESC,x.action_id DESC"
		}
	}
	if operation == "metadata" {
		var total int64
		if err = s.operations.db.QueryRowContext(ctx, `SELECT count(*) FROM `+table+` WHERE `+where, args...).Scan(&total); err != nil {
			writeError(w, 503, "review_statistics_failed", "复核统计读取失败")
			return true
		}
		writeJSON(w, 200, map[string]any{"total": total, "as_of": snapshot, "snapshot": snapshot})
		return true
	}
	offset, _ := pagination.BoundaryOffset(page, limit)
	position := pagination.Position{Page: page, Limit: limit, AsOf: snapshot}
	if page > 1 {
		args = append(args, offset)
		rows, e := s.operations.db.QueryContext(ctx, `SELECT `+keys+` FROM `+table+` WHERE `+where+` ORDER BY `+order+fmt.Sprintf(" LIMIT 2 OFFSET $%d", len(args)), args...)
		if e != nil {
			writeError(w, 503, "review_position_failed", "复核页码定位失败")
			return true
		}
		defer rows.Close()
		count := 0
		for rows.Next() {
			var cursor string
			if evidence {
				var version int64
				e = rows.Scan(&version)
				cursor = strconv.FormatInt(version, 10)
			} else {
				var at time.Time
				var id string
				e = rows.Scan(&at, &id)
				cursor = encodeReviewCursor(at, id)
			}
			if e != nil {
				writeError(w, 503, "review_position_failed", "复核页码定位失败")
				return true
			}
			if count == 0 {
				position.Cursor = cursor
			}
			count++
		}
		if rows.Err() != nil {
			writeError(w, 503, "review_position_failed", "复核页码定位失败")
			return true
		}
		if count != 2 {
			writeError(w, 400, "page_out_of_range", pagination.ErrPageOutOfRange.Error())
			return true
		}
	}
	writeJSON(w, 200, map[string]any{"page": position.Page, "limit": position.Limit, "cursor": position.Cursor, "as_of": snapshot, "snapshot": snapshot})
	return true
}
