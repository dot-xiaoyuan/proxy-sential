package controlplane

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"proxy-sentinel/internal/policy"
	"strings"
	"time"
)

type policyDecisionCursor struct {
	At       time.Time `json:"at"`
	ID       string    `json:"id"`
	Snapshot time.Time `json:"snapshot"`
	Key      string    `json:"key"`
}

func (s *Server) queryPolicyDecisions(w http.ResponseWriter, r *http.Request) {
	if s.productPolicies == nil || s.productPolicies.db == nil {
		if r.URL.Query().Get("trigger") == "shared_access" {
			writeError(w, 503, "policy_decisions_unavailable", "共享记录存储不可用")
			return
		}
		writeJSON(w, 200, map[string]any{"items": []any{}, "next_cursor": ""})
		return
	}
	q := r.URL.Query()
	limit, err := boundedInt(q.Get("limit"), 50, 1, 200)
	if err != nil {
		writeError(w, 400, "bad_limit", err.Error())
		return
	}
	where := []string{}
	args := []any{}
	add := func(expr string, v any) { args = append(args, v); where = append(where, fmt.Sprintf(expr, len(args))) }
	for _, field := range []string{"account_id", "policy_id", "observation_id"} {
		if v := q.Get(field); v != "" {
			if len(v) > 200 {
				writeError(w, 400, "bad_filter", "筛选值过长")
				return
			}
			add(field+"=$%d", v)
		}
	}
	trigger := q.Get("trigger")
	if trigger != "" && trigger != "shared_access" {
		writeError(w, 400, "bad_trigger", "不支持的策略类型")
		return
	}
	if trigger != "" {
		add("trigger_type=$%d", trigger)
	}
	if v := q.Get("ip"); v != "" {
		if _, err := netip.ParseAddr(v); err != nil {
			writeError(w, 400, "bad_ip", "IP 格式错误")
			return
		}
		add("subject_ip=$%d::inet", v)
	}
	if v := q.Get("result"); v != "" {
		if v != "matched" && v != "insufficient" && v != "expired" {
			writeError(w, 400, "bad_result", "不支持的结果")
			return
		}
		add("result=$%d", v)
	}
	key := policy.StableID(q.Get("account_id"), q.Get("policy_id"), q.Get("observation_id"), trigger, q.Get("ip"), q.Get("result"), q.Get("from"), q.Get("to"))
	cursor := policyDecisionCursor{Snapshot: time.Now().UTC(), Key: key}
	if v := q.Get("cursor"); v != "" {
		raw, e := base64.RawURLEncoding.DecodeString(v)
		if e != nil || len(raw) > 2048 || json.Unmarshal(raw, &cursor) != nil || cursor.Key != key || cursor.ID == "" || cursor.At.IsZero() || cursor.Snapshot.IsZero() {
			writeError(w, 400, "bad_cursor", "分页游标与当前筛选不匹配")
			return
		}
	}
	// Legacy quota queries keep their existing history range. Shared queries
	// use a bounded hot window anchored to the first page or explicit end time.
	bounded := trigger == "shared_access" || q.Get("from") != "" || q.Get("to") != "" || q.Get("observation_id") != "" || q.Get("ip") != "" || q.Get("result") != ""
	if bounded {
		to := cursor.Snapshot
		if v := q.Get("to"); v != "" {
			var e error
			to, e = time.Parse(time.RFC3339Nano, v)
			if e != nil {
				writeError(w, 400, "bad_time", "时间需使用 RFC3339 格式")
				return
			}
		}
		from := to.Add(-30 * 24 * time.Hour)
		if v := q.Get("from"); v != "" {
			var e error
			from, e = time.Parse(time.RFC3339Nano, v)
			if e != nil {
				writeError(w, 400, "bad_time", "时间需使用 RFC3339 格式")
				return
			}
		}
		if !to.After(from) || to.Sub(from) > 30*24*time.Hour {
			writeError(w, 400, "bad_window", "查询窗口需在 30 天以内")
			return
		}
		add("evaluated_at >= $%d", from)
		add("evaluated_at <= $%d", to)
	}
	add("evaluated_at <= $%d", cursor.Snapshot)
	if cursor.ID != "" {
		args = append(args, cursor.At, cursor.ID)
		where = append(where, fmt.Sprintf("(evaluated_at,decision_id)<($%d,$%d)", len(args)-1, len(args)))
	}
	args = append(args, limit+1)
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	rows, err := s.productPolicies.db.QueryContext(ctx, `SELECT document,evaluated_at,decision_id FROM policy_decision_records WHERE `+strings.Join(where, " AND ")+fmt.Sprintf(" ORDER BY evaluated_at DESC,decision_id DESC LIMIT $%d", len(args)), args...)
	if err != nil {
		writeError(w, 503, "policy_decisions_failed", "策略记录读取失败")
		return
	}
	defer rows.Close()
	items := []json.RawMessage{}
	next := ""
	var last policyDecisionCursor
	for rows.Next() {
		var raw []byte
		var at time.Time
		var id string
		if err = rows.Scan(&raw, &at, &id); err != nil {
			writeError(w, 503, "policy_decisions_failed", "策略记录读取失败")
			return
		}
		if len(items) == limit {
			b, _ := json.Marshal(last)
			next = base64.RawURLEncoding.EncodeToString(b)
			break
		}
		if !json.Valid(raw) {
			writeError(w, 503, "policy_decisions_failed", "策略记录内容无效")
			return
		}
		items = append(items, json.RawMessage(raw))
		last = policyDecisionCursor{At: at, ID: id, Snapshot: cursor.Snapshot, Key: key}
	}
	if err = rows.Err(); err != nil {
		writeError(w, 503, "policy_decisions_failed", "策略记录读取失败")
		return
	}
	response := map[string]any{"items": items, "next_cursor": next}
	if trigger == "shared_access" && q.Get("include_processing") == "true" {
		rows.Close()
		pending, e := s.productPolicies.db.QueryContext(ctx, `SELECT host(ip),dirty_since,last_error FROM shared_observation_jobs WHERE revision>completed_revision AND NOT expired AND ($1='' OR ip=NULLIF($1,'')::inet) ORDER BY dirty_since,job_id LIMIT 31`, q.Get("ip"))
		if e != nil {
			writeError(w, 503, "policy_decisions_failed", "共享待办读取失败")
			return
		}
		processing := []map[string]any{}
		more := false
		for pending.Next() {
			var ip, issue string
			var since time.Time
			if e = pending.Scan(&ip, &since, &issue); e != nil {
				pending.Close()
				writeError(w, 503, "policy_decisions_failed", "共享待办读取失败")
				return
			}
			if len(processing) == 30 {
				more = true
				break
			}
			state := "processing"
			if issue != "" {
				state = "failed"
			}
			processing = append(processing, map[string]any{"ip": ip, "state": state, "first_received_at": since, "reason": issue})
		}
		e = pending.Err()
		pending.Close()
		if e != nil {
			writeError(w, 503, "policy_decisions_failed", "共享待办读取失败")
			return
		}
		response["processing"] = processing
		response["processing_has_more"] = more
	}
	writeJSON(w, 200, response)
}
