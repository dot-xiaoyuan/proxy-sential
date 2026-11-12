package controlplane

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

type identityBridgeRunsCursor struct {
	Snapshot time.Time `json:"snapshot"`
	At       time.Time `json:"at"`
	Kind     string    `json:"kind"`
	ID       string    `json:"id"`
	Filter   string    `json:"filter"`
}

func decodeIdentityBridgeRunsCursor(raw, filter string) (identityBridgeRunsCursor, error) {
	var cursor identityBridgeRunsCursor
	if raw == "" {
		cursor.Snapshot, cursor.Filter = time.Now().UTC(), filter
		return cursor, nil
	}
	if len(raw) > 1024 {
		return cursor, fmt.Errorf("invalid identity run cursor")
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || json.Unmarshal(data, &cursor) != nil || cursor.Snapshot.IsZero() || cursor.At.IsZero() || cursor.Kind == "" || cursor.ID == "" || cursor.Filter != filter {
		return identityBridgeRunsCursor{}, fmt.Errorf("invalid identity run cursor")
	}
	return cursor, nil
}

func encodeIdentityBridgeRunsCursor(cursor identityBridgeRunsCursor) string {
	raw, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (s *Server) handleIdentityBridgeRunsSeek(w http.ResponseWriter, r *http.Request) {
	limit, err := boundedInt(r.URL.Query().Get("limit"), 20, 1, 50)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_limit", err.Error())
		return
	}
	kind, status := r.URL.Query().Get("kind"), r.URL.Query().Get("status")
	if kind != "" && kind != "event_batch" && kind != "snapshot" && kind != "config_switch" || status != "" && status != "completed" && status != "failed" && status != "running" {
		writeError(w, http.StatusBadRequest, "bad_identity_bridge_filter", "同步记录筛选条件无效")
		return
	}
	defaults := s.identityBridge.normalized()
	cursor, err := decodeIdentityBridgeRunsCursor(r.URL.Query().Get("cursor"), defaults.Source+"\x00"+defaults.BridgeID+"\x00"+kind+"\x00"+status)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_cursor", err.Error())
		return
	}
	args := []any{defaults.Source, defaults.BridgeID, kind, status, cursor.Snapshot}
	eventSeek, bridgeSeek := "", ""
	if cursor.ID != "" {
		args = append(args, cursor.At, cursor.Kind, cursor.ID)
		eventSeek = ` AND (received_at,'event_batch'::text,batch_id)<($6,$7,$8)`
		bridgeSeek = ` AND (started_at,kind,run_id)<($6,$7,$8)`
	}
	limitParameter := "$" + strconv.Itoa(len(args)+1)
	args = append(args, limit+1)
	query := `WITH event_runs AS MATERIALIZED (
 SELECT batch_id AS run_id,'event_batch'::text AS kind,status,records_read,records_emitted,records_skipped,records_malformed,
 retry_count,COALESCE((EXTRACT(EPOCH FROM (completed_at-received_at))*1000)::bigint,0) AS duration_ms,
 CASE WHEN COALESCE(error_message,'')='' THEN '' ELSE 'ingest_error' END AS error_type,
 received_at AS started_at,completed_at FROM identity_ingest_batches
 WHERE source=$1 AND ($3='' OR $3='event_batch') AND ($4='' OR status=$4) AND received_at<=$5` + eventSeek + `
 ORDER BY received_at DESC,batch_id DESC LIMIT ` + limitParameter + `
), bridge_runs AS MATERIALIZED (
 SELECT run_id,kind,status,records_read,records_emitted,records_skipped,records_malformed,retry_count,duration_ms,error_type,started_at,completed_at
 FROM identity_bridge_runs WHERE bridge_id=$2 AND ($3='' OR kind=$3) AND ($4='' OR status=$4) AND started_at<=$5` + bridgeSeek + `
 ORDER BY started_at DESC,kind DESC,run_id DESC LIMIT ` + limitParameter + `
) SELECT run_id,kind,status,records_read,records_emitted,records_skipped,records_malformed,retry_count,duration_ms,error_type,started_at,completed_at
 FROM (SELECT * FROM event_runs UNION ALL SELECT * FROM bridge_runs) runs
 ORDER BY started_at DESC,kind DESC,run_id DESC LIMIT ` + limitParameter
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	rows, err := s.operations.db.QueryContext(ctx, query, args...)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "identity_bridge_runs_unavailable", "同步记录读取失败")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0, limit)
	hasMore := false
	for rows.Next() {
		var id, itemKind, itemStatus, itemError string
		var read, emitted, skipped, malformed, retries int
		var duration int64
		var started time.Time
		var completed sql.NullTime
		if err := rows.Scan(&id, &itemKind, &itemStatus, &read, &emitted, &skipped, &malformed, &retries, &duration, &itemError, &started, &completed); err != nil {
			writeError(w, http.StatusServiceUnavailable, "identity_bridge_runs_unavailable", "同步记录读取失败")
			return
		}
		if len(items) == limit {
			hasMore = true
			break
		}
		item := map[string]any{"run_id": id, "kind": itemKind, "status": itemStatus, "records_read": read, "records_emitted": emitted,
			"records_skipped": skipped, "records_malformed": malformed, "retry_count": retries, "duration_ms": duration, "started_at": started.UTC()}
		if itemError != "" {
			item["error_type"] = itemError
		}
		if completed.Valid {
			item["completed_at"] = completed.Time.UTC()
		}
		items = append(items, item)
		cursor.At, cursor.Kind, cursor.ID = started, itemKind, id
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusServiceUnavailable, "identity_bridge_runs_unavailable", "同步记录读取失败")
		return
	}
	next := ""
	if hasMore {
		next = encodeIdentityBridgeRunsCursor(cursor)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next, "has_more": hasMore})
}
