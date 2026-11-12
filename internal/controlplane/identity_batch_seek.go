package controlplane

import (
	"database/sql"
	"net/http"
	"sort"
	"strconv"
	"time"
)

func (s *Server) handleIdentityBatchesSeek(w http.ResponseWriter, r *http.Request) {
	limit, err := boundedInt(r.URL.Query().Get("limit"), 20, 1, 50)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_limit", err.Error())
		return
	}
	cursor, err := decodeRecordCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_cursor", err.Error())
		return
	}
	if cursor.Snapshot.IsZero() {
		cursor.Snapshot = time.Now().UTC()
	}
	if s.identityIngest.db == nil {
		type ranked struct {
			item IdentityIngestBatch
			at   time.Time
		}
		selected := make([]ranked, 0, limit+1)
		s.identityIngest.mu.Lock()
		for _, item := range s.identityIngest.batches {
			at, parseErr := time.Parse(time.RFC3339Nano, item.ReceivedAt)
			if parseErr != nil || at.After(cursor.Snapshot) || (cursor.ID != "" && !at.Before(cursor.At) && !(at.Equal(cursor.At) && item.BatchID < cursor.ID)) {
				continue
			}
			pos := sort.Search(len(selected), func(i int) bool {
				return at.After(selected[i].at) || (at.Equal(selected[i].at) && item.BatchID > selected[i].item.BatchID)
			})
			if pos >= limit+1 {
				continue
			}
			selected = append(selected, ranked{})
			copy(selected[pos+1:], selected[pos:len(selected)-1])
			selected[pos] = ranked{item: item, at: at}
			if len(selected) > limit+1 {
				selected = selected[:limit+1]
			}
		}
		s.identityIngest.mu.Unlock()
		items := make([]IdentityIngestBatch, 0, min(limit, len(selected)))
		for _, row := range selected[:min(limit, len(selected))] {
			items = append(items, row.item)
			cursor.At, cursor.ID = row.at, row.item.BatchID
		}
		next := ""
		if len(selected) > limit {
			next = encodeRecordCursor(cursor)
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next, "has_more": next != ""})
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	query := `SELECT batch_id,source,sensor_id,status,records_read,records_emitted,records_skipped,records_malformed,
 COALESCE(error_message,''),received_at,retry_count,last_retried_at FROM identity_ingest_batches WHERE received_at<=$1`
	args := []any{cursor.Snapshot}
	if cursor.ID != "" {
		query += ` AND (received_at,batch_id)<($2,$3)`
		args = append(args, cursor.At, cursor.ID)
	}
	query += ` ORDER BY received_at DESC,batch_id DESC LIMIT $` + strconv.Itoa(len(args)+1)
	args = append(args, limit+1)
	rows, err := s.identityIngest.db.QueryContext(ctx, query, args...)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "identity_batches_failed", err.Error())
		return
	}
	defer rows.Close()
	items := make([]IdentityIngestBatch, 0, limit)
	hasMore := false
	for rows.Next() {
		var item IdentityIngestBatch
		var receivedAt time.Time
		var lastRetry sql.NullTime
		if err := rows.Scan(&item.BatchID, &item.Source, &item.SensorID, &item.Status, &item.Read, &item.Emitted, &item.Skipped, &item.Malformed, &item.Error, &receivedAt, &item.RetryCount, &lastRetry); err != nil {
			writeError(w, http.StatusServiceUnavailable, "identity_batches_failed", err.Error())
			return
		}
		if len(items) == limit {
			hasMore = true
			break
		}
		item.ReceivedAt = receivedAt.UTC().Format(time.RFC3339Nano)
		if lastRetry.Valid {
			item.LastRetry = lastRetry.Time.UTC().Format(time.RFC3339Nano)
		}
		items = append(items, item)
		cursor.At, cursor.ID = receivedAt, item.BatchID
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusServiceUnavailable, "identity_batches_failed", err.Error())
		return
	}
	next := ""
	if hasMore {
		next = encodeRecordCursor(cursor)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next, "has_more": hasMore})
}
