package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"proxy-sentinel/internal/discovery"
)

// streamDiscoveryDevices keeps the complete filtered export on one read-only
// PostgreSQL snapshot. The final record is required before a client creates a
// CSV; a failed or interrupted stream is never a partial successful export.
func (s *Server) streamDiscoveryDevices(w http.ResponseWriter, ctx context.Context, repo discovery.Repository, query discovery.DeviceQuery) {
	query.Export = true
	query.Limit = 1000
	query.Cursor = ""
	query.SnapshotAt = time.Now().UTC()
	tx, err := repo.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		writeError(w, 500, "discovery_export_snapshot", "创建导出快照失败")
		return
	}
	defer tx.Rollback()
	meta, err := repo.DevicesIndexedMetadataSnapshot(ctx, tx, query)
	if err != nil {
		log.Printf("discovery export metadata failed: %v", err)
		writeError(w, 500, "discovery_export_metadata", "读取导出数量失败")
		return
	}
	const maxRows = 200_000
	if meta.Total > maxRows {
		writeError(w, http.StatusRequestEntityTooLarge, "discovery_export_limit", "筛选结果超过 200,000 台，请缩小范围后导出")
		return
	}
	page, err := repo.DevicesIndexedSnapshot(ctx, tx, query)
	if err != nil {
		log.Printf("discovery export first page failed: %v", err)
		writeError(w, 500, "discovery_export_page", "读取导出清单失败")
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	flusher, _ := w.(http.Flusher)
	emit := func(record any) bool { return enc.Encode(record) == nil }
	if !emit(map[string]any{"record": "manifest", "total": meta.Total, "snapshot_at": query.SnapshotAt, "count_unit": meta.CountUnit}) {
		return
	}
	var count int64
	seen := map[string]bool{}
	for {
		enrichDiscoveryRecognitionSnapshot(ctx, tx, page)
		items, ok := discoveryPageItems(page)
		if !ok {
			_ = emit(map[string]any{"record": "error", "message": "导出设备结构无效"})
			return
		}
		for _, item := range items {
			count++
			if count > maxRows || !emit(map[string]any{"record": "item", "item": item}) {
				if count > maxRows {
					_ = emit(map[string]any{"record": "error", "message": "导出超过 200,000 台"})
				}
				return
			}
		}
		if flusher != nil {
			flusher.Flush()
		}
		more, _ := page["has_more"].(bool)
		if !more {
			break
		}
		cursor, _ := page["next_cursor"].(string)
		if cursor == "" || seen[cursor] || len(items) == 0 {
			_ = emit(map[string]any{"record": "error", "message": "导出分页中断"})
			return
		}
		seen[cursor] = true
		query.Cursor = cursor
		page, err = repo.DevicesIndexedSnapshot(ctx, tx, query)
		if err != nil {
			log.Printf("discovery export page failed after %d rows: %v", count, err)
			_ = emit(map[string]any{"record": "error", "message": "读取导出清单失败"})
			return
		}
	}
	if count != meta.Total {
		log.Printf("discovery export count mismatch: rows=%d metadata=%d", count, meta.Total)
		_ = emit(map[string]any{"record": "error", "message": "导出数量与统计不一致"})
		return
	}
	if err = tx.Commit(); err != nil {
		log.Printf("discovery export snapshot commit failed: %v", err)
		_ = emit(map[string]any{"record": "error", "message": "完成导出快照失败"})
		return
	}
	_ = emit(map[string]any{"record": "end", "count": count, "complete": true})
	if flusher != nil {
		flusher.Flush()
	}
}
