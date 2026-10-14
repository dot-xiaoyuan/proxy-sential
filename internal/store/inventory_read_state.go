package store

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"strings"
	"time"
)

var ErrInventoryNotReady = errors.New("终端检索投影正在回填，请稍后刷新；未回退读取历史明细")

type InventoryProjectionState struct {
	Available            bool    `json:"available"`
	Complete             bool    `json:"complete"`
	Updating             bool    `json:"updating"`
	AsOf                 string  `json:"as_of"`
	Error                string  `json:"error,omitempty"`
	Status               string  `json:"status"`
	AcceptedWatermark    int64   `json:"accepted_watermark"`
	ProcessedWatermark   int64   `json:"processed_watermark"`
	OldestPendingAt      string  `json:"oldest_pending_at,omitempty"`
	ProcessingLagSeconds float64 `json:"processing_lag_seconds,omitempty"`
	ResultVersion        string  `json:"result_version,omitempty"`
}
type inventoryRowQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func inventoryProjectionState(ctx context.Context, db inventoryRowQueryer) (InventoryProjectionState, error) {
	var s InventoryProjectionState
	var at time.Time
	var oldest sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT backfill_complete AND ready,
 (EXISTS(SELECT 1 FROM endpoint_inventory_projection_jobs WHERE processed_generation<dirty_generation LIMIT 1) OR EXISTS(SELECT 1 FROM endpoint_inventory_snapshot_jobs WHERE NOT processed LIMIT 1)),updated_at,last_error,
 COALESCE((SELECT max(dirty_generation) FROM endpoint_inventory_projection_jobs),0),
 COALESCE((SELECT max(processed_generation) FROM endpoint_inventory_projection_jobs),0),
 (SELECT min(coalesce(pending_since,updated_at)) FROM endpoint_inventory_projection_jobs WHERE processed_generation<dirty_generation) , (summary_complete OR ready) FROM endpoint_inventory_projection_state WHERE singleton`).Scan(&s.Complete, &s.Updating, &at, &s.Error, &s.AcceptedWatermark, &s.ProcessedWatermark, &oldest, &s.Available)
	s.AsOf = at.UTC().Format(time.RFC3339Nano)
	s.ResultVersion = s.AsOf
	s.Status = "ready"
	if s.Error != "" {
		s.Status = "failed"
	} else if !s.Complete {
		s.Status = "backfilling"
	} else if s.Updating {
		s.Status = "processing"
	}
	if oldest.Valid {
		s.OldestPendingAt = oldest.Time.UTC().Format(time.RFC3339Nano)
		s.ProcessingLagSeconds = max(0, time.Since(oldest.Time).Seconds())
	}
	return s, err
}
func inventoryLikeValue(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(s))
}
func inventoryIPMatches(ctx context.Context, db deviceInventoryQueryer, ids []string, q Query, now time.Time) (map[string]*DeviceIPMatch, error) {
	result := map[string]*DeviceIPMatch{}
	if q.InventorySearchType != "all" && q.InventorySearchType != "ip" && q.SrcIP == "" {
		return result, nil
	}
	ip := deviceExactIP(q)
	if ip == "" || len(ids) == 0 {
		return result, nil
	}
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT ON(endpoint_id) endpoint_id,ip,source,matched_at FROM (
 SELECT endpoint_id,host(ip) ip,'ip_observation' source,observed_at matched_at FROM endpoint_inventory_ip_points WHERE endpoint_id=ANY($5::text[]) AND ip=$1::inet AND (NOT $2 OR observed_at BETWEEN $3 AND $4)
 UNION ALL SELECT endpoint_id,host(ip),CASE WHEN interval_explicit THEN 'account_session' ELSE 'snapshot_confirmation' END,confirmed_at FROM endpoint_inventory_sessions WHERE endpoint_id=ANY($5::text[]) AND ip=$1::inet AND (NOT $2 OR (interval_explicit AND started_at<=$4 AND (ended_at IS NULL OR ended_at>=$3)) OR (NOT interval_explicit AND confirmed_at BETWEEN $3 AND $4))
 )m ORDER BY endpoint_id,matched_at DESC,source`, ip, q.View == "recent", deviceViewStart(q, now), now, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var at time.Time
		m := &DeviceIPMatch{}
		if err = rows.Scan(&id, &m.IP, &m.Source, &at); err != nil {
			return nil, err
		}
		m.IP = net.ParseIP(m.IP).String()
		m.MatchedAt = at.UTC().Format(time.RFC3339Nano)
		result[id] = m
	}
	return result, rows.Err()
}
