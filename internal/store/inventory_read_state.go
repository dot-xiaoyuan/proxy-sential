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

// inventoryProjectionState reports the terminal read model's freshness. The endpoint
// state updater (endpoint_state.go) owns the read model; the old projection job tables
// are no longer written.
func inventoryProjectionState(ctx context.Context, db inventoryRowQueryer) (InventoryProjectionState, error) {
	return endpointStateProjection(ctx, db)
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
 SELECT endpoint_id,host(ip) ip,'ip_observation' source,observed_at matched_at FROM device_address_leases WHERE endpoint_id=ANY($5::text[]) AND ip=$1::inet AND (NOT $2 OR observed_at BETWEEN $3 AND $4)
 UNION ALL SELECT endpoint_id,host(ip),'account_session',greatest(started_at,coalesce(nullif(policy_metadata->>'last_confirmed_at','')::timestamptz,started_at)) FROM account_sessions WHERE endpoint_id=ANY($5::text[]) AND ip=$1::inet AND (NOT $2 OR (started_at<=$4 AND (ended_at IS NULL OR ended_at>=$3)))
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
