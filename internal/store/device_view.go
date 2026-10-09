package store

import (
	"context"
	"database/sql"
	"net"
	"strings"
	"time"
)

func deviceViewStart(q Query, now time.Time) time.Time {
	window := q.Window
	if window == "" {
		window = "24h"
	}
	_, duration, err := NormalizeActivityWindow(window)
	if err != nil {
		duration = 24 * time.Hour
	}
	return now.Add(-duration)
}
func deviceInView(d EndpointDeviceInventory, q Query, now time.Time) bool {
	if q.View != "recent" {
		return true
	}
	at, err := time.Parse(time.RFC3339Nano, d.LastSeen)
	return err == nil && !at.Before(deviceViewStart(q, now)) && !at.After(now)
}
func deviceExactIP(q Query) string {
	if ip := net.ParseIP(strings.TrimSpace(q.Q)); ip != nil {
		return ip.String()
	}
	if ip := net.ParseIP(strings.TrimSpace(q.SrcIP)); ip != nil {
		return ip.String()
	}
	return ""
}

// Both the search predicate and page annotations use the same bounded evidence relation.
const deviceIPMatchRelation = `SELECT endpoint_id,host(ip) AS ip,'ip_observation' AS source,last_seen AS matched_at,event_id AS tie FROM identity_ip_mac_history WHERE ip=$1::inet AND ($2::boolean=false OR (last_seen >= $3 AND first_seen <= $4 AND last_seen <= $4))
 UNION ALL SELECT endpoint_id,host(ip),'account_session',coalesce(ended_at,started_at),session_id FROM account_sessions WHERE ip=$1::inet AND ($2::boolean=false OR (started_at <= $4 AND (ended_at IS NULL OR ended_at >= $3)))`

func (s *PostgresStore) deviceIPMatches(ctx context.Context, ids []string, q Query, now time.Time) (map[string]*DeviceIPMatch, error) {
	return s.deviceIPMatchesWith(ctx, s.db, ids, q, now)
}

type deviceInventoryQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func (s *PostgresStore) deviceIPMatchesWith(ctx context.Context, db deviceInventoryQueryer, ids []string, q Query, now time.Time) (map[string]*DeviceIPMatch, error) {
	out := map[string]*DeviceIPMatch{}
	ip := deviceExactIP(q)
	if ip == "" || len(ids) == 0 {
		return out, nil
	}
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT ON(endpoint_id) endpoint_id,ip,source,matched_at FROM (`+deviceIPMatchRelation+`) m WHERE endpoint_id=ANY($5::text[]) ORDER BY endpoint_id,matched_at DESC,source,tie DESC`, ip, q.View == "recent", deviceViewStart(q, now), now, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var at time.Time
		n := &DeviceIPMatch{}
		if err = rows.Scan(&id, &n.IP, &n.Source, &at); err != nil {
			return nil, err
		}
		n.MatchedAt = at.UTC().Format(time.RFC3339Nano)
		out[id] = n
	}
	return out, rows.Err()
}
