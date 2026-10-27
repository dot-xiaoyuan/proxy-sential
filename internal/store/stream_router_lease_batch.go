package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/normalized"
)

type routerLeaseKey struct {
	sensor, campus, ip, at string
}

func routerLeaseKeyFromEvent(event normalized.Event) routerLeaseKey {
	return routerLeaseKey{
		sensor: stringFromMap(event.Observer, "sensor_id"),
		campus: stringFromMap(event.Subject, "campus_id"),
		ip:     stringFromMap(event.Subject, "ip"),
		at:     event.Timestamp,
	}
}

// resolveRouterLeaseBatch keeps the event-time lease rules of ResolveDeviceAt,
// but sends one bounded request for a stream batch instead of one SQL round trip
// per packet/TTL event. The typed lookup remains in PostgreSQL, not the hot
// capture path.
func (s *PostgresStore) resolveRouterLeaseBatch(ctx context.Context, events []normalized.Event) (map[routerLeaseKey]evidence.RouterAssociation, error) {
	if s == nil || s.db == nil || len(events) > 100 {
		return nil, errors.New("invalid router lease batch")
	}
	type request struct {
		SensorID string    `json:"sensor_id"`
		CampusID string    `json:"campus_id"`
		IP       string    `json:"ip"`
		At       time.Time `json:"at"`
	}
	ordered := make([]routerLeaseKey, 0, len(events))
	requests := make([]request, 0, len(events))
	seen := make(map[routerLeaseKey]bool, len(events))
	for _, event := range events {
		// AnalyzeRouters calls Resolve only when no explicit endpoint or valid
		// MAC was supplied. Match that branch to avoid unnecessary lease reads.
		if stringFromMap(event.Subject, "endpoint_id") != "" {
			continue
		}
		if mac, err := net.ParseMAC(stringFromMap(event.Subject, "mac")); err == nil &&
			len(mac) == 6 && mac[0]&1 == 0 && mac.String() != "00:00:00:00:00:00" {
			continue
		}
		key := routerLeaseKeyFromEvent(event)
		if key.sensor == "" || net.ParseIP(key.ip) == nil || seen[key] {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, key.at)
		if err != nil {
			continue
		}
		seen[key] = true
		ordered = append(ordered, key)
		requests = append(requests, request{SensorID: key.sensor, CampusID: key.campus, IP: key.ip, At: at.UTC()})
	}
	result := make(map[routerLeaseKey]evidence.RouterAssociation, len(ordered))
	if len(requests) == 0 {
		return result, nil
	}
	payload, err := json.Marshal(requests)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `WITH request AS (
 SELECT e.ordinality AS ordinal,e.item->>'sensor_id' AS sensor_id,e.item->>'campus_id' AS campus_id,
        e.item->>'ip' AS ip,(e.item->>'at')::timestamptz AS at
 FROM jsonb_array_elements($1::jsonb) WITH ORDINALITY AS e(item,ordinality)
)
SELECT request.ordinal,lease.endpoint_id FROM request LEFT JOIN LATERAL (
 SELECT DISTINCT l.endpoint_id FROM device_address_leases l
 WHERE l.sensor_id=request.sensor_id AND l.campus_id=request.campus_id AND l.ip=request.ip::inet AND l.action='ack'
 AND l.observed_at<=request.at AND l.valid_until>request.at
 AND NOT EXISTS (SELECT 1 FROM device_address_leases n
   WHERE n.sensor_id=l.sensor_id AND n.campus_id=l.campus_id AND n.ip=l.ip AND n.observed_at<=request.at
   AND ((n.action='ack' AND n.observed_at>l.observed_at)
     OR (n.action='stop' AND n.endpoint_id=l.endpoint_id AND n.observed_at>=l.observed_at)))
 ORDER BY l.endpoint_id LIMIT 2
) lease ON true ORDER BY request.ordinal,lease.endpoint_id`, payload)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	owners := make([][]string, len(ordered))
	for rows.Next() {
		var ordinal int
		var endpoint sql.NullString
		if err := rows.Scan(&ordinal, &endpoint); err != nil {
			return nil, err
		}
		if ordinal < 1 || ordinal > len(ordered) || len(owners[ordinal-1]) >= 2 {
			return nil, errors.New("invalid router lease batch result")
		}
		if endpoint.Valid {
			owners[ordinal-1] = append(owners[ordinal-1], endpoint.String)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for index, key := range ordered {
		association := evidence.RouterAssociation{}
		if len(owners[index]) > 0 {
			association.EndpointID = owners[index][0]
			association.Quality = "dhcp_lease"
			if strings.HasPrefix(association.EndpointID, "mac:") {
				association.MAC = strings.TrimPrefix(association.EndpointID, "mac:")
			}
			if len(owners[index]) > 1 {
				association.Ambiguous = true
				association.Reason = "同一传感器和园区存在冲突 DHCP 租约"
			}
		}
		result[key] = association
	}
	return result, nil
}
