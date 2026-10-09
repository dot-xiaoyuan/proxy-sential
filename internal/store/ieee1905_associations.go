package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

type ieee1905AssociationRow struct {
	Timestamp       string                        `json:"event_timestamp"`
	EventID         string                        `json:"event_id"`
	SensorID        string                        `json:"sensor_id"`
	CampusID        string                        `json:"campus_id"`
	AccessDomain    string                        `json:"access_domain"`
	GatewayIP       string                        `json:"gateway_ip"`
	GatewayMAC      string                        `json:"gateway_mac"`
	BSSID           string                        `json:"bssid"`
	ClientMAC       string                        `json:"client_mac"`
	State           string                        `json:"association_state"`
	Source          string                        `json:"source"`
	SourceEventType string                        `json:"source_event_type"`
	Snapshots       []ieee1905AssociationSnapshot `json:"bss_snapshots"`
	SnapshotsJSON   string                        `json:"bss_snapshots_json"`
}

type ieee1905AssociationSnapshot struct {
	BSSID      string   `json:"bssid"`
	ClientMACs []string `json:"client_macs"`
}

type ieee1905AssociationGroup struct {
	SensorID, CampusID, AccessDomain string
	GatewayIP, GatewayMAC            string
	Clients                          []string
	ClientLastSeen                   map[string]time.Time
	ClientEventIDs                   map[string]string
	EventIDs                         []string
	FirstSeen, LastSeen              time.Time
}

// Older workers stored refreshes beyond the closed window. Replay may restore
// a join from that window, but cannot undo a leave or cross an ownership scope.
const ieee1905AssociationUpsertSQL = `INSERT INTO ieee1905_client_associations(
 sensor_id,campus_id,access_domain,gateway_ip,gateway_mac,bssid,client_mac,association_state,
 first_seen,last_seen,last_event_id,source)
VALUES($1,$2,$3,NULLIF($4,'')::inet,$5,$6,$7,$8,$9,$9,$10,$11)
ON CONFLICT(sensor_id,gateway_mac,client_mac) DO UPDATE SET
 campus_id=EXCLUDED.campus_id,access_domain=EXCLUDED.access_domain,
	 gateway_ip=EXCLUDED.gateway_ip,
 bssid=EXCLUDED.bssid,association_state=EXCLUDED.association_state,
 first_seen=LEAST(ieee1905_client_associations.first_seen,EXCLUDED.first_seen),
 last_seen=EXCLUDED.last_seen,last_event_id=EXCLUDED.last_event_id,source=EXCLUDED.source,updated_at=now()
WHERE (EXCLUDED.last_seen>ieee1905_client_associations.last_seen
 OR (EXCLUDED.last_seen=ieee1905_client_associations.last_seen
 AND (ieee1905_client_associations.association_state<>'left' OR EXCLUDED.association_state='left'))
 OR (ieee1905_client_associations.association_state='joined' AND EXCLUDED.association_state='joined'
 AND ieee1905_client_associations.campus_id=EXCLUDED.campus_id
 AND ieee1905_client_associations.access_domain=EXCLUDED.access_domain
 AND ieee1905_client_associations.last_seen>=$12 AND EXCLUDED.last_seen<$12))
 AND (EXCLUDED.association_state<>'left'
 OR (ieee1905_client_associations.bssid=EXCLUDED.bssid
 AND ieee1905_client_associations.campus_id=EXCLUDED.campus_id
 AND ieee1905_client_associations.access_domain=EXCLUDED.access_domain))`

func validUnicastMAC(value string) bool {
	mac, err := net.ParseMAC(value)
	return err == nil && len(mac) == 6 && mac[0]&1 == 0 && mac.String() != "00:00:00:00:00:00"
}

func (s *DBStore) syncIEEE1905Associations(ctx context.Context, sensorID string, from, to time.Time, positiveCutoffs ...time.Time) error {
	if len(positiveCutoffs) > 1 {
		return fmt.Errorf("multiple IEEE 1905 positive cutoffs")
	}
	positiveBefore := to
	if len(positiveCutoffs) > 0 {
		positiveBefore = positiveCutoffs[0]
	}
	if positiveBefore.Before(from) || positiveBefore.After(to) {
		return fmt.Errorf("invalid IEEE 1905 positive window")
	}
	// Only fresh associations can support this window. Include events up to now
	// so a later leave invalidates an earlier join without rescanning history.
	query := fmt.Sprintf(`SELECT
 formatDateTime(timestamp,'%%Y-%%m-%%dT%%H:%%i:%%S.%%fZ','UTC') AS event_timestamp,
 event_id,sensor_id,campus_id,
 JSONExtractString(payload_json,'access_domain') AS access_domain,
 subject_ip AS gateway_ip,subject_mac AS gateway_mac,
 JSONExtractString(payload_json,'bssid') AS bssid,
 JSONExtractString(payload_json,'client_mac') AS client_mac,
 JSONExtractString(payload_json,'association_state') AS association_state,source,source_event_type,
 JSONExtractRaw(payload_json,'bss_snapshots') AS bss_snapshots_json
FROM normalized_events
PREWHERE sensor_id=%s AND normalized_events.timestamp>=parseDateTime64BestEffort(%s,6)
 AND normalized_events.timestamp<parseDateTime64BestEffort(%s,6)
WHERE source_event_type IN ('ieee1905_client_association','ieee1905_client_snapshot')
ORDER BY timestamp,event_id
LIMIT 100000 SETTINGS max_threads=2,max_memory_usage=268435456,max_execution_time=20 FORMAT JSONEachRow`,
		chQuote(sensorID), chQuote(from.UTC().Format(time.RFC3339Nano)), chQuote(to.UTC().Format(time.RFC3339Nano)))
	raw, err := s.ch.query(ctx, query)
	if err != nil {
		return err
	}
	rows := []ieee1905AssociationRow{}
	if err = decodeJSONEachRow(raw, &rows); err != nil {
		return err
	}
	if len(rows) >= 100000 {
		return fmt.Errorf("IEEE 1905 association result reached safety limit")
	}
	type addressKey struct {
		sensor, campus, mac string
		at                  time.Time
	}
	// Client snapshots often repeat the same gateway and timestamp for many
	// clients. Resolve each ownership boundary once per materialization batch.
	addresses := map[addressKey]string{}
	for _, row := range rows {
		at, parseErr := time.Parse(time.RFC3339Nano, normalizeClickHouseTimestamp(row.Timestamp))
		if parseErr != nil || at.Before(from) || !at.Before(to) || row.SensorID != sensorID || row.EventID == "" || !validUnicastMAC(row.GatewayMAC) {
			continue
		}
		if row.SourceEventType == "ieee1905_client_snapshot" {
			if row.SnapshotsJSON != "" && json.Unmarshal([]byte(row.SnapshotsJSON), &row.Snapshots) != nil {
				continue
			}
			if err = s.applyIEEE1905Snapshot(ctx, row, at, positiveBefore); err != nil {
				return err
			}
			continue
		}
		if !validUnicastMAC(row.ClientMAC) || !validUnicastMAC(row.BSSID) || row.State != "joined" && row.State != "left" {
			continue
		}
		// Joins after the closed window wait for its next generation. Later
		// leaves still invalidate old membership immediately.
		if row.State == "joined" && !at.Before(positiveBefore) {
			continue
		}
		// IEEE 1905 is an Ethernet control protocol. A subject IP inferred from
		// unrelated forwarded packets does not establish gateway ownership.
		// Resolve the MAC using the lease valid at this event's timestamp.
		key := addressKey{row.SensorID, row.CampusID, strings.ToLower(row.GatewayMAC), at.UTC()}
		gatewayIP, cached := addresses[key]
		if !cached {
			var resolveErr error
			gatewayIP, resolveErr = s.ieee1905GatewayIPAt(ctx, row.SensorID, row.CampusID, row.GatewayMAC, at)
			if resolveErr != nil {
				return resolveErr
			}
			addresses[key] = gatewayIP
		}
		_, err = s.pg.db.ExecContext(ctx, ieee1905AssociationUpsertSQL,
			row.SensorID, row.CampusID, row.AccessDomain, gatewayIP, strings.ToLower(row.GatewayMAC), strings.ToLower(row.BSSID),
			strings.ToLower(row.ClientMAC), row.State, at, row.EventID, row.Source, positiveBefore)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *DBStore) applyIEEE1905Snapshot(ctx context.Context, row ieee1905AssociationRow, at, positiveBefore time.Time) error {
	includeJoins := at.Before(positiveBefore)
	// Only explicitly reported BSSs are authoritative. An empty BSS list has
	// no scope and cannot retire associations elsewhere on the device.
	seen := map[string]bool{}
	for _, snapshot := range row.Snapshots {
		bssid := strings.ToLower(snapshot.BSSID)
		if !validUnicastMAC(bssid) || seen[bssid] {
			return nil
		}
		seen[bssid] = true
		clients := map[string]bool{}
		for _, client := range snapshot.ClientMACs {
			client = strings.ToLower(client)
			if !validUnicastMAC(client) || clients[client] {
				return nil
			}
			clients[client] = true
		}
	}
	if len(row.Snapshots) == 0 {
		return nil
	}
	gatewayIP := ""
	for _, snapshot := range row.Snapshots {
		if includeJoins && len(snapshot.ClientMACs) > 0 {
			var resolveErr error
			gatewayIP, resolveErr = s.ieee1905GatewayIPAt(ctx, row.SensorID, row.CampusID, row.GatewayMAC, at)
			if resolveErr != nil {
				return resolveErr
			}
			break
		}
	}
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, snapshot := range row.Snapshots {
		clients := make([]string, 0, len(snapshot.ClientMACs))
		for _, client := range snapshot.ClientMACs {
			clients = append(clients, strings.ToLower(client))
		}
		for _, client := range clients {
			if !includeJoins {
				break
			}
			_, err = tx.ExecContext(ctx, ieee1905AssociationUpsertSQL, row.SensorID, row.CampusID, row.AccessDomain, gatewayIP, strings.ToLower(row.GatewayMAC), strings.ToLower(snapshot.BSSID), client, "joined", at, row.EventID, row.Source, positiveBefore)
			if err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `UPDATE ieee1905_client_associations SET
 association_state='left',last_seen=$6,last_event_id=$7,source=$9,updated_at=now()
WHERE sensor_id=$1 AND campus_id=$2 AND access_domain=$3 AND gateway_mac=$4 AND bssid=$5
 AND association_state='joined' AND last_seen<=$6 AND NOT (client_mac=ANY($8::text[]))`,
			row.SensorID, row.CampusID, row.AccessDomain, strings.ToLower(row.GatewayMAC), strings.ToLower(snapshot.BSSID), at, row.EventID, clients, row.Source)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *DBStore) ieee1905GatewayIPAt(ctx context.Context, sensor, campus, mac string, at time.Time) (string, error) {
	rows, err := s.pg.db.QueryContext(ctx, `SELECT DISTINCT host(l.ip) FROM device_address_leases l
WHERE l.sensor_id=$1 AND l.campus_id=$2 AND l.endpoint_id=$3 AND l.action='ack'
 AND l.observed_at<=$4 AND l.valid_until>$4
 AND NOT EXISTS (SELECT 1 FROM device_address_leases n
  WHERE n.sensor_id=l.sensor_id AND n.campus_id=l.campus_id AND n.observed_at<=$4
  AND ((n.action='stop' AND n.endpoint_id=l.endpoint_id AND n.ip=l.ip AND n.observed_at>=l.observed_at)
   OR (n.action='ack' AND n.ip=l.ip AND (n.observed_at>l.observed_at OR (n.observed_at=l.observed_at AND n.endpoint_id<>l.endpoint_id)))
   OR (n.action='ack' AND n.endpoint_id=l.endpoint_id AND n.observed_at>l.observed_at)))
ORDER BY 1 LIMIT 2`, sensor, campus, "mac:"+strings.ToLower(mac), at)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	ips := []string{}
	for rows.Next() {
		var ip string
		if err = rows.Scan(&ip); err != nil {
			return "", err
		}
		ips = append(ips, ip)
	}
	if err = rows.Err(); err != nil {
		return "", err
	}
	if len(ips) != 1 {
		return "", nil
	}
	return ips[0], nil
}

func (s *DBStore) activeIEEE1905AssociationGroups(ctx context.Context, sensorID string, from, to time.Time) ([]ieee1905AssociationGroup, error) {
	rows, err := s.pg.db.QueryContext(ctx, `SELECT sensor_id,campus_id,access_domain,host(gateway_ip),gateway_mac,client_mac,
 first_seen,last_seen,last_event_id
FROM ieee1905_client_associations
WHERE sensor_id=$1 AND association_state='joined' AND gateway_ip IS NOT NULL AND last_seen>=$2 AND last_seen<$3
ORDER BY gateway_ip,client_mac`, sensorID, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groups := map[string]*ieee1905AssociationGroup{}
	for rows.Next() {
		var sensor, campus, domain, gatewayIP, gatewayMAC, clientMAC, eventID string
		var firstSeen, lastSeen time.Time
		if err = rows.Scan(&sensor, &campus, &domain, &gatewayIP, &gatewayMAC, &clientMAC, &firstSeen, &lastSeen, &eventID); err != nil {
			return nil, err
		}
		key := strings.Join([]string{sensor, campus, domain, gatewayIP, gatewayMAC}, "\x00")
		group := groups[key]
		if group == nil {
			group = &ieee1905AssociationGroup{SensorID: sensor, CampusID: campus, AccessDomain: domain, GatewayIP: gatewayIP, GatewayMAC: gatewayMAC, FirstSeen: firstSeen, LastSeen: lastSeen, ClientLastSeen: map[string]time.Time{}, ClientEventIDs: map[string]string{}}
			groups[key] = group
		}
		group.Clients = append(group.Clients, clientMAC)
		group.ClientLastSeen[clientMAC] = lastSeen
		group.ClientEventIDs[clientMAC] = eventID
		if eventID != "" {
			group.EventIDs = append(group.EventIDs, eventID)
		}
		if firstSeen.Before(group.FirstSeen) {
			group.FirstSeen = firstSeen
		}
		if lastSeen.After(group.LastSeen) {
			group.LastSeen = lastSeen
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	result := make([]ieee1905AssociationGroup, 0, len(groups))
	for _, group := range groups {
		// A lease can expire or be reassigned while no new association event
		// arrives. Do not let the persisted IP outlive its ownership proof.
		ownershipAt := time.Now().UTC()
		if to.After(ownershipAt) {
			ownershipAt = to
		}
		ipCurrent, resolveErr := s.ieee1905GatewayIPAt(ctx, group.SensorID, group.CampusID, group.GatewayMAC, ownershipAt)
		if resolveErr != nil {
			return nil, resolveErr
		}
		if ipCurrent != group.GatewayIP {
			continue
		}
		clients, events := []string{}, []string{}
		times := map[time.Time]string{}
		eventSeen := map[string]bool{}
		lastObserved := time.Time{}
		for _, client := range group.Clients {
			if !validUnicastMAC(client) {
				continue
			}
			at := group.ClientLastSeen[client]
			ip, cached := times[at]
			if !cached {
				ip, resolveErr = s.ieee1905GatewayIPAt(ctx, group.SensorID, group.CampusID, group.GatewayMAC, at)
				if resolveErr != nil {
					return nil, resolveErr
				}
				times[at] = ip
			}
			if ip != group.GatewayIP {
				continue
			}
			clients = append(clients, client)
			if at.After(lastObserved) {
				lastObserved = at
			}
			id := group.ClientEventIDs[client]
			if id != "" && !eventSeen[id] {
				events = append(events, id)
				eventSeen[id] = true
			}
		}
		if len(clients) == 0 {
			continue
		}
		group.Clients, group.EventIDs, group.LastSeen = clients, events, lastObserved
		sort.Strings(group.Clients)
		sort.Strings(group.EventIDs)
		result = append(result, *group)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].GatewayIP < result[j].GatewayIP })
	return result, nil
}
