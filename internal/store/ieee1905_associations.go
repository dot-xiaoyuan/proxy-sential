package store

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

type ieee1905AssociationRow struct {
	Timestamp    string `json:"event_timestamp"`
	EventID      string `json:"event_id"`
	SensorID     string `json:"sensor_id"`
	CampusID     string `json:"campus_id"`
	AccessDomain string `json:"access_domain"`
	GatewayIP    string `json:"gateway_ip"`
	GatewayMAC   string `json:"gateway_mac"`
	BSSID        string `json:"bssid"`
	ClientMAC    string `json:"client_mac"`
	State        string `json:"association_state"`
	Source       string `json:"source"`
}

type ieee1905AssociationGroup struct {
	SensorID, CampusID, AccessDomain string
	GatewayIP, GatewayMAC            string
	Clients                          []string
	EventIDs                         []string
	FirstSeen, LastSeen              time.Time
}

func validUnicastMAC(value string) bool {
	mac, err := net.ParseMAC(value)
	return err == nil && len(mac) == 6 && mac[0]&1 == 0 && mac.String() != "00:00:00:00:00:00"
}

func (s *DBStore) syncIEEE1905Associations(ctx context.Context, sensorID string, now time.Time) error {
	query := fmt.Sprintf(`SELECT
 formatDateTime(timestamp,'%%Y-%%m-%%dT%%H:%%i:%%S.%%fZ','UTC') AS event_timestamp,
 event_id,sensor_id,campus_id,
 JSONExtractString(payload_json,'access_domain') AS access_domain,
 subject_ip AS gateway_ip,subject_mac AS gateway_mac,
 JSONExtractString(payload_json,'bssid') AS bssid,
 JSONExtractString(payload_json,'client_mac') AS client_mac,
 JSONExtractString(payload_json,'association_state') AS association_state,source
FROM normalized_events
PREWHERE sensor_id=%s AND normalized_events.timestamp>=parseDateTime64BestEffort(%s,6)
WHERE source_event_type='ieee1905_client_association'
ORDER BY timestamp,event_id
LIMIT 100000 SETTINGS max_threads=2,max_memory_usage=268435456,max_execution_time=20 FORMAT JSONEachRow`,
		chQuote(sensorID), chQuote(now.UTC().Add(-8*24*time.Hour).Format(time.RFC3339Nano)))
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
	for _, row := range rows {
		at, parseErr := time.Parse(time.RFC3339Nano, normalizeClickHouseTimestamp(row.Timestamp))
		if parseErr != nil || row.SensorID == "" || row.EventID == "" || !validUnicastMAC(row.GatewayMAC) || !validUnicastMAC(row.ClientMAC) || !validUnicastMAC(row.BSSID) || row.State != "joined" && row.State != "left" {
			continue
		}
		gatewayIP := strings.TrimSpace(row.GatewayIP)
		if gatewayIP != "" && net.ParseIP(gatewayIP) == nil {
			gatewayIP = ""
		}
		if gatewayIP == "" {
			_ = s.pg.db.QueryRowContext(ctx, `SELECT host(ip) FROM device_address_leases
WHERE sensor_id=$1 AND endpoint_id=$2 AND action='ack' AND observed_at<=$3
ORDER BY observed_at DESC LIMIT 1`, row.SensorID, "mac:"+strings.ToLower(row.GatewayMAC), at).Scan(&gatewayIP)
		}
		_, err = s.pg.db.ExecContext(ctx, `INSERT INTO ieee1905_client_associations(
 sensor_id,campus_id,access_domain,gateway_ip,gateway_mac,bssid,client_mac,association_state,
 first_seen,last_seen,last_event_id,source)
VALUES($1,$2,$3,NULLIF($4,'')::inet,$5,$6,$7,$8,$9,$9,$10,$11)
ON CONFLICT(sensor_id,gateway_mac,client_mac) DO UPDATE SET
 campus_id=EXCLUDED.campus_id,access_domain=EXCLUDED.access_domain,
 gateway_ip=COALESCE(EXCLUDED.gateway_ip,ieee1905_client_associations.gateway_ip),
 bssid=EXCLUDED.bssid,association_state=EXCLUDED.association_state,
 first_seen=LEAST(ieee1905_client_associations.first_seen,EXCLUDED.first_seen),
 last_seen=EXCLUDED.last_seen,last_event_id=EXCLUDED.last_event_id,source=EXCLUDED.source,updated_at=now()
WHERE EXCLUDED.last_seen>=ieee1905_client_associations.last_seen`,
			row.SensorID, row.CampusID, row.AccessDomain, gatewayIP, strings.ToLower(row.GatewayMAC), strings.ToLower(row.BSSID),
			strings.ToLower(row.ClientMAC), row.State, at, row.EventID, row.Source)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *DBStore) activeIEEE1905AssociationGroups(ctx context.Context, sensorID string) ([]ieee1905AssociationGroup, error) {
	rows, err := s.pg.db.QueryContext(ctx, `SELECT sensor_id,campus_id,access_domain,host(gateway_ip),gateway_mac,client_mac,
 first_seen,last_seen,last_event_id
FROM ieee1905_client_associations
WHERE sensor_id=$1 AND association_state='joined' AND gateway_ip IS NOT NULL
ORDER BY gateway_ip,client_mac`, sensorID)
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
			group = &ieee1905AssociationGroup{SensorID: sensor, CampusID: campus, AccessDomain: domain, GatewayIP: gatewayIP, GatewayMAC: gatewayMAC, FirstSeen: firstSeen, LastSeen: lastSeen}
			groups[key] = group
		}
		group.Clients = append(group.Clients, clientMAC)
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
	result := make([]ieee1905AssociationGroup, 0, len(groups))
	for _, group := range groups {
		sort.Strings(group.Clients)
		sort.Strings(group.EventIDs)
		result = append(result, *group)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].GatewayIP < result[j].GatewayIP })
	return result, nil
}
