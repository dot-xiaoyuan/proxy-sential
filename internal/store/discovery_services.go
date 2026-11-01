package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// DiscoveryServiceClues returns mirror-observed DNS-SD/SSDP announcements for
// requested sensor/MAC pairs. A port announcement is not a probe result.
func (s *ClickHouseStore) DiscoveryServiceClues(ctx context.Context, targets []string, since time.Time) (map[string][]DiscoveryServiceClue, error) {
	sql, requested := discoveryServiceCluesQuery(targets, since)
	if sql == "" {
		return map[string][]DiscoveryServiceClue{}, nil
	}
	data, err := s.query(ctx, sql)
	if err != nil {
		return nil, err
	}
	out := map[string][]DiscoveryServiceClue{}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	for {
		var row DiscoveryServiceClue
		if err := decoder.Decode(&row); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("decode service clue: %w", err)
		}
		row.MAC = strings.ToLower(strings.TrimSpace(row.MAC))
		key := row.SensorID + "|" + row.MAC
		if !requested[key+"|"+row.SourceIP] || row.Port <= 0 || row.Port > 65535 || row.EvidenceID == "" {
			continue
		}
		out[key] = append(out[key], row)
	}
	return out, nil
}

func discoveryServiceCluesQuery(targets []string, since time.Time) (string, map[string]bool) {
	quotedAddresses, quotedMACs := []string{}, []string{}
	seenAddresses, seenMACs, requested := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, target := range targets {
		parts := strings.SplitN(target, "|", 3)
		if len(parts) != 3 || parts[0] == "" || len(parts[0]) > 128 || !safeFlowSensor(parts[0]) {
			continue
		}
		mac, err := net.ParseMAC(parts[1])
		if err != nil || len(mac) != 6 {
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(parts[2]))
		if ip == nil {
			continue
		}
		macText := mac.String()
		key := parts[0] + "|" + macText + "|" + ip.String()
		if requested[key] {
			continue
		}
		requested[key] = true
		address := "('" + parts[0] + "','" + ip.String() + "')"
		if !seenAddresses[address] {
			seenAddresses[address] = true
			quotedAddresses = append(quotedAddresses, address)
		}
		if !seenMACs[macText] {
			seenMACs[macText] = true
			quotedMACs = append(quotedMACs, "'"+macText+"'")
		}
		if len(requested) == 50 {
			break
		}
	}
	if len(requested) == 0 {
		return "", requested
	}
	if since.IsZero() {
		since = time.Now().UTC().Add(-2 * time.Hour)
	}
	// Filter the event type before reading payload_json for the selected devices.
	sql := fmt.Sprintf(`SELECT sensor_id,
 lower(JSONExtractString(payload_json,'ethernet_source_mac')) AS mac,
 subject_ip AS source_ip,
 JSONExtractString(payload_json,'service_type') AS service_type,
 JSONExtractString(payload_json,'service_instance') AS service_name,
 JSONExtractString(payload_json,'service_target') AS service_target,
 JSONExtractInt(payload_json,'service_port') AS port,
 max(timestamp) AS last_seen,
 argMax(event_id,timestamp) AS evidence_id
FROM proxy_sentinel.normalized_events
PREWHERE timestamp >= toDateTime64('%s',6,'UTC')
 AND (sensor_id,subject_ip) IN (%s)
 AND source_event_type='dns_sd'
WHERE lower(JSONExtractString(payload_json,'ethernet_source_mac')) IN (%s)
 AND JSONHas(payload_json,'service_port')
GROUP BY sensor_id,mac,source_ip,service_type,service_name,service_target,port
ORDER BY last_seen DESC LIMIT 1000 FORMAT JSONEachRow`, since.UTC().Format("2006-01-02 15:04:05"), strings.Join(quotedAddresses, ","), strings.Join(quotedMACs, ","))
	return sql, requested
}
