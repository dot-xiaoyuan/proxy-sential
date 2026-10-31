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
		if !requested[key] || row.Port <= 0 || row.Port > 65535 || row.EvidenceID == "" {
			continue
		}
		out[key] = append(out[key], row)
	}
	return out, nil
}

func discoveryServiceCluesQuery(targets []string, since time.Time) (string, map[string]bool) {
	quotedSensors, quotedMACs := []string{}, []string{}
	seenSensors, seenMACs, requested := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, target := range targets {
		parts := strings.SplitN(target, "|", 2)
		if len(parts) != 2 || parts[0] == "" || len(parts[0]) > 128 || !safeFlowSensor(parts[0]) {
			continue
		}
		mac, err := net.ParseMAC(parts[1])
		if err != nil || len(mac) != 6 {
			continue
		}
		macText := mac.String()
		key := parts[0] + "|" + macText
		if requested[key] {
			continue
		}
		requested[key] = true
		if !seenSensors[parts[0]] {
			seenSensors[parts[0]] = true
			quotedSensors = append(quotedSensors, "'"+parts[0]+"'")
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
	sql := fmt.Sprintf(`SELECT sensor_id,
 lower(JSONExtractString(payload_json,'ethernet_source_mac')) AS mac,
 JSONExtractString(payload_json,'service_type') AS service_type,
 JSONExtractString(payload_json,'service_instance') AS service_name,
 JSONExtractString(payload_json,'service_target') AS service_target,
 JSONExtractInt(payload_json,'service_port') AS port,
 max(timestamp) AS last_seen,
 argMax(event_id,timestamp) AS evidence_id
FROM proxy_sentinel.normalized_events
WHERE timestamp >= toDateTime64('%s',6,'UTC')
 AND sensor_id IN (%s)
 AND lower(JSONExtractString(payload_json,'ethernet_source_mac')) IN (%s)
 AND JSONHas(payload_json,'service_port')
GROUP BY sensor_id,mac,service_type,service_name,service_target,port
ORDER BY last_seen DESC LIMIT 1000 FORMAT JSONEachRow`, since.UTC().Format("2006-01-02 15:04:05"), strings.Join(quotedSensors, ","), strings.Join(quotedMACs, ","))
	return sql, requested
}
