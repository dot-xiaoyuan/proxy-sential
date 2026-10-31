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

// DiscoveryObservedFlowPorts reads only compact, indexed 10-minute buckets
// for the requested sensor/IP pairs. Results are weak access clues because an
// IP can be shared or reassigned; the caller must not label them open ports.
func (s *ClickHouseStore) DiscoveryObservedFlowPorts(ctx context.Context, targets []string, since time.Time) (map[string][]DiscoveryObservedFlowPort, error) {
	query := discoveryObservedFlowPortsQuery(targets, since)
	if query == "" {
		return map[string][]DiscoveryObservedFlowPort{}, nil
	}
	data, err := s.query(ctx, query)
	if err != nil {
		return nil, err
	}
	out := map[string][]DiscoveryObservedFlowPort{}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	for {
		var row DiscoveryObservedFlowPort
		if err := decoder.Decode(&row); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("decode observed flow port: %w", err)
		}
		if row.SensorID == "" || net.ParseIP(row.SourceIP) == nil || row.DestinationPort <= 0 || row.DestinationPort > 65535 || row.EvidenceID == "" {
			continue
		}
		key := row.SensorID + "|" + row.SourceIP
		if len(out[key]) < 8 {
			out[key] = append(out[key], row)
		}
	}
	return out, nil
}

func discoveryObservedFlowPortsQuery(targets []string, since time.Time) string {
	quotedTargets := make([]string, 0, 50)
	seenTargets := map[string]bool{}
	for _, target := range targets {
		parts := strings.SplitN(target, "|", 2)
		if len(parts) != 2 || parts[0] == "" || len(parts[0]) > 128 || !safeFlowSensor(parts[0]) {
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(parts[1]))
		if ip == nil || seenTargets[parts[0]+"|"+ip.String()] {
			continue
		}
		seenTargets[parts[0]+"|"+ip.String()] = true
		quotedTargets = append(quotedTargets, "('"+parts[0]+"','"+ip.String()+"')")
		if len(quotedTargets) == 50 {
			break
		}
	}
	if len(quotedTargets) == 0 {
		return ""
	}
	if since.IsZero() {
		since = time.Now().UTC().Add(-2 * time.Hour)
	}
	return fmt.Sprintf(`SELECT sensor_id,src_ip,proto,dst_port,
 maxMerge(last_seen) AS last_seen,
 argMaxMerge(evidence_id) AS evidence_id
FROM proxy_sentinel.discovery_observed_flow_ports_10m
WHERE (sensor_id,src_ip) IN (%s)
 AND window_start>=toDateTime('%s','UTC')
GROUP BY sensor_id,src_ip,proto,dst_port
ORDER BY sensor_id,src_ip,last_seen DESC
LIMIT 8 BY sensor_id,src_ip FORMAT JSONEachRow`,
		strings.Join(quotedTargets, ","), since.UTC().Truncate(10*time.Minute).Format("2006-01-02 15:04:05"))
}

func safeFlowSensor(sensor string) bool {
	for _, ch := range sensor {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_' || ch == '.' || ch == ':') {
			return false
		}
	}
	return true
}
