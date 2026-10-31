package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strings"
	"time"
)

// PassiveClientClue belongs to a sensor/IP at observation time. An IP can be
// reused or shared, so it remains a weak clue until a device binding is
// checked independently. JA3/JA4 are shown as fingerprints, not OS labels.
type PassiveClientClue struct {
	Kind       string `json:"kind"`
	Value      string `json:"value"`
	ObservedAt string `json:"observed_at"`
	EvidenceID string `json:"evidence_id,omitempty"`
}

const passiveClientSignalsSQL = `SELECT f.sensor_id,host(f.ip),f.kind,left(f.value,256),f.last_seen,
       coalesce(f.event_ids_sample->>0,'')
FROM unnest(string_to_array($1,',')::inet[]) AS requested(ip)
CROSS JOIN unnest(string_to_array($2,',')) AS sensors(sensor_id)
JOIN LATERAL (
 SELECT f.sensor_id,f.ip,f.kind,f.value,f.last_seen,f.event_ids_sample
 FROM device_signal_facts f
 WHERE f.sensor_id=sensors.sensor_id AND f.ip=requested.ip
   AND f.kind IN ('user_agent','ja3','ja4')
   AND f.last_seen>=now()-interval '24 hours'
 ORDER BY f.last_seen DESC,f.signal_id LIMIT 12
) f ON true`

func readPassiveClientSignals(ctx context.Context, db *sql.DB, ips, sensors []string) ([]PassiveSignal, error) {
	if len(ips) == 0 || len(sensors) == 0 {
		return nil, nil
	}
	validIPs := make([]string, 0, len(ips))
	for _, ip := range ips {
		if parsed := net.ParseIP(ip); parsed != nil {
			validIPs = append(validIPs, parsed.String())
		}
	}
	if len(validIPs) == 0 {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, passiveClientSignalsSQL, strings.Join(validIPs, ","), strings.Join(sensors, ","))
	if err != nil {
		return nil, fmt.Errorf("read passive client clues: %w", err)
	}
	defer rows.Close()
	items := []PassiveSignal{}
	for rows.Next() {
		var signal PassiveSignal
		var clue PassiveClientClue
		var observed time.Time
		if err := rows.Scan(&signal.SensorID, &signal.IP, &clue.Kind, &clue.Value, &observed, &clue.EvidenceID); err != nil {
			return nil, err
		}
		clue.ObservedAt = observed.UTC().Format(time.RFC3339)
		clue.Value = strings.TrimSpace(clue.Value)
		if clue.Value == "" {
			continue
		}
		signal.ClientClues = []PassiveClientClue{clue}
		if clue.Kind == "user_agent" {
			if family := passiveUserAgentOSFamily(clue.Value); family != "" {
				signal.OSFamily = family
				signal.OSConfidence = "weak"
				signal.OSEvidence = "HTTP User-Agent（IP 线索）: " + clue.Value
			}
		}
		items = append(items, signal)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func passiveUserAgentOSFamily(raw string) string {
	ua := strings.ToLower(raw)
	switch {
	case strings.Contains(ua, "android"):
		return "Android"
	case strings.Contains(ua, "iphone os") || strings.Contains(ua, "ipad; cpu os"):
		return "iOS"
	case strings.Contains(ua, "windows nt"):
		return "Windows"
	case strings.Contains(ua, "macintosh;") && strings.Contains(ua, "mac os x"):
		return "macOS"
	case strings.Contains(ua, "x11; linux"):
		return "Linux"
	default:
		return ""
	}
}
