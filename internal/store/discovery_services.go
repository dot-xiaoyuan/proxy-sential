package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// DiscoveryServiceClues returns DNS-SD/SSDP service announcements observed for
// the given MAC addresses. The evidence already exists in normalized_events;
// this read is intentionally MAC-scoped and time-bounded so a device list does
// not scan the whole event table.
func (s *ClickHouseStore) DiscoveryServiceClues(ctx context.Context, macs []string, since time.Time) (map[string][]DiscoveryServiceClue, error) {
	normalized := make([]string, 0, len(macs))
	seen := map[string]bool{}
	for _, mac := range macs {
		mac = strings.ToLower(strings.TrimSpace(mac))
		if mac == "" || seen[mac] {
			continue
		}
		if len(mac) > 64 || strings.ContainsAny(mac, "'\\") {
			continue
		}
		seen[mac] = true
		normalized = append(normalized, mac)
	}
	if len(normalized) == 0 {
		return map[string][]DiscoveryServiceClue{}, nil
	}
	if since.IsZero() {
		since = time.Now().UTC().Add(-24 * time.Hour)
	}
	quoted := make([]string, 0, len(normalized))
	for _, mac := range normalized {
		quoted = append(quoted, "'"+mac+"'")
	}
	sql := fmt.Sprintf(`SELECT
 JSONExtractString(payload_json,'ethernet_source_mac') AS mac,
 JSONExtractString(payload_json,'service_type') AS service_type,
 JSONExtractString(payload_json,'service_instance') AS service_name,
 JSONExtractString(payload_json,'service_target') AS service_target,
 JSONExtractInt(payload_json,'service_port') AS port,
 count() AS observations,
 max(timestamp) AS last_seen
FROM proxy_sentinel.normalized_events
WHERE timestamp >= toDateTime64('%s',6,'UTC')
 AND lower(JSONExtractString(payload_json,'ethernet_source_mac')) IN (%s)
 AND JSONHas(payload_json,'service_port')
GROUP BY mac,service_type,service_name,service_target,port
ORDER BY observations DESC LIMIT 1000 FORMAT JSONEachRow`, since.UTC().Format("2006-01-02 15:04:05"), strings.Join(quoted, ","))
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
		if row.MAC == "" || row.Port <= 0 {
			continue
		}
		out[row.MAC] = append(out[row.MAC], row)
	}
	return out, nil
}
