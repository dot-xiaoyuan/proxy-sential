package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	passiveUserAgentInterval = 5 * time.Minute
	passiveUserAgentWindow   = 15 * time.Minute
	passiveUserAgentMaxIPs   = 2000
	passiveUserAgentMaxBytes = 512
)

// runPassiveUserAgentWorker attributes the most frequent browser user agent of
// each device IP (captured HTTP) back to its MAC entity, so the recognition
// engine can use the device's own self-reported client. It stays bounded: a
// short window, one representative agent per IP, and only entities that have no
// user agent yet. The entity trigger then marks recognition dirty.
func (s *DBStore) runPassiveUserAgentWorker(ctx context.Context) {
	for ctx.Err() == nil {
		work, cancel := context.WithTimeout(ctx, 60*time.Second)
		updated, err := s.attributePassiveUserAgents(work)
		cancel()
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "passive user agent attribution: %v\n", err)
		}
		delay := passiveUserAgentInterval
		if updated > 0 {
			delay = 30 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func (s *DBStore) attributePassiveUserAgents(ctx context.Context) (int, error) {
	if s.ch == nil || s.pg == nil || s.pg.db == nil {
		return 0, nil
	}
	until := time.Now().UTC()
	since := until.Add(-passiveUserAgentWindow)
	// Only explicit client browser tokens carry a device class. The most
	// frequent agent on a Windows host is usually a system component (NCSI,
	// CryptoAPI), so prefer any browser agent over the raw dominant one.
	query := fmt.Sprintf(`SELECT subject_ip,ua FROM (
 SELECT subject_ip,JSONExtractString(payload_json,'user_agent') AS ua,count() AS n FROM normalized_events
 WHERE type='http' AND timestamp>=parseDateTime64BestEffort('%s',3) AND timestamp<parseDateTime64BestEffort('%s',3)
 AND (JSONExtractString(payload_json,'user_agent') ILIKE '%%iphone%%' OR JSONExtractString(payload_json,'user_agent') ILIKE '%%ipad%%'
   OR JSONExtractString(payload_json,'user_agent') ILIKE '%%macintosh%%' OR JSONExtractString(payload_json,'user_agent') ILIKE '%%windows nt%%'
   OR JSONExtractString(payload_json,'user_agent') ILIKE '%%android%%')
 GROUP BY subject_ip,ua
) WHERE ua<>'' ORDER BY subject_ip,n DESC LIMIT 1 BY subject_ip LIMIT %d FORMAT JSONEachRow`,
		since.Format(time.RFC3339Nano), until.Format(time.RFC3339Nano), passiveUserAgentMaxIPs)
	data, err := s.ch.query(ctx, query)
	if err != nil {
		return 0, err
	}
	type attributed struct {
		IP string `json:"subject_ip"`
		UA string `json:"ua"`
	}
	rows := []attributed{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var row attributed
		if err = json.Unmarshal([]byte(line), &row); err != nil {
			return 0, err
		}
		if row.IP != "" && row.UA != "" {
			rows = append(rows, row)
		}
	}
	if len(rows) == 0 {
		return 0, nil
	}
	ips := make([]string, 0, len(rows))
	byIP := map[string]string{}
	for _, row := range rows {
		ips = append(ips, row.IP)
		byIP[row.IP] = row.UA
	}
	macRows, err := s.pg.db.QueryContext(ctx, `SELECT DISTINCT ON (data->>'ip') data->>'ip',lower(data->>'mac')
 FROM discovery_observation_latest
 WHERE data->>'ip'=ANY($1::text[]) AND coalesce(data->>'mac','')<>'' AND observed_at>=now()-interval '30 minutes'
 ORDER BY data->>'ip',observed_at DESC`, ips)
	if err != nil {
		return 0, err
	}
	defer macRows.Close()
	ids := []string{}
	agents := []string{}
	seen := map[string]bool{}
	for macRows.Next() {
		var ip, mac string
		if err = macRows.Scan(&ip, &mac); err != nil {
			return 0, err
		}
		ua := strings.TrimSpace(byIP[ip])
		if mac == "" || ua == "" {
			continue
		}
		if len(ua) > passiveUserAgentMaxBytes {
			ua = ua[:passiveUserAgentMaxBytes]
		}
		endpoint := "mac:" + strings.ToLower(mac)
		if seen[endpoint] {
			continue
		}
		seen[endpoint] = true
		ids = append(ids, endpoint)
		agents = append(agents, ua)
	}
	if err = macRows.Err(); err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	result, err := s.pg.db.ExecContext(ctx, `UPDATE endpoint_entities e
 SET attributes=coalesce(e.attributes,'{}'::jsonb)||jsonb_build_object('user_agent',v.ua),updated_at=now()
 FROM (SELECT * FROM unnest($1::text[],$2::text[]) AS t(endpoint_id,ua)) v
 WHERE e.endpoint_id=v.endpoint_id`, ids, agents)
	if err != nil {
		return 0, err
	}
	affected, _ := result.RowsAffected()
	return int(affected), nil
}
