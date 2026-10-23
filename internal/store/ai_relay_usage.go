package store

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"proxy-sentinel/internal/airelay"
)

// AIRelayUsage is an IP-level observation, not proof of a model API call.
type AIRelayUsage struct {
	IP          string            `json:"ip"`
	AccountID   string            `json:"account_id,omitempty"`
	FirstSeen   string            `json:"first_seen"`
	LastSeen    string            `json:"last_seen"`
	EventCount  uint64            `json:"event_count"`
	Domains     []string          `json:"domains"`
	DomainNames map[string]string `json:"domain_names"`
	Events      []AIRelayEvent    `json:"events"`
	total       int
}

type AIRelayEvent struct {
	EventID   string `json:"event_id"`
	Timestamp string `json:"timestamp"`
	Domain    string `json:"domain"`
	Source    string `json:"source"`
	SensorID  string `json:"sensor_id"`
}

type AIRelayUsageQuery struct {
	From, To                       time.Time
	IP, Domain, CampusID, SensorID string
	Limit                          int
	Cursor                         string
}

type AIRelayUsagePage struct {
	Items            []AIRelayUsage `json:"items"`
	Page             Page           `json:"page"`
	IndicatorVersion string         `json:"indicator_version"`
}

func relayReadScope(q AIRelayUsageQuery) (string, error) {
	if q.From.IsZero() || q.To.IsZero() || !q.From.Before(q.To) || q.To.Sub(q.From) > 7*24*time.Hour {
		return "", fmt.Errorf("time range must be within 7 days")
	}
	clauses := []string{
		"timestamp >= parseDateTime64BestEffort(" + chQuote(q.From.UTC().Format(time.RFC3339Nano)) + ",6)",
		"timestamp < parseDateTime64BestEffort(" + chQuote(q.To.UTC().Format(time.RFC3339Nano)) + ",6)",
		"subject_ip != ''",
	}
	if q.Cursor != "" {
		if _, err := netip.ParseAddr(q.Cursor); err != nil {
			return "", fmt.Errorf("invalid cursor")
		}
	}
	if q.IP != "" {
		if _, err := netip.ParseAddr(q.IP); err != nil {
			return "", fmt.Errorf("invalid source IP")
		}
		clauses = append(clauses, "subject_ip="+chQuote(q.IP))
	}
	if q.SensorID != "" {
		clauses = append(clauses, "sensor_id="+chQuote(q.SensorID))
	}
	if q.CampusID != "" {
		clauses = append(clauses, "campus_id="+chQuote(q.CampusID))
	}
	return strings.Join(clauses, " AND "), nil
}

func relayMatchSQL(m *airelay.Matcher) string {
	rules := make([]string, 0, m.IndicatorCount())
	for _, rule := range m.Indicators() {
		exact := "domain=" + chQuote(rule.Domain)
		if rule.MatchType == airelay.MatchSubdomain {
			exact = "(" + exact + " OR endsWith(domain," + chQuote("."+rule.Domain) + "))"
		}
		rules = append(rules, exact)
	}
	excluded := make([]string, 0)
	for _, domain := range m.OfficialDomains() {
		excluded = append(excluded, chQuote(domain))
	}
	return "(" + strings.Join(rules, " OR ") + ") AND domain NOT IN (" + strings.Join(excluded, ",") + ")"
}

func relayRowsSQL(q AIRelayUsageQuery, selectedIPs ...string) (string, error) {
	scope, err := relayReadScope(q)
	if err != nil {
		return "", err
	}
	if len(selectedIPs) > 0 {
		quoted := make([]string, 0, len(selectedIPs))
		for _, ip := range selectedIPs {
			if _, err := netip.ParseAddr(ip); err != nil {
				return "", fmt.Errorf("invalid selected source IP")
			}
			quoted = append(quoted, chQuote(ip))
		}
		scope += " AND subject_ip IN (" + strings.Join(quoted, ",") + ")"
	}
	domainFilter := ""
	if q.Domain != "" {
		domainFilter = " AND (domain=" + chQuote(strings.ToLower(strings.TrimSuffix(q.Domain, "."))) + " OR endsWith(domain," + chQuote("."+strings.ToLower(strings.TrimSuffix(q.Domain, "."))) + "))"
	}
	return `SELECT timestamp,event_id,sensor_id,subject_ip AS ip,domain,source FROM ai_relay_domain_matches_v1 WHERE ` + scope + ` AND domain!='' AND ` + relayMatchSQL(airelay.Default()) + domainFilter, nil
}

func decodeAIRelayRows(data []byte, dest any) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 4*1024*1024)
	switch target := dest.(type) {
	case *[]AIRelayUsage:
		for scanner.Scan() {
			var row struct {
				IP         string   `json:"ip"`
				FirstSeen  string   `json:"first_seen"`
				LastSeen   string   `json:"last_seen"`
				EventCount uint64   `json:"event_count"`
				Domains    []string `json:"domains"`
				Total      int      `json:"total"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
				return err
			}
			*target = append(*target, AIRelayUsage{IP: row.IP, FirstSeen: row.FirstSeen, LastSeen: row.LastSeen, EventCount: row.EventCount, Domains: row.Domains, Events: []AIRelayEvent{}, total: row.Total})
		}
	case *[]struct {
		IP string
		AIRelayEvent
	}:
		for scanner.Scan() {
			var row struct {
				IP        string `json:"ip"`
				EventID   string `json:"event_id"`
				Timestamp string `json:"timestamp"`
				Domain    string `json:"domain"`
				Source    string `json:"source"`
				SensorID  string `json:"sensor_id"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
				return err
			}
			*target = append(*target, struct {
				IP string
				AIRelayEvent
			}{row.IP, AIRelayEvent{EventID: row.EventID, Timestamp: row.Timestamp, Domain: row.Domain, Source: row.Source, SensorID: row.SensorID}})
		}
	}
	return scanner.Err()
}

func (s *ClickHouseStore) ListAIRelayUsage(ctx context.Context, q AIRelayUsageQuery) (AIRelayUsagePage, error) {
	if q.Limit < 1 || q.Limit > 50 {
		q.Limit = 20
	}
	rows, err := relayRowsSQL(q)
	if err != nil {
		return AIRelayUsagePage{}, err
	}
	cursorClause := ""
	if q.Cursor != "" {
		cursorClause = " WHERE ip>" + chQuote(q.Cursor)
	}
	sql := fmt.Sprintf(`SELECT * FROM (SELECT *,count() OVER() AS total FROM (SELECT ip,formatDateTime(min(timestamp),'%%Y-%%m-%%dT%%H:%%i:%%S.%%fZ','UTC') AS first_seen,formatDateTime(max(timestamp),'%%Y-%%m-%%dT%%H:%%i:%%S.%%fZ','UTC') AS last_seen,uniqExact(tuple(sensor_id,event_id)) AS event_count,groupUniqArray(domain) AS domains FROM (%s) GROUP BY ip))%s ORDER BY ip LIMIT %d SETTINGS max_threads=2,max_memory_usage=268435456,max_execution_time=30 FORMAT JSONEachRow`, rows, cursorClause, q.Limit+1)
	data, err := s.query(ctx, sql)
	if err != nil {
		return AIRelayUsagePage{}, err
	}
	items := []AIRelayUsage{}
	if err = decodeAIRelayRows(data, &items); err != nil {
		return AIRelayUsagePage{}, err
	}
	total := 0
	if len(items) > 0 {
		total = items[0].total
	} else if q.Cursor != "" {
		countData, e := s.query(ctx, fmt.Sprintf(`SELECT uniqExact(ip) AS total FROM (%s) SETTINGS max_threads=2,max_memory_usage=268435456,max_execution_time=30 FORMAT JSONEachRow`, rows))
		if e != nil {
			return AIRelayUsagePage{}, e
		}
		var countRow struct {
			Total int `json:"total"`
		}
		if e = json.Unmarshal(bytes.TrimSpace(countData), &countRow); e != nil {
			return AIRelayUsagePage{}, e
		}
		total = countRow.Total
	}
	var next *string
	if len(items) > q.Limit {
		items = items[:q.Limit]
		v := items[len(items)-1].IP
		next = &v
	}
	matcher := airelay.Default()
	for i := range items {
		items[i].DomainNames = make(map[string]string, len(items[i].Domains))
		for _, domain := range items[i].Domains {
			if indicator, ok := matcher.Match(domain); ok {
				if indicator.NameZH != "" {
					items[i].DomainNames[domain] = indicator.NameZH
				} else if indicator.Name != "" {
					items[i].DomainNames[domain] = indicator.Name
				}
			}
		}
	}
	if len(items) > 0 {
		ips := make([]string, 0, len(items))
		byIP := map[string]*AIRelayUsage{}
		for i := range items {
			ips = append(ips, items[i].IP)
			byIP[items[i].IP] = &items[i]
		}
		detailRows, e := relayRowsSQL(q, ips...)
		if e != nil {
			return AIRelayUsagePage{}, e
		}
		detailSQL := fmt.Sprintf(`SELECT ip,event_id,formatDateTime(timestamp,'%%Y-%%m-%%dT%%H:%%i:%%S.%%fZ','UTC') AS timestamp,domain,source,sensor_id FROM (SELECT ip,sensor_id,event_id,max(timestamp) AS timestamp,any(domain) AS domain,any(source) AS source FROM (%s) GROUP BY ip,sensor_id,event_id) ORDER BY ip,timestamp DESC,event_id DESC LIMIT 10 BY ip SETTINGS max_threads=2,max_memory_usage=268435456,max_execution_time=20 FORMAT JSONEachRow`, detailRows)
		detailData, e := s.query(ctx, detailSQL)
		if e != nil {
			return AIRelayUsagePage{}, e
		}
		details := []struct {
			IP string
			AIRelayEvent
		}{}
		if e = decodeAIRelayRows(detailData, &details); e != nil {
			return AIRelayUsagePage{}, e
		}
		seen := map[string]bool{}
		for _, d := range details {
			key := d.IP + "\x00" + d.SensorID + "\x00" + d.EventID
			if seen[key] {
				continue
			}
			seen[key] = true
			byIP[d.IP].Events = append(byIP[d.IP].Events, d.AIRelayEvent)
		}
	}
	return AIRelayUsagePage{Items: items, Page: Page{Limit: q.Limit, NextCursor: next, Total: total}, IndicatorVersion: airelay.Default().Version()}, nil
}

func (s *DBStore) ListAIRelayUsage(ctx context.Context, q AIRelayUsageQuery) (AIRelayUsagePage, error) {
	page, err := s.ch.ListAIRelayUsage(ctx, q)
	if err != nil {
		return page, err
	}
	for i := range page.Items {
		item := &page.Items[i]
		if len(item.Events) == 0 {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, item.Events[0].Timestamp)
		if err != nil {
			continue
		}
		item.AccountID, err = s.pg.UniqueAIRelayAccountAt(ctx, item.IP, at)
		if err != nil {
			return AIRelayUsagePage{}, err
		}
	}
	return page, nil
}

func (s *PostgresStore) UniqueAIRelayAccountAt(ctx context.Context, ip string, at time.Time) (string, error) {
	var account string
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(min(account_id),''),count(DISTINCT account_id) FROM account_sessions WHERE ip=$1::inet AND started_at<=$2 AND (ended_at IS NULL OR ended_at>$2) AND account_id<>'' AND identity_confidence>=0.8`, ip, at).Scan(&account, &count)
	if err != nil || count != 1 {
		return "", err
	}
	return account, nil
}

func (s *FileStore) ListAIRelayUsage(ctx context.Context, q AIRelayUsageQuery) (AIRelayUsagePage, error) {
	return AIRelayUsagePage{}, fmt.Errorf("AI relay usage list requires the database event read model")
}
