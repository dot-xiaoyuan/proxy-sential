package store

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"proxy-sentinel/internal/risk"
)

// QueryDPITrends performs bounded aggregation inside ClickHouse so the control
// plane never pulls a 100k event sample into memory for a chart.
func (s *ClickHouseStore) QueryDPITrends(ctx context.Context, query ActivityQuery, risks map[string]risk.Snapshot) ([]DPITrendPoint, error) {
	window, duration, err := NormalizeActivityWindow(query.Window)
	if err != nil {
		return nil, err
	}
	intervalValue, intervalUnit := clickHouseInterval(duration)
	bucket := "toStartOfMinute(timestamp)"
	seconds := 60.0
	if window == "24h" || window == "7d" {
		bucket = "toStartOfHour(timestamp)"
		seconds = 3600
	}
	clauses := []string{fmt.Sprintf("timestamp >= now() - INTERVAL %d %s", intervalValue, intervalUnit)}
	if query.SensorID != "" {
		clauses = append(clauses, "sensor_id = "+chQuote(query.SensorID))
	}
	riskIPs := make([]string, 0)
	for ip, snapshot := range risks {
		if snapshot.Level != "" && snapshot.Level != "normal" {
			riskIPs = append(riskIPs, chQuote(ip))
		}
	}
	riskExpression := "0"
	if len(riskIPs) > 0 {
		riskExpression = "uniqExactIf(subject_ip, subject_ip IN (" + strings.Join(riskIPs, ",") + "))"
	}
	sql := fmt.Sprintf(`SELECT toString(%s) AS bucket, count() AS event_count, uniqExact(subject_ip) AS active_devices, %s AS risk_ips FROM normalized_events PREWHERE %s GROUP BY bucket ORDER BY bucket FORMAT JSONEachRow`, bucket, riskExpression, strings.Join(clauses, " AND "))
	data, err := s.query(ctx, sql)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Bucket        string `json:"bucket"`
		EventCount    int    `json:"event_count"`
		ActiveDevices int    `json:"active_devices"`
		RiskIPs       int    `json:"risk_ips"`
	}
	if err := decodeJSONEachRow(data, &rows); err != nil {
		return nil, err
	}
	items := make([]DPITrendPoint, 0, len(rows))
	for _, row := range rows {
		items = append(items, DPITrendPoint{Time: clickHouseTimeRFC3339(row.Bucket), ActiveDevices: row.ActiveDevices, RiskIPs: row.RiskIPs, EventCount: row.EventCount, CPS: float64(row.EventCount) / seconds, Estimated: true})
	}
	return items, nil
}

func (s *ClickHouseStore) QueryDPIProtocolFlows(ctx context.Context, query ActivityQuery) ([]DPIProtocolFlow, error) {
	_, duration, err := NormalizeActivityWindow(query.Window)
	if err != nil {
		return nil, err
	}
	intervalValue, intervalUnit := clickHouseInterval(duration)
	clauses := []string{fmt.Sprintf("timestamp >= now() - INTERVAL %d %s", intervalValue, intervalUnit)}
	if query.SensorID != "" {
		clauses = append(clauses, "sensor_id = "+chQuote(query.SensorID))
	}
	protocol := `multiIf(type='dns','DNS',type='http','HTTP',type='tls','TLS',type='quic','QUIC',type='flow' AND proto!='',upper(proto),upper(type))`
	target := `multiIf(type='dns',JSONExtractString(payload_json,'query'),type='http',JSONExtractString(payload_json,'host'),type='tls',JSONExtractString(payload_json,'sni'),dst_ip)`
	sql := fmt.Sprintf(`SELECT %s AS protocol, %s AS target, count() AS event_count FROM normalized_events PREWHERE %s GROUP BY protocol,target HAVING protocol != '' ORDER BY event_count DESC LIMIT 500 FORMAT JSONEachRow`, protocol, target, strings.Join(clauses, " AND "))
	data, err := s.query(ctx, sql)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Protocol   string `json:"protocol"`
		Target     string `json:"target"`
		EventCount int    `json:"event_count"`
	}
	if err := decodeJSONEachRow(data, &rows); err != nil {
		return nil, err
	}
	total := 0
	buckets := map[string]*struct {
		count int
		apps  map[string]int
	}{}
	for _, row := range rows {
		total += row.EventCount
		bucket := buckets[row.Protocol]
		if bucket == nil {
			bucket = &struct {
				count int
				apps  map[string]int
			}{apps: map[string]int{}}
			buckets[row.Protocol] = bucket
		}
		bucket.count += row.EventCount
		if row.Target != "" {
			bucket.apps[row.Target] += row.EventCount
		}
	}
	items := make([]DPIProtocolFlow, 0, len(buckets))
	for protocol, bucket := range buckets {
		share := 0.0
		if total > 0 {
			share = float64(bucket.count) * 100 / float64(total)
		}
		items = append(items, DPIProtocolFlow{Protocol: protocol, AppProtocol: protocol, Category: dpiCategory(protocol), SharePercent: share, EventCount: bucket.count, TopApps: topStringCounts(bucket.apps, 6)})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].EventCount > items[j].EventCount })
	return items, nil
}

func (s *ClickHouseStore) QueryDPIFingerprintConflicts(ctx context.Context, query ActivityQuery, risks map[string]risk.Snapshot) ([]DPIFingerprintConflict, error) {
	_, duration, err := NormalizeActivityWindow(query.Window)
	if err != nil {
		return nil, err
	}
	intervalValue, intervalUnit := clickHouseInterval(duration)
	clauses := []string{fmt.Sprintf("timestamp >= now() - INTERVAL %d %s", intervalValue, intervalUnit), "subject_ip != ''"}
	if query.SensorID != "" {
		clauses = append(clauses, "sensor_id = "+chQuote(query.SensorID))
	}
	sql := fmt.Sprintf(`SELECT subject_ip AS ip, groupUniqArrayIf(8)(JSONExtractString(payload_json,'user_agent'),JSONExtractString(payload_json,'user_agent')!='') AS uas, groupUniqArrayIf(8)(concat('ja3:',JSONExtractString(payload_json,'ja3')),JSONExtractString(payload_json,'ja3')!='') AS ja3s, groupUniqArrayIf(8)(concat('ja4:',JSONExtractString(payload_json,'ja4')),JSONExtractString(payload_json,'ja4')!='') AS ja4s, groupUniqArrayIf(8)(toString(JSONExtractInt(flow_json,'ttl')),JSONExtractInt(flow_json,'ttl')>0) AS ttls, toString(max(timestamp)) AS last_seen FROM normalized_events PREWHERE %s GROUP BY ip HAVING length(uas)>1 OR length(ja3s)+length(ja4s)>1 OR length(ttls)>1 ORDER BY last_seen DESC LIMIT 200 FORMAT JSONEachRow`, strings.Join(clauses, " AND "))
	data, err := s.query(ctx, sql)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		IP       string   `json:"ip"`
		UAs      []string `json:"uas"`
		JA3s     []string `json:"ja3s"`
		JA4s     []string `json:"ja4s"`
		TTLs     []string `json:"ttls"`
		LastSeen string   `json:"last_seen"`
	}
	if err := decodeJSONEachRow(data, &rows); err != nil {
		return nil, err
	}
	items := []DPIFingerprintConflict{}
	for _, row := range rows {
		sets := []struct {
			kind, label string
			values      []string
		}{{"ua_conflict", "UA 客户端碰撞", row.UAs}, {"ja3_mismatch", "JA3 / JA4 栈错配", append(row.JA3s, row.JA4s...)}, {"ttl_step", "TTL 步进差异", row.TTLs}}
		for _, set := range sets {
			if len(set.values) < 2 {
				continue
			}
			snapshot := risks[row.IP]
			level := snapshot.Level
			if level == "" {
				level = "normal"
			}
			confidence := 0.55 + float64(len(set.values))*0.08
			if confidence > 0.95 {
				confidence = 0.95
			}
			items = append(items, DPIFingerprintConflict{ID: "dpi-conflict-" + shortHash(set.kind+"|"+row.IP+"|"+row.LastSeen), IP: row.IP, ConflictType: set.kind, TypeLabel: set.label, RiskLevel: level, Confidence: confidence, DeviceCount: len(set.values), DetectedSamples: set.values, Reason: fmt.Sprintf("%s 在同一观测窗口内出现 %d 组不同标准化指纹特征", row.IP, len(set.values)), LastSeen: clickHouseTimeRFC3339(row.LastSeen)})
		}
	}
	return items, nil
}

func decodeJSONEachRow[T any](data []byte, target *[]T) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		var item T
		if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
			return err
		}
		*target = append(*target, item)
	}
	return scanner.Err()
}

func clickHouseTimeRFC3339(value string) string { return strings.Replace(value, " ", "T", 1) + "Z" }
