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

// QueryDPIOverview keeps the overview bounded by aggregating the complete
// window in ClickHouse. It deliberately does not use ListEventSamples: a cold
// dashboard request must not transfer tens of thousands of event rows to Go.
func (s *ClickHouseStore) QueryDPIOverview(ctx context.Context, query ActivityQuery) (DPIOverview, error) {
	window, duration, err := NormalizeActivityWindow(query.Window)
	if err != nil {
		return DPIOverview{}, err
	}
	where, err := activityWhereSQL(query.SensorID, query.CampusID, query.AsOf, duration)
	if err != nil {
		return DPIOverview{}, err
	}
	protocol := `multiIf(type='dns','DNS',type='http','HTTP',type='tls','TLS',type='quic','QUIC',type='flow' AND proto!='',upper(proto),upper(type))`
	data, err := s.query(ctx, fmt.Sprintf(`SELECT count() AS event_count, uniqExactIf(subject_ip,subject_ip!='') AS active_ip_count, uniqExactIf(%s,%s!='') AS protocol_flow_count, minOrNull(timestamp) AS first_seen, maxOrNull(timestamp) AS last_seen FROM normalized_events PREWHERE %s FORMAT JSONEachRow`, protocol, protocol, where))
	if err != nil {
		return DPIOverview{}, err
	}
	var summary []struct {
		EventCount        int     `json:"event_count"`
		ActiveIPCount     int     `json:"active_ip_count"`
		ProtocolFlowCount int     `json:"protocol_flow_count"`
		FirstSeen         *string `json:"first_seen"`
		LastSeen          *string `json:"last_seen"`
	}
	if err := decodeJSONEachRow(data, &summary); err != nil {
		return DPIOverview{}, err
	}
	result := DPIOverview{SensorID: query.SensorID, Window: window}
	if len(summary) > 0 {
		result.EventCount = summary[0].EventCount
		result.FlowSampleCount = summary[0].EventCount
		result.ActiveIPCount = summary[0].ActiveIPCount
		result.ProtocolFlowCount = summary[0].ProtocolFlowCount
		if summary[0].FirstSeen != nil {
			result.FirstSeen = normalizeClickHouseTimestamp(*summary[0].FirstSeen)
		}
		if summary[0].LastSeen != nil {
			result.LastSeen = normalizeClickHouseTimestamp(*summary[0].LastSeen)
		}
	}
	conflictSQL := fmt.Sprintf(`SELECT sum(toUInt8(length(ja3s)+length(ja4s)>1)+toUInt8(length(ttls)>1)) AS count FROM (SELECT groupUniqArrayIf(8)(JSONExtractString(payload_json,'ja3'),JSONExtractString(payload_json,'ja3')!='') AS ja3s, groupUniqArrayIf(8)(JSONExtractString(payload_json,'ja4'),JSONExtractString(payload_json,'ja4')!='') AS ja4s, groupUniqArrayIf(8)(toString(JSONExtractInt(flow_json,'ttl')),JSONExtractInt(flow_json,'ttl')>0) AS ttls FROM normalized_events PREWHERE %s AND subject_ip!='' GROUP BY subject_ip) FORMAT JSONEachRow`, where)
	data, err = s.query(ctx, conflictSQL)
	if err != nil {
		return DPIOverview{}, err
	}
	result.FingerprintConflictCount, err = decodeSingleCount(data)
	return result, err
}

// QueryDPITrends performs bounded aggregation inside ClickHouse so the control
// plane never pulls a 100k event sample into memory for a chart.
func (s *ClickHouseStore) QueryDPITrends(ctx context.Context, query ActivityQuery, risks map[string]risk.Snapshot) ([]DPITrendPoint, error) {
	window, duration, err := NormalizeActivityWindow(query.Window)
	if err != nil {
		return nil, err
	}
	where, err := activityWhereSQL(query.SensorID, query.CampusID, query.AsOf, duration)
	if err != nil {
		return nil, err
	}
	bucket := "toStartOfMinute(timestamp)"
	seconds := 60.0
	if window == "24h" || window == "7d" {
		bucket = "toStartOfHour(timestamp)"
		seconds = 3600
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
	sql := fmt.Sprintf(`SELECT toString(%s) AS bucket, count() AS event_count, uniqExact(subject_ip) AS active_devices, %s AS risk_ips FROM normalized_events PREWHERE %s GROUP BY bucket ORDER BY bucket FORMAT JSONEachRow`, bucket, riskExpression, where)
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
	where, err := activityWhereSQL(query.SensorID, query.CampusID, query.AsOf, duration)
	if err != nil {
		return nil, err
	}
	protocol := `multiIf(type='dns','DNS',type='http','HTTP',type='tls','TLS',type='quic','QUIC',type='flow' AND proto!='',upper(proto),upper(type))`
	target := `multiIf(type='dns',JSONExtractString(payload_json,'query'),type='http',JSONExtractString(payload_json,'host'),type='tls',JSONExtractString(payload_json,'sni'),dst_ip)`
	sql := fmt.Sprintf(`SELECT protocol, sum(target_count) AS event_count, arrayMap(item -> item.1, arraySlice(arrayReverseSort(item -> item.2, groupArray((target,target_count))),1,6)) AS top_apps FROM (SELECT %s AS protocol, %s AS target, count() AS target_count FROM normalized_events PREWHERE %s GROUP BY protocol,target HAVING protocol!='') GROUP BY protocol ORDER BY event_count DESC,protocol LIMIT 50 FORMAT JSONEachRow`, protocol, target, where)
	data, err := s.query(ctx, sql)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Protocol   string   `json:"protocol"`
		EventCount int      `json:"event_count"`
		TopApps    []string `json:"top_apps"`
	}
	if err := decodeJSONEachRow(data, &rows); err != nil {
		return nil, err
	}
	total := 0
	for _, row := range rows {
		total += row.EventCount
	}
	items := make([]DPIProtocolFlow, 0, len(rows))
	for _, row := range rows {
		share := 0.0
		if total > 0 {
			share = float64(row.EventCount) * 100 / float64(total)
		}
		items = append(items, DPIProtocolFlow{Protocol: row.Protocol, AppProtocol: row.Protocol, Category: dpiCategory(row.Protocol), SharePercent: share, EventCount: row.EventCount, TopApps: row.TopApps, TopTargets: row.TopApps})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].EventCount > items[j].EventCount })
	return items, nil
}

func (s *ClickHouseStore) QueryDPIFingerprintConflicts(ctx context.Context, query ActivityQuery, risks map[string]risk.Snapshot) ([]DPIFingerprintConflict, error) {
	_, duration, err := NormalizeActivityWindow(query.Window)
	if err != nil {
		return nil, err
	}
	where, err := activityWhereSQL(query.SensorID, query.CampusID, query.AsOf, duration)
	if err != nil {
		return nil, err
	}
	sql := fmt.Sprintf(`SELECT subject_ip AS ip, groupUniqArrayIf(8)(concat('ja3:',JSONExtractString(payload_json,'ja3')),JSONExtractString(payload_json,'ja3')!='') AS ja3s, groupUniqArrayIf(8)(concat('ja4:',JSONExtractString(payload_json,'ja4')),JSONExtractString(payload_json,'ja4')!='') AS ja4s, groupUniqArrayIf(8)(toString(JSONExtractInt(flow_json,'ttl')),JSONExtractInt(flow_json,'ttl')>0) AS ttls, toString(max(timestamp)) AS last_seen FROM normalized_events PREWHERE %s AND subject_ip != '' GROUP BY ip HAVING length(ja3s)+length(ja4s)>1 OR length(ttls)>1 ORDER BY last_seen DESC LIMIT 200 FORMAT JSONEachRow`, where)
	data, err := s.query(ctx, sql)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		IP       string   `json:"ip"`
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
		}{{"ja3_mismatch", "TLS 客户端栈差异", append(row.JA3s, row.JA4s...)}, {"ttl_step", "网络栈 TTL 差异", row.TTLs}}
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
			items = append(items, DPIFingerprintConflict{ID: "dpi-conflict-" + shortHash(set.kind+"|"+row.IP+"|"+row.LastSeen), IP: row.IP, ConflictType: set.kind, TypeLabel: set.label, RiskLevel: level, Confidence: confidence, SampleCount: len(set.values), Scope: "ip_window", SignalTypes: []string{set.kind}, Assessment: "needs_corroboration", DetectedSamples: set.values, Reason: fmt.Sprintf("%s 在同一观测窗口内出现 %d 组网络客户端栈样本，需要结合身份会话、MAC 或 DHCP 证据复核", row.IP, len(set.values)), LastSeen: clickHouseTimeRFC3339(row.LastSeen)})
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
