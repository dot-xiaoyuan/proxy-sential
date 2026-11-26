package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"proxy-sentinel/internal/discovery"
)

// MineDiscoveryGaps 在不写入任何业务表的前提下，对 PostgreSQL 和 ClickHouse 执行有界只读采样，
// 输出双列表差异、未识别高频特征 Top-N 和镜像高价值目标端口覆盖，用于指导后续规则与协议优先级。
func (s *DBStore) MineDiscoveryGaps(ctx context.Context, opts discovery.GapMineOptions) (discovery.GapReport, error) {
	opts = discovery.NormalizeGapOptions(opts)
	report := discovery.GapReport{
		SensorID:    opts.SensorID,
		Window:      opts.Window.String(),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}

	windowHours := int(opts.Window.Hours())
	groupHours := 24
	if windowHours > 24 {
		groupHours = 168
	}

	// 1. PostgreSQL: 终端列表与发现列表 MAC 重叠统计
	pgCtx, cancelPG := context.WithTimeout(ctx, 20*time.Second)
	defer cancelPG()
	overlapSQL := `
WITH term AS (
  SELECT DISTINCT lower(primary_mac) AS mac
  FROM endpoint_entities
  WHERE entity_role = 'endpoint'
    AND last_seen >= now() - make_interval(hours => $1)
    AND coalesce(primary_mac, '') <> ''
),
disc AS (
  SELECT DISTINCT lower(mac) AS mac
  FROM discovery_list_group_current
  WHERE hours = $2
    AND coalesce(mac, '') <> ''
)
SELECT
  (SELECT count(*) FROM term),
  (SELECT count(*) FROM disc),
  (SELECT count(*) FROM (SELECT mac FROM term INTERSECT SELECT mac FROM disc) a),
  (SELECT count(*) FROM (SELECT mac FROM term EXCEPT SELECT mac FROM disc) b),
  (SELECT count(*) FROM (SELECT mac FROM disc EXCEPT SELECT mac FROM term) c)`
	if err := s.pg.db.QueryRowContext(pgCtx, overlapSQL, windowHours, groupHours).Scan(
		&report.Overlap.TerminalMACs,
		&report.Overlap.DiscoveryMACs,
		&report.Overlap.OverlapMACs,
		&report.Overlap.TerminalOnlyMACs,
		&report.Overlap.DiscoveryOnlyMACs,
	); err != nil {
		report.Warnings = append(report.Warnings, fmt.Sprintf("PostgreSQL 双表重叠查询失败: %v", err))
	}

	// 1.5 PostgreSQL: 发现列表随机 MAC（LAA，首字节 bit 1 为 1）占比统计
	laaSQL := `
WITH macs AS (
  SELECT DISTINCT lower(mac) AS mac
  FROM discovery_list_group_current
  WHERE hours = $1
    AND mac ~ '^[0-9a-fA-F]{2}:'
)
SELECT
  count(*),
  count(*) FILTER (WHERE ((('x' || substr(mac, 1, 2))::bit(8)::int) & 2) = 2),
  count(*) FILTER (WHERE ((('x' || substr(mac, 1, 2))::bit(8)::int) & 2) = 0)
FROM macs`
	if err := s.pg.db.QueryRowContext(pgCtx, laaSQL, groupHours).Scan(
		&report.RandomMAC.TotalMACs,
		&report.RandomMAC.LocalAdminMACs,
		&report.RandomMAC.GlobalMACs,
	); err != nil {
		report.Warnings = append(report.Warnings, fmt.Sprintf("PostgreSQL 随机 MAC 占比查询失败: %v", err))
	} else if report.RandomMAC.TotalMACs > 0 {
		report.RandomMAC.LocalAdminRatio = float64(report.RandomMAC.LocalAdminMACs) / float64(report.RandomMAC.TotalMACs)
	}

	// 2. PostgreSQL: 硬件投影状态分布
	statusRows, err := s.pg.db.QueryContext(pgCtx, `
SELECT coalesce(hardware_type_status, ''), count(*), count(DISTINCT mac)
FROM passive_hardware_current
WHERE sensor_id = $1 AND last_seen >= now() - make_interval(hours => $2)
GROUP BY 1
ORDER BY 2 DESC`, opts.SensorID, windowHours)
	if err != nil {
		report.Warnings = append(report.Warnings, fmt.Sprintf("PostgreSQL 硬件状态分布查询失败: %v", err))
	} else {
		defer statusRows.Close()
		for statusRows.Next() {
			var item discovery.StatusCount
			if scanErr := statusRows.Scan(&item.Status, &item.Count, &item.MACs); scanErr == nil {
				report.HardwareStatuses = append(report.HardwareStatuses, item)
			}
		}
	}

	// 仅采集非空 ClickHouse 采样（所有查询严格限制单线程、256MB 内存与 20 秒超时）。
	since := time.Now().UTC().Add(-opts.Window).Format(time.RFC3339)
	sinceExpr := "parseDateTime64BestEffort(" + chQuote(since) + ",6)"
	sensorFilter := "sensor_id=" + chQuote(opts.SensorID)
	chSettings := "SETTINGS max_threads=1,max_memory_usage=268435456,max_execution_time=20 FORMAT JSONEachRow"

	// 2.5 ClickHouse: 新增被动协议命中统计（CAPWAP / 大华发现 / IEEE 1905 / SSH Banner）
	newProtoSQL := fmt.Sprintf(`
SELECT
  source_event_type AS category,
  multiIf(
    source_event_type='capwap', coalesce(nullIf(JSONExtractString(payload_json, 'message_type'), ''), nullIf(JSONExtractString(payload_json, 'capwap_message'), ''), 'capwap'),
    source_event_type='dahua_discovery', coalesce(nullIf(JSONExtractString(payload_json, 'model'), ''), nullIf(JSONExtractString(payload_json, 'device_type'), ''), 'dahua'),
    source_event_type='ssh_banner', coalesce(nullIf(JSONExtractString(payload_json, 'server'), ''), 'ssh'),
    source_event_type
  ) AS value,
  multiIf(
    source_event_type='capwap', coalesce(nullIf(JSONExtractString(payload_json, 'model'), ''), JSONExtractString(payload_json, 'manufacturer')),
    source_event_type='dahua_discovery', JSONExtractString(payload_json, 'manufacturer'),
    source_event_type='ssh_banner', JSONExtractString(payload_json, 'software'),
    ''
  ) AS detail,
  uniq(if(subject_mac <> '', lower(subject_mac), subject_ip)) AS entities,
  count() AS events
FROM passive_discovery_events_v2
PREWHERE %s AND source_event_type IN ('capwap','dahua_discovery','ieee1905','ieee1905_client','ssh_banner') AND timestamp >= %s
GROUP BY category, value, detail
ORDER BY entities DESC, events DESC
LIMIT %d %s`, sensorFilter, sinceExpr, opts.Top, chSettings)
	if items, qErr := s.queryFeatureGaps(ctx, newProtoSQL); qErr != nil {
		report.Warnings = append(report.Warnings, fmt.Sprintf("ClickHouse 新增被动协议命中统计失败: %v", qErr))
	} else {
		report.NewProtocolHits = items
	}

	// 3. ClickHouse: 高频 DHCP Vendor Class / Option 55 组合
	dhcpSQL := fmt.Sprintf(`
SELECT
  'dhcp' AS category,
  JSONExtractString(payload_json, 'vendor_class') AS value,
  JSONExtractString(payload_json, 'requested_options') AS detail,
  uniq(lower(subject_mac)) AS entities,
  count() AS events
FROM passive_discovery_events_v2
PREWHERE %s AND source_event_type='dhcp' AND timestamp >= %s
WHERE (value <> '' OR detail <> '')
GROUP BY value, detail
ORDER BY entities DESC, events DESC
LIMIT %d %s`, sensorFilter, sinceExpr, opts.Top, chSettings)
	if items, qErr := s.queryFeatureGaps(ctx, dhcpSQL); qErr != nil {
		report.Warnings = append(report.Warnings, fmt.Sprintf("ClickHouse DHCP 特征挖掘失败: %v", qErr))
	} else {
		report.UnmatchedDHCP = items
	}

	// 4. ClickHouse: 高频 HTTP 设备与客户端特征（UA / Server / Title）
	httpSQL := fmt.Sprintf(`
SELECT
  if(JSONExtractString(payload_json, 'user_agent') <> '', 'http_ua', if(JSONExtractString(payload_json, 'server') <> '', 'http_server', 'http_title')) AS category,
  coalesce(nullIf(JSONExtractString(payload_json, 'user_agent'), ''), nullIf(JSONExtractString(payload_json, 'server'), ''), JSONExtractString(payload_json, 'title')) AS value,
  JSONExtractString(payload_json, 'title') AS detail,
  uniq(subject_ip) AS entities,
  count() AS events
FROM passive_discovery_events_v2
PREWHERE %s AND source_event_type='http-device' AND timestamp >= %s
WHERE value <> ''
GROUP BY category, value, detail
ORDER BY entities DESC, events DESC
LIMIT %d %s`, sensorFilter, sinceExpr, opts.Top, chSettings)
	if items, qErr := s.queryFeatureGaps(ctx, httpSQL); qErr != nil {
		report.Warnings = append(report.Warnings, fmt.Sprintf("ClickHouse HTTP 特征挖掘失败: %v", qErr))
	} else {
		report.HTTPDeviceAgents = items
	}

	// 5. ClickHouse: 高频设备协议响应特征（SNMP / mDNS / SSDP / WS-Discovery / SIP）
	protoSQL := fmt.Sprintf(`
SELECT
  source_event_type AS category,
  multiIf(
    source_event_type='snmp', coalesce(nullIf(JSONExtractString(payload_json, 'system_description'), ''), JSONExtractString(payload_json, 'system_object_id')),
    source_event_type='mdns', coalesce(nullIf(JSONExtractString(payload_json, 'service_type'), ''), JSONExtractString(payload_json, 'query')),
    source_event_type='ssdp', coalesce(nullIf(JSONExtractString(payload_json, 'server'), ''), JSONExtractString(payload_json, 'st')),
    source_event_type='ws_discovery', coalesce(nullIf(JSONExtractString(payload_json, 'types'), ''), JSONExtractString(payload_json, 'scopes')),
    source_event_type='sip', coalesce(nullIf(JSONExtractString(payload_json, 'user_agent'), ''), JSONExtractString(payload_json, 'server')),
    ''
  ) AS value,
  multiIf(
    source_event_type='snmp', JSONExtractString(payload_json, 'system_object_id'),
    source_event_type='ssdp', JSONExtractString(payload_json, 'st'),
    ''
  ) AS detail,
  uniq(subject_ip) AS entities,
  count() AS events
FROM passive_discovery_events_v2
PREWHERE %s AND source_event_type IN ('snmp','mdns','ssdp','ws_discovery','sip') AND timestamp >= %s
WHERE value <> ''
GROUP BY category, value, detail
ORDER BY entities DESC, events DESC
LIMIT %d %s`, sensorFilter, sinceExpr, opts.Top, chSettings)
	if items, qErr := s.queryFeatureGaps(ctx, protoSQL); qErr != nil {
		report.Warnings = append(report.Warnings, fmt.Sprintf("ClickHouse 设备协议特征挖掘失败: %v", qErr))
	} else {
		report.UnconfirmedProtocols = items
	}

	// 6. ClickHouse: 镜像高价值目标端口覆盖
	portSQL := fmt.Sprintf(`
SELECT
  proto,
  dst_port AS port,
  uniq(src_ip) AS source_ips,
  count() AS buckets
FROM discovery_observed_flow_ports_10m
PREWHERE %s AND window_start >= toDateTime(%s)
WHERE dst_port IN (22, 23, 53, 80, 123, 137, 139, 161, 443, 445, 502, 515, 554, 631, 1900, 3389, 3702, 5060, 5246, 5247, 5353, 8000, 9100, 37020, 37777, 37810, 47808)
GROUP BY proto, dst_port
ORDER BY source_ips DESC, buckets DESC
LIMIT %d %s`, sensorFilter, sinceExpr, opts.Top, chSettings)
	if raw, qErr := s.ch.query(ctx, portSQL); qErr != nil {
		report.Warnings = append(report.Warnings, fmt.Sprintf("ClickHouse 目标端口统计失败: %v", qErr))
	} else {
		rows := []struct {
			Proto     string `json:"proto"`
			Port      uint32 `json:"port"`
			SourceIPs int64  `json:"source_ips"`
			Buckets   int64  `json:"buckets"`
		}{}
		if decErr := decodeJSONEachRow(raw, &rows); decErr != nil {
			report.Warnings = append(report.Warnings, fmt.Sprintf("ClickHouse 目标端口解析失败: %v", decErr))
		} else {
			for _, row := range rows {
				report.MirrorPorts = append(report.MirrorPorts, discovery.PortGapItem{
					Proto:      row.Proto,
					Port:       row.Port,
					Annotation: discovery.CampusPortAnnotation(row.Proto, row.Port),
					SourceIPs:  row.SourceIPs,
					Buckets:    row.Buckets,
				})
			}
		}
	}

	// 7. ClickHouse: 高频 TLS SNI 域名
	sniSQL := fmt.Sprintf(`
SELECT
  'sni' AS category,
  lower(coalesce(nullIf(JSONExtractString(payload_json, 'server_name'), ''), JSONExtractString(payload_json, 'sni'))) AS value,
  '' AS detail,
  uniq(subject_ip) AS entities,
  count() AS events
FROM passive_discovery_events_v2
PREWHERE %s AND source_event_type IN ('ssl','tls') AND timestamp >= %s
WHERE value <> ''
GROUP BY value
ORDER BY entities DESC, events DESC
LIMIT %d %s`, sensorFilter, sinceExpr, opts.Top, chSettings)
	if items, qErr := s.queryFeatureGaps(ctx, sniSQL); qErr != nil {
		report.Warnings = append(report.Warnings, fmt.Sprintf("ClickHouse SNI 特征挖掘失败: %v", qErr))
	} else {
		report.TopSNIDomains = items
	}

	return report, nil
}

func (s *DBStore) queryFeatureGaps(ctx context.Context, query string) ([]discovery.FeatureGapItem, error) {
	raw, err := s.ch.query(ctx, query)
	if err != nil {
		return nil, err
	}
	rows := []discovery.FeatureGapItem{}
	if err := decodeJSONEachRow(raw, &rows); err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i].Value = strings.TrimSpace(rows[i].Value)
		rows[i].Detail = strings.TrimSpace(rows[i].Detail)
	}
	return rows, nil
}
