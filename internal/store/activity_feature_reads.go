package store

import (
	"context"
	"regexp"
	"strings"
)

var activityPayloadField = regexp.MustCompile(`JSONExtractString\(\s*payload_json,\s*'([^']+)'\s*\)`)
var activityFlowField = regexp.MustCompile(`JSONExtractString\(\s*flow_json,\s*'app_protocol'\s*\)`)
var activityTTLField = regexp.MustCompile(`JSONExtractInt\(\s*flow_json,\s*'ttl'\s*\)`)

func activityFeatureSQL(sql string) string {
	if !strings.Contains(sql, "normalized_events") {
		return sql
	}
	fields := map[string]string{"query": "dns_query", "host": "http_host", "sni": "sni", "user_agent": "user_agent", "ja3": "ja3", "ja4": "ja4"}
	translated := activityPayloadField.ReplaceAllStringFunc(sql, func(expression string) string {
		match := activityPayloadField.FindStringSubmatch(expression)
		if field := fields[match[1]]; field != "" {
			return field
		}
		return expression
	})
	translated = activityFlowField.ReplaceAllString(translated, "app_protocol")
	translated = activityTTLField.ReplaceAllString(translated, "ttl")
	for _, raw := range []string{"payload_json", "flow_json", "observer_json", "raw_ref_json"} {
		if strings.Contains(translated, raw) {
			return sql
		}
	}
	return strings.ReplaceAll(translated, "normalized_events", "normalized_event_features FINAL")
}

func (s *ClickHouseStore) activityFeatureQuery(ctx context.Context, sql string) ([]byte, error) {
	sql = activityFeatureSQL(sql)
	if !strings.Contains(sql, " SETTINGS ") {
		sql = strings.ReplaceAll(sql, "FORMAT JSONEachRow", "SETTINGS max_threads=1,max_block_size=8192,max_memory_usage=268435456,max_execution_time=20 FORMAT JSONEachRow")
	}
	return s.query(ctx, sql)
}
