package store

import (
	"context"
	"fmt"
)

type ActivityReportQuery struct {
	ActivityQuery
	Dimension string
	Limit     int
}

type ActivityReportItem struct {
	Key      string  `json:"key"`
	Label    string  `json:"label"`
	Count    int     `json:"count"`
	Share    float64 `json:"share"`
	LastSeen string  `json:"last_seen,omitempty"`
}

type ActivityReport struct {
	Dimension       string               `json:"dimension"`
	Total           int                  `json:"total"`
	ClassifiedCount int                  `json:"classified_count"`
	UnknownCount    int                  `json:"unknown_count"`
	Items           []ActivityReportItem `json:"items"`
}

type ActivityReportReader interface {
	GetActivityReport(ctx context.Context, query ActivityReportQuery) (ActivityReport, error)
}

func (s *DBStore) GetActivityReport(ctx context.Context, query ActivityReportQuery) (ActivityReport, error) {
	return s.ch.QueryActivityReport(ctx, query)
}

func (s *ClickHouseStore) QueryActivityReport(ctx context.Context, query ActivityReportQuery) (ActivityReport, error) {
	result := ActivityReport{Dimension: query.Dimension, Items: []ActivityReportItem{}}
	if query.Limit <= 0 || query.Limit > 50 {
		query.Limit = 10
	}
	_, duration, err := NormalizeActivityWindow(query.Window)
	if err != nil {
		return result, err
	}
	if query.Dimension == "ecosystem" {
		where := fmt.Sprintf("observed_at>=now()-INTERVAL %d SECOND", int(duration.Seconds()))
		if query.SensorID != "" {
			where += " AND sensor_id=" + chQuote(query.SensorID)
		}
		if query.CampusID != "" {
			where += " AND campus_id=" + chQuote(query.CampusID)
		}
		return s.queryActivityReport(ctx, query, `ecosystem`, "domain_ecosystem_observations FINAL", where)
	}
	where, err := activityWhereSQL(query.SensorID, query.CampusID, query.AsOf, duration)
	if err != nil {
		return result, err
	}
	value, eventFilter, ok := reportDimensionExpression(query.Dimension)
	if !ok {
		return result, fmt.Errorf("unsupported report dimension %q", query.Dimension)
	}
	if eventFilter != "" {
		where += " AND " + eventFilter
	}
	return s.queryActivityReport(ctx, query, value, "normalized_events", where)
}

func (s *ClickHouseStore) queryActivityReport(ctx context.Context, query ActivityReportQuery, value, table, where string) (ActivityReport, error) {
	sql := fmt.Sprintf(`SELECT value AS key,value AS label,count() AS count,sum(count()) OVER () AS total_count,sum(countIf(value='未知')) OVER () AS unknown_count,toString(max(observed)) AS last_seen FROM (SELECT if(trim(toString(%s))='','未知',trim(toString(%s))) AS value,%s AS observed FROM %s PREWHERE %s) GROUP BY value ORDER BY count DESC,value LIMIT %d FORMAT JSONEachRow`, value, value, reportTimestamp(table), table, where, query.Limit)
	data, err := s.activityFeatureQuery(ctx, sql)
	if err != nil {
		return ActivityReport{}, err
	}
	var rows []struct {
		Key          string `json:"key"`
		Label        string `json:"label"`
		Count        int    `json:"count"`
		TotalCount   int    `json:"total_count"`
		UnknownCount int    `json:"unknown_count"`
		LastSeen     string `json:"last_seen"`
	}
	if err := decodeJSONEachRow(data, &rows); err != nil {
		return ActivityReport{}, err
	}
	result := ActivityReport{Dimension: query.Dimension, Items: make([]ActivityReportItem, 0, len(rows))}
	if len(rows) > 0 {
		result.Total = rows[0].TotalCount
		result.UnknownCount = rows[0].UnknownCount
		result.ClassifiedCount = result.Total - result.UnknownCount
	}
	for _, row := range rows {
		share := 0.0
		if result.Total > 0 {
			share = float64(row.Count) / float64(result.Total)
		}
		result.Items = append(result.Items, ActivityReportItem{Key: row.Key, Label: row.Label, Count: row.Count, Share: share, LastSeen: clickHouseTimeRFC3339(row.LastSeen)})
	}
	return result, nil
}

func reportTimestamp(table string) string {
	if table == "normalized_events" {
		return "timestamp"
	}
	return "observed_at"
}

func reportDimensionExpression(dimension string) (string, string, bool) {
	switch dimension {
	case "application":
		return `JSONExtractString(flow_json,'app_protocol')`, "", true
	case "domain":
		return `multiIf(type='dns',JSONExtractString(payload_json,'query'),type='http',JSONExtractString(payload_json,'host'),type IN ('tls','quic'),JSONExtractString(payload_json,'sni'),'')`, "type IN ('dns','http','tls','quic')", true
	case "http_host":
		return `JSONExtractString(payload_json,'host')`, "type='http'", true
	case "tls_sni":
		return `JSONExtractString(payload_json,'sni')`, "type='tls'", true
	case "quic_sni":
		return `JSONExtractString(payload_json,'sni')`, "type='quic'", true
	case "protocol":
		return `upper(proto)`, "", true
	case "dst_port":
		return `if(dst_port=0,'',toString(dst_port))`, "", true
	case "src_ip":
		return `subject_ip`, "", true
	case "dst_ip":
		return `dst_ip`, "", true
	case "user_agent":
		return `JSONExtractString(payload_json,'user_agent')`, "type='http'", true
	default:
		return "", "", false
	}
}

func ValidActivityReportDimension(dimension string) bool {
	if dimension == "ecosystem" {
		return true
	}
	_, _, ok := reportDimensionExpression(dimension)
	return ok
}
