package store

import (
	"context"
	"fmt"
	"strings"
	"time"
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
	if !ValidActivityReportDimension(query.Dimension) {
		return result, fmt.Errorf("unsupported report dimension %q", query.Dimension)
	}
	available, start, end, err := s.activityRollupAvailable(ctx, query, duration)
	if err != nil {
		return result, err
	}
	if available {
		rollup, rollupErr := s.queryActivityReportHybrid(ctx, query, start, end)
		if rollupErr == nil && rollup.Total > 0 {
			return rollup, nil
		}
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
	return s.queryActivityReport(ctx, query, value, "normalized_events_canonical FINAL", where)
}

func (s *ClickHouseStore) queryActivityReport(ctx context.Context, query ActivityReportQuery, value, table, where string) (ActivityReport, error) {
	sql := fmt.Sprintf(`SELECT value AS key,value AS label,count() AS count,sum(count()) OVER () AS total_count,sum(countIf(value='未知')) OVER () AS unknown_count,toString(max(observed)) AS last_seen FROM (SELECT if(trim(toString(%s))='','未知',trim(toString(%s))) AS value,%s AS observed FROM %s PREWHERE %s) GROUP BY value ORDER BY count DESC,value LIMIT %d FORMAT JSONEachRow`, value, value, reportTimestamp(table), table, where, query.Limit)
	if table == "activity_rollup_10m" {
		sql = fmt.Sprintf(`SELECT value AS key,value AS label,sum(event_count) AS count,sum(sum(event_count)) OVER () AS total_count,sum(sumIf(event_count,value='未知')) OVER () AS unknown_count,toString(max(last_seen)) AS last_seen FROM activity_rollup_10m WHERE %s GROUP BY value ORDER BY count DESC,value LIMIT %d FORMAT JSONEachRow`, where, query.Limit)
	}
	return s.queryActivityReportSQL(ctx, query.Dimension, sql)
}

func (s *ClickHouseStore) queryActivityReportSQL(ctx context.Context, dimension, sql string) (ActivityReport, error) {
	data, err := s.query(ctx, sql)
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
	result := ActivityReport{Dimension: dimension, Items: make([]ActivityReportItem, 0, len(rows))}
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

func (s *ClickHouseStore) activityRollupAvailable(ctx context.Context, query ActivityReportQuery, duration time.Duration) (bool, time.Time, time.Time, error) {
	end := time.Now().UTC()
	if query.AsOf != "" {
		parsed, err := time.Parse(time.RFC3339, query.AsOf)
		if err != nil {
			return false, time.Time{}, time.Time{}, err
		}
		end = parsed.UTC()
	}
	start := end.Add(-duration)
	zone, _ := time.LoadLocation("Asia/Shanghai")
	first, last := start.In(zone), end.In(zone)
	days := []string{}
	for day := time.Date(first.Year(), first.Month(), first.Day(), 0, 0, 0, 0, zone); !day.After(last); day = day.AddDate(0, 0, 1) {
		days = append(days, chQuote(day.Format("2006-01-02")))
	}
	data, err := s.query(ctx, "SELECT count() AS count FROM activity_rollup_refreshes FINAL WHERE date IN ("+strings.Join(days, ",")+") FORMAT JSONEachRow")
	if err != nil {
		return false, start, end, nil
	}
	count, err := decodeSingleCount(data)
	if err != nil {
		return false, start, end, err
	}
	if count != len(days) {
		return false, start, end, nil
	}
	rollupWhere := "dimension=" + chQuote(query.Dimension) + " AND bucket>=" + chQuote(start.In(zone).Format("2006-01-02 15:04:05")) + " AND bucket<" + chQuote(end.In(zone).Format("2006-01-02 15:04:05"))
	if query.SensorID != "" {
		rollupWhere += " AND sensor_id=" + chQuote(query.SensorID)
	}
	if query.CampusID != "" {
		rollupWhere += " AND campus_id=" + chQuote(query.CampusID)
	}
	data, err = s.query(ctx, "SELECT count() AS count FROM activity_rollup_10m WHERE "+rollupWhere+" FORMAT JSONEachRow")
	if err != nil {
		return false, start, end, nil
	}
	count, err = decodeSingleCount(data)
	if err != nil {
		return false, start, end, err
	}
	return count > 0, start, end, nil
}

func (s *ClickHouseStore) queryActivityReportHybrid(ctx context.Context, query ActivityReportQuery, start, end time.Time) (ActivityReport, error) {
	value, filter, ok := reportDimensionExpression(query.Dimension)
	if !ok {
		return ActivityReport{}, fmt.Errorf("unsupported report dimension %q", query.Dimension)
	}
	ceilStart := start.Truncate(10 * time.Minute)
	if ceilStart.Before(start) {
		ceilStart = ceilStart.Add(10 * time.Minute)
	}
	floorEnd := end.Truncate(10 * time.Minute)
	quoteTime := func(t time.Time) string {
		return "parseDateTime64BestEffort(" + chQuote(t.Format(time.RFC3339Nano)) + ",6,'UTC')"
	}
	rollupFilter := "dimension=" + chQuote(query.Dimension) + " AND bucket>=" + quoteTime(ceilStart) + " AND bucket<" + quoteTime(floorEnd)
	rawFilter := ""
	if query.SensorID != "" {
		rollupFilter += " AND sensor_id=" + chQuote(query.SensorID)
		rawFilter += " AND sensor_id=" + chQuote(query.SensorID)
	}
	if query.CampusID != "" {
		rollupFilter += " AND campus_id=" + chQuote(query.CampusID)
		rawFilter += " AND campus_id=" + chQuote(query.CampusID)
	}
	if filter != "" {
		rawFilter += " AND " + filter
	}
	normalized := "if(trim(toString(" + value + "))='','未知',trim(toString(" + value + ")))"
	rawPart := func(from, to time.Time, includeEnd bool) string {
		operator := "<"
		if includeEnd {
			operator = "<="
		}
		return "SELECT " + normalized + " AS value,count() AS weight,max(timestamp) AS last_seen FROM normalized_events_canonical FINAL WHERE timestamp>=" + quoteTime(from) + " AND timestamp" + operator + quoteTime(to) + rawFilter + " GROUP BY value"
	}
	sql := fmt.Sprintf(`SELECT value AS key,value AS label,sum(weight) AS count,sum(sum(weight)) OVER () AS total_count,sum(sumIf(weight,value='未知')) OVER () AS unknown_count,toString(max(last_seen)) AS last_seen FROM (
SELECT value,event_count AS weight,last_seen FROM activity_rollup_10m WHERE %s
UNION ALL %s
UNION ALL %s
) GROUP BY value ORDER BY count DESC,value LIMIT %d FORMAT JSONEachRow`, rollupFilter, rawPart(start, ceilStart, false), rawPart(floorEnd, end, true), query.Limit)
	return s.queryActivityReportSQL(ctx, query.Dimension, sql)
}

func activityRollupWhereSQL(query ActivityReportQuery, duration time.Duration) (string, error) {
	anchor := "now64(6)"
	if query.AsOf != "" {
		parsed, err := time.Parse(time.RFC3339, query.AsOf)
		if err != nil {
			return "", err
		}
		anchor = "parseDateTime64BestEffort(" + chQuote(parsed.UTC().Format(time.RFC3339Nano)) + ",6,'UTC')"
	}
	where := fmt.Sprintf("dimension=%s AND bucket>=%s-INTERVAL %d SECOND AND bucket<%s", chQuote(query.Dimension), anchor, int(duration.Seconds()), anchor)
	if query.SensorID != "" {
		where += " AND sensor_id=" + chQuote(query.SensorID)
	}
	if query.CampusID != "" {
		where += " AND campus_id=" + chQuote(query.CampusID)
	}
	return where, nil
}

func reportTimestamp(table string) string {
	if strings.HasPrefix(table, "normalized_events") {
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
