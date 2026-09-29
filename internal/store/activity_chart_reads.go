package store

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// Statistics routes read only published facts. They deliberately align the
// leading edge to a five-minute bucket and use the latest published revision
// for the current bucket; interactive queries never fall back to raw events.
func activityChartFactRowsSQL(query ActivityQuery, window time.Duration, dimensions []string) (string, error) {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("PROXY_SENTINEL_ACTIVITY_READ_MODEL_V3")), "true") {
		return activityChartFactRowsV3SQL(query, window, dimensions)
	}
	to := time.Now().UTC()
	if query.AsOf != "" {
		var err error
		to, err = time.Parse(time.RFC3339Nano, query.AsOf)
		if err != nil {
			return "", err
		}
	}
	from := to.Add(-window)
	stamp := func(t time.Time) string {
		return "parseDateTime64BestEffort(" + chQuote(t.UTC().Format(time.RFC3339Nano)) + ",6)"
	}
	scope := []string{"1"}
	if query.SensorID != "" {
		scope = append(scope, "sensor_id="+chQuote(query.SensorID))
	}
	if query.CampusID != "" {
		scope = append(scope, "campus_id="+chQuote(query.CampusID))
	}
	if len(dimensions) > 0 {
		quoted := []string{}
		for _, dimension := range dimensions {
			quoted = append(quoted, chQuote(dimension))
		}
		scope = append(scope, "dimension IN("+strings.Join(quoted, ",")+")")
	}
	scoped := strings.Join(scope, " AND ")
	starts := []time.Time{}
	ends := []time.Time{}
	widths := []time.Duration{5 * time.Minute, time.Hour, 24 * time.Hour}
	for _, width := range widths {
		start := from.Truncate(width)
		if start.Before(from) {
			start = start.Add(width)
		}
		starts = append(starts, start)
		ends = append(ends, to.Truncate(width))
	}
	tables := []string{"activity_chart_bucket_facts_v2", "activity_chart_hour_facts", "activity_chart_day_facts"}
	pieces := []string{}
	for i, table := range tables {
		where := scoped + " AND event_count>0 AND window_start>=" + stamp(starts[i]) + " AND window_start<" + stamp(ends[i])
		if i+1 < len(tables) {
			where += " AND NOT(window_start>=" + stamp(starts[i+1]) + " AND window_start<" + stamp(ends[i+1]) + ")"
		}
		pieces = append(pieces, "SELECT dimension,value,event_count,first_seen,last_seen FROM "+table+" FINAL WHERE "+where)
	}
	boundary := "timestamp>=" + stamp(from) + " AND timestamp<=" + stamp(to) + " AND NOT(timestamp>=" + stamp(starts[0]) + " AND timestamp<" + stamp(ends[0]) + ")"
	// Dimension predicates apply after array expansion; the sensor/campus filters
	// still prune source features before decoding boundary observations.
	featureScope := strings.ReplaceAll(scoped, "dimension IN(", "t.1 IN(")
	pieces = append(pieces, fmt.Sprintf("SELECT t.1 AS dimension,t.2 AS value,count() AS event_count,min(timestamp) AS first_seen,max(timestamp) AS last_seen FROM(SELECT timestamp,sensor_id,campus_id,arrayJoin(%s) AS t FROM normalized_event_features FINAL WHERE %s) WHERE %s GROUP BY dimension,value", activityChartArray, boundary, featureScope))
	return strings.Join(pieces, " UNION ALL "), nil
}

func activityChartFactRowsV3SQL(query ActivityQuery, window time.Duration, dimensions []string) (string, error) {
	to := time.Now().UTC()
	if query.AsOf != "" {
		var err error
		to, err = time.Parse(time.RFC3339Nano, query.AsOf)
		if err != nil {
			return "", err
		}
	}
	from := to.Add(-window)
	if rawCutover := strings.TrimSpace(os.Getenv("PROXY_SENTINEL_ACTIVITY_V3_CUTOVER")); rawCutover != "" {
		cutover, err := time.Parse(time.RFC3339Nano, rawCutover)
		if err != nil {
			return "", fmt.Errorf("parse PROXY_SENTINEL_ACTIVITY_V3_CUTOVER: %w", err)
		}
		if from.Before(cutover) {
			from = cutover.UTC()
		}
	}
	stamp := func(t time.Time) string {
		return "parseDateTime64BestEffort(" + chQuote(t.UTC().Format(time.RFC3339Nano)) + ",6)"
	}
	ceil := func(t time.Time, width time.Duration) time.Time {
		out := t.Truncate(width)
		if out.Before(t) {
			out = out.Add(width)
		}
		return out
	}
	scope := func(alias string, includeDimension bool) string {
		prefix := ""
		if alias != "" {
			prefix = alias + "."
		}
		parts := []string{"1"}
		if query.SensorID != "" {
			parts = append(parts, prefix+"sensor_id="+chQuote(query.SensorID))
		}
		if query.CampusID != "" {
			parts = append(parts, prefix+"campus_id="+chQuote(query.CampusID))
		}
		if includeDimension && len(dimensions) > 0 {
			quoted := make([]string, 0, len(dimensions))
			for _, dimension := range dimensions {
				quoted = append(quoted, chQuote(dimension))
			}
			parts = append(parts, prefix+"dimension IN("+strings.Join(quoted, ",")+")")
		}
		return strings.Join(parts, " AND ")
	}
	pieces := []string{}
	appendFacts := func(granularity, table string, start, end time.Time) {
		if !start.Before(end) {
			return
		}
		startSQL, endSQL := stamp(start), stamp(end)
		// An explicit tuple IN lets ClickHouse apply the published revision set to
		// the primary key. A JOIN scans every superseded revision in the bucket,
		// which is catastrophic when late traffic repeatedly rebuilds old buckets.
		pieces = append(pieces, fmt.Sprintf(`SELECT f.dimension,f.value,f.event_count,f.first_seen,f.last_seen FROM %s f WHERE f.bucket_start>=%s AND f.bucket_start<%s AND %s AND (f.bucket_start,f.sensor_id,f.campus_id,f.revision) IN(SELECT bucket_start,sensor_id,campus_id,argMax(revision,published_at) revision FROM activity_chart_bucket_versions_v3 WHERE granularity=%s AND bucket_start>=%s AND bucket_start<%s AND %s GROUP BY bucket_start,sensor_id,campus_id)`, table, startSQL, endSQL, scope("f", true), chQuote(granularity), startSQL, endSQL, scope("", false)))
	}
	from5, closed5 := ceil(from, 5*time.Minute), to.Truncate(5*time.Minute)
	current5End := closed5.Add(5 * time.Minute)
	switch {
	case window <= time.Hour:
		appendFacts("5m", "activity_chart_facts_5m_v3", from5, current5End)
	case window <= 7*24*time.Hour:
		fromHour, toHour := ceil(from5, time.Hour), closed5.Truncate(time.Hour)
		appendFacts("5m", "activity_chart_facts_5m_v3", from5, minTime(fromHour, closed5))
		appendFacts("hour", "activity_chart_facts_hour_v3", fromHour, toHour)
		appendFacts("5m", "activity_chart_facts_5m_v3", maxTime(toHour, from5), current5End)
	default:
		fromHour, toHour := ceil(from5, time.Hour), closed5.Truncate(time.Hour)
		fromDay, toDay := ceil(fromHour, 24*time.Hour), toHour.Truncate(24*time.Hour)
		appendFacts("5m", "activity_chart_facts_5m_v3", from5, minTime(fromHour, closed5))
		appendFacts("hour", "activity_chart_facts_hour_v3", fromHour, minTime(fromDay, toHour))
		appendFacts("day", "activity_chart_facts_day_v3", fromDay, toDay)
		appendFacts("hour", "activity_chart_facts_hour_v3", maxTime(toDay, fromHour), toHour)
		appendFacts("5m", "activity_chart_facts_5m_v3", maxTime(toHour, from5), current5End)
	}
	if len(pieces) == 0 {
		return "SELECT '' dimension,'' value,toUInt64(0) event_count,now64(6) first_seen,now64(6) last_seen WHERE 0", nil
	}
	return strings.Join(pieces, " UNION ALL "), nil
}
func activityChartBucketSQL(query ActivityQuery, window time.Duration) (string, error) {
	source, err := activityChartFactRowsSQL(query, window, []string{"type", "protocol", "domain", "http_host", "tls_sni", "user_agent", "tls_fp", "dst_port", "dst_ip", "source_ip"})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`SELECT dimension,value,count,last_seen,
 sum(count) OVER(PARTITION BY dimension) AS total,
 count() OVER(PARTITION BY dimension) AS distinct_values,
 countIf(value!='') OVER(PARTITION BY dimension) AS nonempty_values,
 min(first_seen) OVER(PARTITION BY dimension) AS first_seen,
 max(last_seen) OVER(PARTITION BY dimension) AS latest_seen
 FROM(SELECT dimension,value,sum(event_count) AS count,min(first_seen) AS first_seen,max(last_seen) AS last_seen FROM(%s) GROUP BY dimension,value)
 ORDER BY dimension,count DESC,last_seen DESC,value ASC LIMIT 21 BY dimension
 SETTINGS max_threads=4,max_block_size=8192,max_memory_usage=1073741824,max_bytes_before_external_group_by=268435456,max_execution_time=20 FORMAT JSONEachRow`, source), nil
}

func (s *ClickHouseStore) populateActivityChartBuckets(ctx context.Context, query ActivityQuery, window time.Duration, overview *ActivityOverview) error {
	sql, err := activityChartBucketSQL(query, window)
	if err != nil {
		return err
	}
	data, err := s.query(ctx, sql)
	if err != nil {
		return err
	}
	var rows []struct {
		Dimension      string `json:"dimension"`
		Value          string `json:"value"`
		Count          int    `json:"count"`
		Total          int    `json:"total"`
		DistinctValues int    `json:"distinct_values"`
		NonemptyValues int    `json:"nonempty_values"`
		FirstSeen      string `json:"first_seen"`
		LastSeen       string `json:"last_seen"`
		LatestSeen     string `json:"latest_seen"`
	}
	if err = decodeJSONEachRow(data, &rows); err != nil {
		return err
	}
	targets := map[string]*[]ActivityCount{"type": &overview.EventTypeCounts, "protocol": &overview.ProtocolCounts, "domain": &overview.TopDomains, "http_host": &overview.TopHTTPHosts, "tls_sni": &overview.TopTLSSNI, "user_agent": &overview.TopUserAgents, "tls_fp": &overview.TopTLSFingerprints, "dst_port": &overview.TopDstPorts, "dst_ip": &overview.TopDstIPs, "source_ip": &overview.TopSourceIPs}
	for _, row := range rows {
		switch row.Dimension {
		case "type":
			overview.EventCount = row.Total
			overview.FirstSeen = normalizeClickHouseTimestamp(row.FirstSeen)
			overview.LastSeen = normalizeClickHouseTimestamp(row.LatestSeen)
		case "source_ip":
			overview.ActiveIPCount = row.DistinctValues
		case "domain":
			overview.AccessObjectCount = row.NonemptyValues
		}
		target := targets[row.Dimension]
		if target != nil && len(*target) < 20 && (row.Value != "" || row.Dimension == "type") {
			*target = append(*target, ActivityCount{Value: row.Value, Count: row.Count, LastSeen: normalizeClickHouseTimestamp(row.LastSeen)})
		}
	}
	return nil
}
