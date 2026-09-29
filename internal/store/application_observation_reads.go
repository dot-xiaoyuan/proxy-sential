package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"proxy-sentinel/internal/appdomain"
)

func applicationObservationCountsSQL(q appdomain.Query) string {
	return applicationObservationFactsSQL(q, false)
}

// Pagination needs two scalar aggregates, not classification groups, labels or
// terminal sets. Exact boundary rows are counted directly after canonical FINAL.
func applicationObservationPageCountsSQL(q appdomain.Query) string {
	return applicationObservationFactsSQL(q, true)
}

func applicationObservationFactsSQL(q appdomain.Query, pageCounts bool) string {
	stamp := func(t time.Time) string {
		return "parseDateTime64BestEffort(" + chQuote(t.UTC().Format(time.RFC3339Nano)) + ",9)"
	}
	scope := []string{"1"}
	for _, f := range []struct{ k, v string }{{"sensor_id", q.SensorID}, {"campus_id", q.CampusID}, {"ip", q.IP}} {
		if f.v != "" {
			scope = append(scope, f.k+"="+chQuote(f.v))
		}
	}
	if pageCounts && q.ApplicationID != "" {
		scope = append(scope, "target_type='application' AND target_id="+chQuote(q.ApplicationID))
	}
	scoped := strings.Join(scope, " AND ")
	first := q.From.Truncate(5 * time.Minute)
	if first.Before(q.From) {
		first = first.Add(5 * time.Minute)
	}
	last := q.To.Truncate(5 * time.Minute)
	boundary := "timestamp>=" + stamp(q.From) + " AND timestamp<" + stamp(q.To)
	if q.IP == "" && first.Before(last) {
		boundary += " AND (timestamp<" + stamp(first) + " OR timestamp>=" + stamp(last) + ")"
	}
	raw := `SELECT bundle_version,event_type,target_type,target_id,toUInt8(domain!='' AND target_id='') AS unknown_domain,toUInt8(event_type!='dns' AND connection_id='') AS missing_connection,count() AS event_count,argMax(application_latest_observations.name,timestamp) AS name,argMax(application_latest_observations.category,timestamp) AS category,max(timestamp) AS last_seen,groupUniqArrayIf(tuple(campus_id,ip),ip!='') AS terminals FROM application_latest_observations FINAL WHERE ` + boundary + " AND " + scoped + ` GROUP BY bundle_version,event_type,target_type,target_id,unknown_domain,missing_connection`
	if pageCounts {
		raw = "SELECT count() AS event_count,maxOrNull(timestamp) AS last_seen FROM application_latest_observations FINAL WHERE " + boundary + " AND " + scoped
	}
	if q.IP != "" {
		return raw
	}
	columns := "bundle_version,event_type,target_type,target_id,unknown_domain,missing_connection,event_count,name,category,last_seen,terminals"
	if pageCounts {
		columns = "event_count,last_seen"
	}
	fullBounds := func(width time.Duration) (time.Time, time.Time) {
		start := q.From.Truncate(width)
		if start.Before(q.From) {
			start = start.Add(width)
		}
		return start, q.To.Truncate(width)
	}
	dayFrom, dayTo := fullBounds(24 * time.Hour)
	hourFrom, hourTo := fullBounds(time.Hour)
	inRange := func(start, end time.Time) string {
		return "(window_start>=" + stamp(start) + " AND window_start<" + stamp(end) + ")"
	}
	parts := []string{}
	for _, tier := range []struct {
		table    string
		from, to time.Time
		exclude  string
	}{
		{"application_observation_day_facts", dayFrom, dayTo, ""},
		{"application_observation_hour_facts", hourFrom, hourTo, " AND NOT " + inRange(dayFrom, dayTo)},
		{"application_observation_bucket_facts_v2", first, last, " AND NOT " + inRange(hourFrom, hourTo)},
	} {
		parts = append(parts, "SELECT "+columns+" FROM "+tier.table+" FINAL WHERE "+inRange(tier.from, tier.to)+tier.exclude+" AND event_count>0 AND "+scoped)
	}
	return strings.Join(parts, " UNION ALL ") + " UNION ALL " + raw
}

func (d *applicationDB) observationModelTimestamp(ctx context.Context) (time.Time, error) {
	if d.syncConnectionReadModel {
		if err := d.store.DrainApplicationObservationReadModel(ctx); err != nil {
			return time.Time{}, err
		}
	}
	var at time.Time
	if err := d.store.pg.db.QueryRowContext(ctx, `SELECT updated_at FROM application_observation_read_model_cursor_v2 WHERE id=1`).Scan(&at); err != nil {
		return at, fmt.Errorf("observation statistics are not ready: %w", err)
	}
	return at, nil
}
