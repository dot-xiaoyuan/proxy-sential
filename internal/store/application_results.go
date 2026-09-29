package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxy-sentinel/internal/appdomain"
)

type applicationDB struct {
	store                   *DBStore
	queryMillis             atomic.Int64
	queryOnce               sync.Once
	querySlots              chan struct{}
	syncConnectionReadModel bool
}

func (s *DBStore) ApplicationBackend() appdomain.DatabaseBackend { return &applicationDB{store: s} }

// FINAL resolves every version even before background merges. The read model
// orders by immutable standard-event timestamp/key and encodes revision plus
// lower-batch tie precedence without an HTTP-time argMax over retained history.
func appLatest(q appdomain.Query, columns ...string) string {
	return appLatestFrom(q, time.Now().UTC().Add(-7*24*time.Hour), columns...)
}
func appLatestWindow(q appdomain.Query, columns ...string) string {
	return appLatestFrom(q, q.From, columns...)
}
func appLatestFrom(q appdomain.Query, from time.Time, columns ...string) string {
	fields := append([]string{"sensor_id", "event_id", "timestamp", "campus_id", "ip"}, columns...)
	where := "timestamp >= parseDateTime64BestEffort(" + chQuote(from.Format(time.RFC3339Nano)) + ",9) AND timestamp < parseDateTime64BestEffort(" + chQuote(q.To.Format(time.RFC3339Nano)) + ",9)"
	if q.SensorID != "" {
		where += " AND sensor_id=" + chQuote(q.SensorID)
	}
	return "WITH latest AS (SELECT " + strings.Join(fields, ",") + " FROM application_latest_observations FINAL WHERE " + where + ")"
}
func appActive(q appdomain.Query) string {
	w := "timestamp >= parseDateTime64BestEffort(" + chQuote(q.From.Format(time.RFC3339Nano)) + ",9)"
	for _, f := range []struct{ k, v string }{{"sensor_id", q.SensorID}, {"campus_id", q.CampusID}, {"ip", q.IP}} {
		if f.v != "" {
			w += " AND " + f.k + "=" + chQuote(f.v)
		}
	}
	return w
}
func appCTE(q appdomain.Query) string {
	from := "parseDateTime64BestEffort(" + chQuote(q.From.Format(time.RFC3339Nano)) + ",9)"
	to := "parseDateTime64BestEffort(" + chQuote(q.To.Format(time.RFC3339Nano)) + ",9)"
	retained := "now64(9)-INTERVAL 7 DAY"
	whole := "first_seen>=" + from + " AND first_seen>=" + retained + " AND last_seen<" + to
	scope := "last_seen>=" + from + " AND first_seen<" + to
	for _, f := range []struct{ k, v string }{{"sensor_id", q.SensorID}, {"campus_id", q.CampusID}} {
		if f.v != "" {
			scope += " AND " + f.k + "=" + chQuote(f.v)
		}
	}
	if q.IP != "" {
		// The selected IP may have an earlier last observation than the connection.
		whole = "0"
		scope += " AND arrayExists(t->t.2=" + chQuote(q.IP) + ",summary_terminals)"
	}
	active := "o.1>=" + from
	if q.IP != "" {
		active += " AND o.2=" + chQuote(q.IP)
	}
	fast := "SELECT sensor_id,campus_id,connection_id,summary_apps AS apps,summary_upload AS up,summary_download AS down,summary_terminals AS terminals,last_seen,summary_label AS label FROM application_connection_summaries_v2 FINAL WHERE " + scope + " AND (" + whole + ")"
	// The canonical summary key identifies a connection exactly once. Filter
	// crossing connections before loading event arrays; whole connections read
	// only scalar summaries, without regrouping their repeated bucket copies.
	crossingKeys := "SELECT sensor_id,campus_id,connection_id FROM application_connection_summaries_v2 FINAL WHERE " + scope + " AND NOT (" + whole + ")"
	arrays := "SELECT sensor_id,campus_id,connection_id,arrayFilter(o->o.1>=" + retained + " AND o.1<" + to + ",events) AS history,arrayFilter(o->" + active + ",history) AS observed FROM application_connection_summaries_v2 FINAL WHERE (sensor_id,campus_id,connection_id) IN (" + crossingKeys + ")"
	return "WITH connection_arrays AS (" + arrays + "), connections AS (" + fast +
		" UNION ALL SELECT sensor_id,campus_id,connection_id,arrayDistinct(arrayMap(o->o.3,arrayFilter(o->o.4='application',history))) AS apps,arrayReduce('max',arrayMap(o->o.7,history)) AS up,arrayReduce('max',arrayMap(o->o.8,history)) AS down,arrayDistinct(arrayMap(o->tuple(campus_id,o.2),arrayFilter(o->o.2!='',observed))) AS terminals,arrayMax(arrayMap(o->o.1,observed)) AS last_seen,tuple(arraySort(o->tuple(o.1,o.9),arrayFilter(o->o.4='application',history))[-1].5,arraySort(o->tuple(o.1,o.9),arrayFilter(o->o.4='application',history))[-1].6) AS label FROM connection_arrays WHERE length(observed)>0) "

}

const appQuerySettings = " SETTINGS max_threads=2,max_block_size=8192,max_memory_usage=536870912,max_bytes_before_external_group_by=268435456,max_execution_time=20,output_format_json_quote_64bit_integers=0 FORMAT JSONEachRow"

func (d *applicationDB) Report(ctx context.Context, q appdomain.Query) (appdomain.Report, error) {
	if d.syncConnectionReadModel {
		if err := d.store.DrainApplicationConnectionReadModel(ctx); err != nil {
			return appdomain.Report{}, err
		}
	}
	started := time.Now()
	defer func() { d.queryMillis.Store(time.Since(started).Milliseconds()) }()
	r := appdomain.Report{Items: []appdomain.Item{}, Versions: map[string]int{}, TrafficBasis: "仅汇总已被特征库识别的应用连接累计字节；未分类域名保留在观测统计中，不进入连接流量合计"}
	var modelAsOf time.Time
	if err := d.store.pg.db.QueryRowContext(ctx, `SELECT updated_at FROM application_connection_read_model_v2_cursor WHERE id=1`).Scan(&modelAsOf); err != nil {
		return r, fmt.Errorf("connection read model is not ready: %w", err)
	}
	observationAsOf, err := d.observationModelTimestamp(ctx)
	if err != nil {
		return r, err
	}
	if observationAsOf.Before(modelAsOf) {
		modelAsOf = observationAsOf
	}
	r.AsOf = modelAsOf.UTC().Format(time.RFC3339Nano)
	sql := "SELECT bundle_version,sum(event_count) AS count,sumIf(event_count,event_type='dns') AS dns,sumIf(event_count,unknown_domain=1) AS unknown,sumIf(event_count,missing_connection=1) AS missing FROM (" + applicationObservationCountsSQL(q) + ") GROUP BY bundle_version" + appQuerySettings
	queryCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type versionResult struct {
		raw []byte
		err error
	}
	versionDone := make(chan versionResult, 1)
	versionSQL := sql
	go func() {
		raw, err := d.readQuery(queryCtx, versionSQL)
		versionDone <- versionResult{raw: raw, err: err}
	}()

	sql = appCTE(q) + ", observation_counts AS (" + applicationObservationCountsSQL(q) + ")" + `, contributions AS (
 SELECT target_id AS application_id,argMax(observation_counts.name,observation_counts.last_seen) AS name,argMax(observation_counts.category,observation_counts.last_seen) AS category,sum(event_count) AS observation_count,toUInt64(0) AS connection_count,CAST(NULL AS Nullable(UInt64)) AS upload_bytes,CAST(NULL AS Nullable(UInt64)) AS download_bytes,toUInt64(0) AS missing_meter_connections,groupUniqArrayArray(observation_counts.terminals) AS terminals,max(observation_counts.last_seen) AS last_seen,toUInt8(0) AS kind FROM observation_counts WHERE target_type='application' GROUP BY target_id
 UNION ALL
 SELECT if(length(apps)=1,apps[1],'') AS application_id,label.1 AS name,label.2 AS category,toUInt64(0),toUInt64(1),up,down,toUInt64(isNull(up) OR isNull(down)),terminals,last_seen,toUInt8(if(length(apps)=0,1,if(length(apps)>1,2,0))) AS kind FROM connections
 ) SELECT kind,application_id,argMax(contributions.name,contributions.last_seen) AS name,argMax(contributions.category,contributions.last_seen) AS category,sum(observation_count) AS observation_count,sum(connection_count) AS connection_count,sumOrNull(upload_bytes) AS upload_bytes,sumOrNull(download_bytes) AS download_bytes,sum(missing_meter_connections) AS missing_meter_connections,uniqExactArray(terminals) AS terminal_count,formatDateTime(max(contributions.last_seen),'%Y-%m-%dT%H:%i:%S.%fZ','UTC') AS last_seen FROM contributions`
	if q.ApplicationID != "" {
		sql += " WHERE kind!=0 OR application_id=" + chQuote(q.ApplicationID)
	}

	sql += " GROUP BY kind,application_id ORDER BY kind,connection_count DESC,application_id" + appQuerySettings
	raw, err := d.readQuery(queryCtx, sql)
	if err != nil {
		return r, err
	}
	var contributions []struct {
		Kind uint8 `json:"kind"`
		appdomain.Item
	}
	if err = decodeJSONEachRow(raw, &contributions); err != nil {
		return r, err
	}
	for _, contribution := range contributions {
		if contribution.Kind == 0 {
			item := contribution.Item
			item.LastSeen = canonicalAppTime(item.LastSeen)
			r.Items = append(r.Items, item)
		} else {
			bucket := appdomain.Bucket{ConnectionCount: contribution.ConnectionCount, UploadBytes: contribution.UploadBytes, DownloadBytes: contribution.DownloadBytes, MissingMeterConnections: contribution.MissingMeterConnections}
			if contribution.Kind == 1 {
				r.Unknown = bucket
			} else {
				r.MultiApplication = bucket
			}
		}
	}

	versionRows := <-versionDone
	if versionRows.err != nil {
		return r, versionRows.err
	}
	raw = versionRows.raw
	var versions []struct {
		Version string `json:"bundle_version"`
		Count   int    `json:"count"`
		DNS     int    `json:"dns"`
		Unknown int    `json:"unknown"`
		Missing int    `json:"missing"`
	}
	if err = decodeJSONEachRow(raw, &versions); err != nil {
		return r, err
	}
	for _, v := range versions {
		r.Versions[v.Version] = v.Count
		r.ObservationCount += v.Count
		r.DNSObservations += v.DNS
		r.UnknownObservations += v.Unknown
		r.MissingConnectionObservations += v.Missing
	}

	return r, err
}
func (d *applicationDB) Page(ctx context.Context, q appdomain.Query, p appdomain.PageRequest) (appdomain.ObservationPage, error) {
	r := appdomain.ObservationPage{Items: []appdomain.Observation{}, Limit: p.Limit, Offset: p.Offset}
	c, err := appdomain.DecodePageCursor(p.Cursor)
	if err != nil {
		return r, err
	}
	where := appActive(q)
	if q.ApplicationID != "" {
		where += " AND target_type='application' AND target_id=" + chQuote(q.ApplicationID)
	}
	modelAt, err := d.observationModelTimestamp(ctx)
	if err != nil {
		return r, err
	}
	r.TotalAsOf = modelAt.UTC().Format(time.RFC3339Nano)
	raw, err := d.readQuery(ctx, "SELECT coalesce(sum(event_count),0) AS count,maxOrNull(last_seen) AS newest FROM ("+applicationObservationPageCountsSQL(q)+")"+appQuerySettings)
	if err != nil {
		return r, err
	}
	r.Total, err = decodeSingleCount(raw)
	if err != nil {
		return r, err
	}
	if r.Total == 0 {
		return r, nil
	}
	if p.Cursor != "" {
		ts := "parseDateTime64BestEffort(" + chQuote(c.Timestamp) + ",9)"
		where += " AND (timestamp<" + ts + " OR (timestamp=" + ts + " AND (sensor_id,event_id)>(" + chQuote(c.SensorID) + "," + chQuote(c.EventID) + ")))"
	}
	// Expand a descending time slice until it contains a full page. Every
	// skipped row is earlier than the selected rows, so this preserves the
	// original timestamp/sensor/event ordering, including equal timestamps.
	end := q.To
	var anchors []struct {
		Newest *string `json:"newest"`
	}
	if err = decodeJSONEachRow(raw, &anchors); err != nil {
		return r, err
	}
	if len(anchors) > 0 && anchors[0].Newest != nil {
		newest, parseErr := time.Parse(time.RFC3339Nano, *anchors[0].Newest)
		if parseErr != nil {
			return r, parseErr
		}
		if newest.Before(end) {
			end = newest.Add(time.Nanosecond)
		}
	}
	if p.Cursor != "" {
		cursorAt, parseErr := time.Parse(time.RFC3339Nano, c.Timestamp)
		if parseErr != nil {
			return r, parseErr
		}
		if cursorAt.Before(end) {
			end = cursorAt.Add(time.Nanosecond)
		}
	}
	span := 5 * time.Minute
	var rows []struct {
		JSON string `json:"observation_json"`
	}
	for {
		sliced := q
		sliced.From = end.Add(-span)
		if sliced.From.Before(q.From) {
			sliced.From = q.From
		}
		sliced.To = end
		selected := appLatestWindow(sliced, "target_id", "target_type") + fmt.Sprintf(", selected AS (SELECT timestamp,sensor_id,event_id FROM latest WHERE %s ORDER BY timestamp DESC,sensor_id,event_id LIMIT %d OFFSET %d) ", where, p.Limit+1, p.Offset)
		raw, err = d.readQuery(ctx, selected+"SELECT observation_json FROM application_latest_observations FINAL PREWHERE timestamp>=parseDateTime64BestEffort("+chQuote(sliced.From.Format(time.RFC3339Nano))+",9) AND timestamp<parseDateTime64BestEffort("+chQuote(end.Format(time.RFC3339Nano))+",9) AND (timestamp,sensor_id,event_id) IN (SELECT timestamp,sensor_id,event_id FROM selected) ORDER BY timestamp DESC,sensor_id,event_id"+appQuerySettings)
		if err != nil {
			return r, err
		}
		rows = nil
		if err = decodeJSONEachRow(raw, &rows); err != nil {
			return r, err
		}
		if len(rows) > p.Limit || !sliced.From.After(q.From) {
			break
		}
		span *= 2
	}

	for _, row := range rows {
		var o appdomain.Observation
		if err = json.Unmarshal([]byte(row.JSON), &o); err != nil {
			return r, err
		}
		r.Items = append(r.Items, o)
	}
	if len(r.Items) > p.Limit {
		r.Items = r.Items[:p.Limit]
		r.NextCursor = appdomain.EncodePageCursor(r.Items[len(r.Items)-1])
	}
	return r, nil
}
func (d *applicationDB) Export(ctx context.Context, q appdomain.Query, w io.Writer) error {
	// Bounded keyset pages also bound the HTTP response buffer of the CH client.
	after := ""
	enc := json.NewEncoder(w)
	for {
		sql := appLatestWindow(q, "domain", "source_field", "bundle_version", "target_id") + " SELECT domain,source_field,sensor_id,bundle_version,formatDateTime(min(timestamp),'%Y-%m-%dT%H:%i:%S.%fZ','UTC') AS first_seen,formatDateTime(max(timestamp),'%Y-%m-%dT%H:%i:%S.%fZ','UTC') AS last_seen,count() AS observation_count FROM latest WHERE " + appActive(q) + " AND domain!='' AND target_id=''"
		if after != "" {
			sql += " AND tuple(domain,source_field,sensor_id,bundle_version)>" + after
		}
		sql += " GROUP BY domain,source_field,sensor_id,bundle_version ORDER BY domain,source_field,sensor_id,bundle_version LIMIT 1000" + appQuerySettings
		raw, err := d.readQuery(ctx, sql)
		if err != nil {
			return err
		}
		var rows []appdomain.UnknownDomain
		if err = decodeJSONEachRow(raw, &rows); err != nil {
			return err
		}
		for _, row := range rows {
			row.FirstSeen = canonicalAppTime(row.FirstSeen)
			row.LastSeen = canonicalAppTime(row.LastSeen)
			if err = enc.Encode(row); err != nil {
				return err
			}
		}
		if len(rows) < 1000 {
			return nil
		}
		r := rows[len(rows)-1]
		after = "tuple(" + chQuote(r.Domain) + "," + chQuote(r.SourceField) + "," + chQuote(r.SensorID) + "," + chQuote(r.BundleVersion) + ")"
	}
}
func (d *applicationDB) write(ctx context.Context, rows []appdomain.Observation, revision, batch int64) error {
	if len(rows) == 0 {
		return nil
	}
	var b strings.Builder
	b.WriteString("INSERT INTO application_observations SETTINGS async_insert=0,date_time_input_format='best_effort' FORMAT JSONEachRow\n")
	enc := json.NewEncoder(&b)
	for _, o := range rows {
		raw, err := json.Marshal(o)
		if err != nil {
			return err
		}
		m := map[string]any{"timestamp": o.Timestamp, "sensor_id": o.SensorID, "event_id": o.EventID, "campus_id": o.CampusID, "ip": o.IP, "connection_id": o.ConnectionID, "event_type": o.EventType, "domain": o.Domain, "source_field": o.SourceField, "bundle_version": o.BundleVersion, "target_id": o.Match.TargetID, "target_type": o.Match.TargetType, "name": o.Match.Name, "category": o.Match.Category, "upload_bytes": o.UploadBytes, "download_bytes": o.DownloadBytes, "observation_json": string(raw), "classification_revision": revision, "batch_id": batch}
		if err = enc.Encode(m); err != nil {
			return err
		}
	}
	return d.store.ch.exec(ctx, b.String())
}

func canonicalAppTime(s string) string {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC().Format(time.RFC3339Nano)
	}
	return s
}

// Ordinary reconciliation only fills unseen events. Re-reading a seven-day
// source window must not append another copy of the entire result set.
func (d *applicationDB) existing(ctx context.Context, rows []appdomain.Observation) (map[string]bool, error) {
	out := map[string]bool{}
	// Include the complete MergeTree sorting key so ClickHouse can prune to the
	// narrow event ranges instead of rereading the retained observation table for
	// every event-ID page. This worker explicitly raises only the parser limit for
	// this bounded 5,000-key lookup, avoiding several fixed-cost round trips.
	const lookupChunkSize = 5000
	for start := 0; start < len(rows); start += lookupChunkSize {
		end := min(start+lookupChunkSize, len(rows))
		keys := make([]string, 0, end-start)
		for _, o := range rows[start:end] {
			if _, err := time.Parse(time.RFC3339Nano, o.Timestamp); err != nil {
				return nil, fmt.Errorf("invalid application observation timestamp %q: %w", o.Timestamp, err)
			}
			keys = append(keys, "tuple("+chQuote(o.SensorID)+","+chQuote(o.CampusID)+",parseDateTime64BestEffort("+chQuote(o.Timestamp)+",9),"+chQuote(o.EventID)+")")
		}
		raw, err := d.store.ch.queryWithSettings(ctx, "SELECT sensor_id,event_id FROM application_observations PREWHERE timestamp>=now64(9)-INTERVAL 7 DAY AND (sensor_id,campus_id,timestamp,event_id) IN ("+strings.Join(keys, ",")+") GROUP BY sensor_id,event_id"+appQuerySettings, map[string]string{"max_query_size": "1048576"})
		if err != nil {
			return nil, err
		}
		var found []struct {
			SensorID string `json:"sensor_id"`
			EventID  string `json:"event_id"`
		}
		if err = decodeJSONEachRow(raw, &found); err != nil {
			return nil, err
		}
		for _, row := range found {
			out[row.SensorID+"\x00"+row.EventID] = true
		}
	}
	return out, nil
}

// Interactive statistics have their own admission budget. Slow report clients
// cannot occupy the worker's source/read admission slots.
func (d *applicationDB) readQuery(ctx context.Context, query string) ([]byte, error) {
	d.queryOnce.Do(func() { d.querySlots = make(chan struct{}, 4) })
	select {
	case d.querySlots <- struct{}{}:
		defer func() { <-d.querySlots }()
		return d.store.ch.query(ctx, query)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
