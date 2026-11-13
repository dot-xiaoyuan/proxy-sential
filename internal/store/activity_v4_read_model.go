package store

import (
	"context"
	"fmt"
	"time"
)

const activityV4FiveMinuteModel = "activity-5m-v4"

type activityV4Version struct {
	Count      uint64 `json:"count"`
	Slot       uint8  `json:"slot"`
	Revision   uint64 `json:"revision"`
	Finalized  uint8  `json:"finalized"`
	SourceAsOf string `json:"source_as_of"`
}

type activityV4Digest struct {
	Keys   uint64 `json:"keys"`
	Events uint64 `json:"events"`
	Hash   uint64 `json:"hash"`
}

func activityV4BucketWhere(bucket time.Time, sensor, campus string) string {
	return "bucket_start=parseDateTimeBestEffort(" + chQuote(bucket.UTC().Format(time.RFC3339Nano)) + ") AND " + activityV3Scope(sensor, campus)
}

// A failed build only touches the nonpublished slot. Before retrying that slot,
// tombstones cover every key it has ever contained, including keys no longer
// present in the latest source revision. The next successful build publishes
// only after the full row digest matches v3.
func (s *DBStore) materializeActivityV4FiveMinute(ctx context.Context, job readModelJob) error {
	where := activityV4BucketWhere(job.BucketStart, job.SensorID, job.CampusID)
	var source []activityV4Version
	raw, err := s.ch.query(ctx, "SELECT count() count,argMax(revision,published_at) revision,argMax(finalized,published_at) finalized,argMax(source_as_of,published_at) source_as_of FROM activity_chart_bucket_versions_v3 WHERE granularity='5m' AND "+where+" FORMAT JSONEachRow")
	if err != nil {
		return err
	}
	if err = decodeJSONEachRow(raw, &source); err != nil {
		return err
	}
	if len(source) != 1 || source[0].Count == 0 || source[0].SourceAsOf == "" {
		return fmt.Errorf("activity v4 source revision missing: %s %s", job.SensorID, job.BucketStart)
	}
	var published []activityV4Version
	raw, err = s.ch.query(ctx, "SELECT count() count,argMax(slot,published_at) slot,argMax(revision,published_at) revision FROM activity_chart_bucket_versions_v4 WHERE "+where+" FORMAT JSONEachRow")
	if err != nil {
		return err
	}
	if err = decodeJSONEachRow(raw, &published); err != nil {
		return err
	}
	slot := uint8(1)
	if len(published) == 1 && published[0].Count > 0 {
		slot = published[0].Slot ^ 1
	}
	revision, err := s.nextReadModelRevision(ctx)
	if err != nil {
		return err
	}
	if revision > ^uint64(0)/2-1 {
		return fmt.Errorf("activity v4 revision overflow")
	}
	deadVersion, liveVersion := revision*2, revision*2+1
	// This SELECT is bounded to one bucket, sensor and inactive slot. It also
	// cleans up keys from an interrupted attempt on the same slot.
	tombstones := fmt.Sprintf(`INSERT INTO activity_chart_facts_5m_v4
SELECT bucket_start,sensor_id,campus_id,toUInt8(%d),dimension,value,toUInt64(%d),toUInt8(1),toUInt64(0),max(first_seen),max(last_seen)
FROM activity_chart_facts_5m_v4 WHERE %s AND slot=%d
GROUP BY bucket_start,sensor_id,campus_id,dimension,value
SETTINGS max_threads=1,max_memory_usage=536870912,max_bytes_before_external_group_by=134217728,max_execution_time=25`, slot, deadVersion, where, slot)
	if err = s.ch.exec(ctx, tombstones); err != nil {
		return err
	}
	data := fmt.Sprintf(`INSERT INTO activity_chart_facts_5m_v4
SELECT bucket_start,sensor_id,campus_id,toUInt8(%d),dimension,value,toUInt64(%d),toUInt8(0),event_count,first_seen,last_seen
FROM activity_chart_facts_5m_v3 WHERE %s AND revision=toUInt64(%d)
SETTINGS max_threads=1,max_memory_usage=536870912,max_execution_time=25`, slot, liveVersion, where, source[0].Revision)
	if err = s.ch.exec(ctx, data); err != nil {
		return err
	}
	var expected, actual []activityV4Digest
	raw, err = s.ch.query(ctx, fmt.Sprintf(`SELECT count() keys,sum(event_count) events,groupBitXor(cityHash64(dimension,value,event_count,first_seen,last_seen)) hash
FROM activity_chart_facts_5m_v3 WHERE %s AND revision=toUInt64(%d) FORMAT JSONEachRow`, where, source[0].Revision))
	if err != nil {
		return err
	}
	if err = decodeJSONEachRow(raw, &expected); err != nil {
		return err
	}
	raw, err = s.ch.query(ctx, fmt.Sprintf(`SELECT count() keys,sum(state.1) events,groupBitXor(cityHash64(dimension,value,state.1,state.2,state.3)) hash FROM (
 SELECT dimension,value,argMax(tuple(event_count,first_seen,last_seen,deleted),version) state
 FROM activity_chart_facts_5m_v4 WHERE %s AND slot=%d GROUP BY dimension,value HAVING state.4=0)
SETTINGS max_threads=1,max_memory_usage=536870912,max_bytes_before_external_group_by=134217728,max_execution_time=25 FORMAT JSONEachRow`, where, slot))
	if err != nil {
		return err
	}
	if err = decodeJSONEachRow(raw, &actual); err != nil {
		return err
	}
	if len(expected) != 1 || len(actual) != 1 || expected[0] != actual[0] {
		return fmt.Errorf("activity v4 bucket verification failed: %s %s expected=%v actual=%v", job.SensorID, job.BucketStart, expected, actual)
	}
	finalized := source[0].Finalized
	publish := fmt.Sprintf(`INSERT INTO activity_chart_bucket_versions_v4(bucket_start,sensor_id,campus_id,slot,revision,source_revision,source_as_of,published_at,finalized,metric_keys,event_count,content_hash)
VALUES(parseDateTimeBestEffort(%s),%s,%s,toUInt8(%d),toUInt64(%d),toUInt64(%d),parseDateTime64BestEffort(%s,9),now64(9),toUInt8(%d),toUInt64(%d),toUInt64(%d),toUInt64(%d))`, chQuote(job.BucketStart.UTC().Format(time.RFC3339Nano)), chQuote(job.SensorID), chQuote(job.CampusID), slot, revision, source[0].Revision, chQuote(source[0].SourceAsOf), finalized, actual[0].Keys, actual[0].Events, actual[0].Hash)
	return s.ch.exec(ctx, publish)
}
