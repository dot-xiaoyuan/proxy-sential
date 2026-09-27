package store

import (
	"context"
	"fmt"
	"time"
)

// RefreshActivityRollupDay replaces a whole day, so retries and late events do
// not add counts to a previously computed bucket.
func (s *ClickHouseStore) RefreshActivityRollupDay(ctx context.Context, date string) error {
	day, err := time.Parse("2006-01-02", date)
	if err != nil || day.Format("2006-01-02") != date {
		return fmt.Errorf("invalid rollup date %q", date)
	}
	partition := day.Format("20060102")
	if err := s.exec(ctx, "TRUNCATE TABLE activity_rollup_10m_stage"); err != nil {
		return err
	}
	const domain = `multiIf(type='dns',JSONExtractString(payload_json,'query'),type='http',JSONExtractString(payload_json,'host'),type IN ('tls','quic'),JSONExtractString(payload_json,'sni'),'')`
	query := fmt.Sprintf(`INSERT INTO activity_rollup_10m_stage
SELECT bucket,sensor_id,campus_id,tupleElement(pair,1) AS dimension,
if(trim(toString(tupleElement(pair,2)))='','未知',trim(toString(tupleElement(pair,2)))) AS value,
count() AS event_count,max(timestamp) AS last_seen
FROM (
  SELECT timestamp,toStartOfInterval(timestamp,INTERVAL 10 MINUTE) AS bucket,sensor_id,campus_id,
  arrayJoin([
    tuple('application',JSONExtractString(flow_json,'app_protocol')),
    tuple('protocol',upper(proto)),
    tuple('src_ip',subject_ip),
    tuple('dst_ip',dst_ip),
    tuple('dst_port',if(dst_port=0,'',toString(dst_port))),
    tuple('domain',if(type IN ('dns','http','tls','quic'),%s,'__skip__')),
    tuple('http_host',if(type='http',JSONExtractString(payload_json,'host'),'__skip__')),
    tuple('tls_sni',if(type='tls',JSONExtractString(payload_json,'sni'),'__skip__')),
    tuple('quic_sni',if(type='quic',JSONExtractString(payload_json,'sni'),'__skip__')),
    tuple('user_agent',if(type='http',JSONExtractString(payload_json,'user_agent'),'__skip__'))
  ]) AS pair
  FROM normalized_events_canonical FINAL
  WHERE timestamp >= toDateTime(%s,'Asia/Shanghai') AND timestamp < toDateTime(%s,'Asia/Shanghai') + INTERVAL 1 DAY
) WHERE tupleElement(pair,2) != '__skip__'
GROUP BY bucket,sensor_id,campus_id,dimension,value`, domain, chQuote(date), chQuote(date))
	if err := s.exec(ctx, query); err != nil {
		return err
	}
	data, err := s.query(ctx, "SELECT count() AS count FROM activity_rollup_10m_stage FORMAT JSONEachRow")
	if err != nil {
		return err
	}
	count, err := decodeSingleCount(data)
	if err != nil {
		return err
	}
	if count == 0 {
		if err := s.exec(ctx, "ALTER TABLE activity_rollup_10m DROP PARTITION "+partition); err != nil {
			return err
		}
	} else if err := s.exec(ctx, "ALTER TABLE activity_rollup_10m REPLACE PARTITION "+partition+" FROM activity_rollup_10m_stage"); err != nil {
		return err
	}
	if err := s.exec(ctx, "INSERT INTO activity_rollup_refreshes(date,refreshed_at) VALUES (toDate("+chQuote(date)+"),now64(6))"); err != nil {
		return err
	}
	return s.exec(ctx, "TRUNCATE TABLE activity_rollup_10m_stage")
}
