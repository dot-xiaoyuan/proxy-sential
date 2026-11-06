package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
)

const passiveLivePTRBatchSize = 500

type passiveLivePTRCursor struct {
	ReceivedAt time.Time
	EventID    string
	Owner      string
}

type passiveLivePTRStreamRow struct {
	ReceivedAt    string `json:"received_at"`
	Timestamp     string `json:"event_timestamp"`
	EventID       string `json:"event_id"`
	SensorID      string `json:"sensor_id"`
	CampusID      string `json:"campus_id"`
	SubjectIP     string `json:"subject_ip"`
	FlowSrcIP     string `json:"flow_src_ip"`
	FlowDstIP     string `json:"flow_dst_ip"`
	InterfaceName string `json:"interface_name"`
	ResponderMAC  string `json:"responder_mac"`
	RecordName    string `json:"record_name"`
	ServiceTarget string `json:"service_target"`
	RecordTTLRaw  string `json:"record_ttl_raw"`
}

func (row passiveLivePTRStreamRow) normalizedEvent() (normalized.Event, time.Time, error) {
	receivedAt, err := time.Parse(time.RFC3339Nano, normalizeClickHouseTimestamp(row.ReceivedAt))
	if err != nil {
		return normalized.Event{}, time.Time{}, err
	}
	at, err := time.Parse(time.RFC3339Nano, normalizeClickHouseTimestamp(row.Timestamp))
	if err != nil {
		return normalized.Event{}, time.Time{}, err
	}
	event := normalized.Event{
		EventID: row.EventID, Source: "zeek", SourceEventType: "mdns", Timestamp: at.UTC().Format(time.RFC3339Nano),
		Observer: map[string]any{"sensor_id": row.SensorID, "interface": row.InterfaceName},
		Subject: map[string]any{"ip": row.SubjectIP, "campus_id": row.CampusID},
		Flow: map[string]any{"src_ip": row.FlowSrcIP, "dst_ip": row.FlowDstIP},
		Payload: map[string]any{"is_response": true, "record_type": "PTR", "record_name": row.RecordName, "service_target": row.ServiceTarget,
			"l2_source_mac_direct": true, "responder_l2_mac": row.ResponderMAC}, Confidence: 0.75,
	}
	if row.RecordTTLRaw != "" {
		var ttl any
		if err = json.Unmarshal([]byte(row.RecordTTLRaw), &ttl); err != nil {
			return normalized.Event{}, time.Time{}, err
		}
		event.Payload["record_ttl"] = ttl
	}
	return event, receivedAt.UTC(), nil
}

func passiveLivePTRStart(now time.Time) (time.Time, error) {
	raw := strings.TrimSpace(os.Getenv("PROXY_SENTINEL_PASSIVE_LIVE_PTR_START"))
	if raw == "" {
		return now.Add(-2 * time.Hour).UTC(), nil
	}
	start, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || start.After(now) {
		return time.Time{}, fmt.Errorf("invalid passive live PTR start: expected a past RFC3339 time")
	}
	return start.UTC(), nil
}

func (s *DBStore) claimPassiveLivePTR(ctx context.Context, sensorID, owner string) (passiveLivePTRCursor, bool, error) {
	start, err := passiveLivePTRStart(time.Now())
	if err != nil {
		return passiveLivePTRCursor{}, false, err
	}
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return passiveLivePTRCursor{}, false, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO passive_live_ptr_state(sensor_id,start_received_at,cursor_received_at) VALUES($1,$2,$2) ON CONFLICT DO NOTHING`, sensorID, start); err != nil {
		return passiveLivePTRCursor{}, false, err
	}
	var cursor passiveLivePTRCursor
	var leased bool
	if err = tx.QueryRowContext(ctx, `SELECT cursor_received_at,cursor_event_id,lease_until>clock_timestamp() FROM passive_live_ptr_state WHERE sensor_id=$1 FOR UPDATE`, sensorID).Scan(&cursor.ReceivedAt, &cursor.EventID, &leased); err != nil {
		return passiveLivePTRCursor{}, false, err
	}
	if leased {
		return passiveLivePTRCursor{}, false, tx.Commit()
	}
	cursor.Owner = owner
	if _, err = tx.ExecContext(ctx, `UPDATE passive_live_ptr_state SET lease_owner=$2,lease_until=clock_timestamp()+interval '90 seconds',updated_at=now() WHERE sensor_id=$1`, sensorID, owner); err != nil {
		return passiveLivePTRCursor{}, false, err
	}
	return cursor, true, tx.Commit()
}

func (s *DBStore) passiveLivePTREvents(ctx context.Context, sensorID string, cursor passiveLivePTRCursor) ([]normalized.Event, passiveLivePTRCursor, error) {
	cutoff := time.Now().UTC().Add(-2 * time.Minute)
	stamp := "parseDateTime64BestEffort(" + chQuote(cursor.ReceivedAt.UTC().Format(time.RFC3339Nano)) + ",6)"
	upper := "parseDateTime64BestEffort(" + chQuote(cutoff.Format(time.RFC3339Nano)) + ",6)"
	where := "sensor_id=" + chQuote(sensorID) + " AND received_at>=" + stamp + " AND received_at<" + upper
	where += " AND (" + chAfterBound([]chBoundKey{{Expr: "received_at", Value: stamp}, {Expr: "event_id", Value: chQuote(cursor.EventID)}}) + ")"
	query := fmt.Sprintf(`SELECT formatDateTime(received_at,'%%Y-%%m-%%dT%%H:%%i:%%S.%%fZ','UTC') received_at,
formatDateTime(timestamp,'%%Y-%%m-%%dT%%H:%%i:%%S.%%fZ','UTC') event_timestamp,
event_id,sensor_id,campus_id,subject_ip,flow_src_ip,flow_dst_ip,interface_name,responder_mac,record_name,service_target,record_ttl_raw
FROM passive_live_ptr_events PREWHERE %s ORDER BY received_at,event_id LIMIT %d
SETTINGS max_threads=1,max_memory_usage=268435456,max_execution_time=20 FORMAT JSONEachRow`, where, passiveLivePTRBatchSize)
	raw, err := s.ch.query(ctx, query)
	if err != nil {
		return nil, cursor, err
	}
	rows := []passiveLivePTRStreamRow{}
	if err = decodeJSONEachRow(raw, &rows); err != nil {
		return nil, cursor, err
	}
	events := make([]normalized.Event, 0, len(rows))
	next := cursor
	for _, row := range rows {
		event, receivedAt, parseErr := row.normalizedEvent()
		if parseErr != nil {
			return nil, cursor, parseErr
		}
		events = append(events, event)
		next.ReceivedAt, next.EventID = receivedAt.UTC(), row.EventID
	}
	return events, next, nil
}

func (s *DBStore) finishPassiveLivePTR(ctx context.Context, sensorID string, cursor passiveLivePTRCursor, events []normalized.Event, scope passiveDiscoveryScope) error {
	facts := make([]passiveLivePTRFactRow, 0, len(events))
	accepted := 0
	now := time.Now()
	for _, event := range events {
		fact, ok := passiveLivePTRFact(event, scope)
		if !ok {
			continue
		}
		// Keep the latest event-time watermark even when an old advertisement
		// has already expired; a later-arriving older positive must not revive it.
		if !fact.Withdrawn && !fact.ValidUntil.After(now) {
			fact.Withdrawn = true
		}
		facts = append(facts, fact)
		accepted++
	}
	facts = passiveLatestLivePTRFacts(facts)
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if len(facts) > 0 {
		raw, marshalErr := json.Marshal(facts)
		if marshalErr != nil {
			return marshalErr
		}
		// The responder MAC is taken from its own multicast frame. Promote a
		// low-confidence endpoint before the fact trigger wakes recognition.
		_, err = tx.ExecContext(ctx, `WITH incoming AS (
 SELECT endpoint_id,min(observed_at) first_seen,max(observed_at) last_seen
 FROM jsonb_to_recordset($1::jsonb) AS r(endpoint_id text,observed_at timestamptz)
 GROUP BY endpoint_id
)
INSERT INTO endpoint_entities(endpoint_id,primary_mac,entity_role,first_seen,last_seen,identity_confidence,attributes)
SELECT endpoint_id,substring(endpoint_id from 5),'endpoint',first_seen,last_seen,0.55,
       '{"identity_source":"passive_mdns_l2_responder"}'::jsonb FROM incoming
ON CONFLICT(endpoint_id) DO UPDATE SET
 first_seen=LEAST(coalesce(endpoint_entities.first_seen,EXCLUDED.first_seen),EXCLUDED.first_seen),
 last_seen=GREATEST(endpoint_entities.last_seen,EXCLUDED.last_seen),
 identity_confidence=GREATEST(endpoint_entities.identity_confidence,EXCLUDED.identity_confidence),
 attributes=CASE WHEN endpoint_entities.last_seen IS NULL THEN endpoint_entities.attributes || '{"identity_source":"passive_mdns_l2_responder"}'::jsonb ELSE endpoint_entities.attributes END,
 updated_at=now()
WHERE endpoint_entities.entity_role='endpoint'
 AND (endpoint_entities.attributes->>'identity_source'='passive_mdns_l2_responder' OR endpoint_entities.last_seen IS NULL)
 AND (endpoint_entities.last_seen IS NULL OR endpoint_entities.last_seen<EXCLUDED.last_seen-interval '5 minutes')`, string(raw))
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO passive_live_ptr_current(sensor_id,site,interface_name,responder_ip,endpoint_id,record_name,instance,name,event_id,observed_at,valid_until,withdrawn)
SELECT sensor_id,site,interface_name,responder_ip,endpoint_id,record_name,instance,name,event_id,observed_at,valid_until,withdrawn
FROM jsonb_to_recordset($1::jsonb) AS r(sensor_id text,site text,interface_name text,responder_ip text,endpoint_id text,record_name text,instance text,name text,event_id text,observed_at timestamptz,valid_until timestamptz,withdrawn boolean)
ON CONFLICT(sensor_id,site,interface_name,responder_ip,endpoint_id,record_name,instance)
DO UPDATE SET name=EXCLUDED.name,event_id=EXCLUDED.event_id,observed_at=EXCLUDED.observed_at,valid_until=EXCLUDED.valid_until,withdrawn=EXCLUDED.withdrawn,updated_at=now()
WHERE (EXCLUDED.observed_at,EXCLUDED.event_id)>(passive_live_ptr_current.observed_at,passive_live_ptr_current.event_id)`, string(raw))
		if err != nil {
			return err
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE passive_live_ptr_state SET cursor_received_at=$3,cursor_event_id=$4,
processed_events=processed_events+$5,candidate_facts=candidate_facts+$6,rejected_events=rejected_events+$7,
lease_owner='',lease_until='-infinity',last_success_at=now(),last_error='',updated_at=now()
WHERE sensor_id=$1 AND lease_owner=$2 AND lease_until>clock_timestamp()`, sensorID, cursor.Owner, cursor.ReceivedAt, cursor.EventID, len(events), len(facts), len(events)-accepted)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return fmt.Errorf("passive live PTR lease lost")
	}
	return tx.Commit()
}

func (s *DBStore) failPassiveLivePTR(sensorID, owner string, failure error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = s.pg.db.ExecContext(ctx, `UPDATE passive_live_ptr_state SET lease_owner='',lease_until='-infinity',last_error=$3,updated_at=now() WHERE sensor_id=$1 AND lease_owner=$2`, sensorID, owner, failure.Error())
}

func (s *DBStore) sweepPassiveLivePTR(ctx context.Context) error {
	_, err := s.pg.db.ExecContext(ctx, `WITH due AS (
 SELECT ctid FROM passive_live_ptr_current WHERE NOT withdrawn AND valid_until<=clock_timestamp()
 ORDER BY valid_until LIMIT 100 FOR UPDATE SKIP LOCKED
)
UPDATE passive_live_ptr_current SET withdrawn=true,updated_at=now()
WHERE ctid IN (SELECT ctid FROM due)`)
	if err != nil {
		return err
	}
	_, err = s.pg.db.ExecContext(ctx, `WITH stale AS (
 SELECT ctid FROM passive_live_ptr_current WHERE withdrawn AND valid_until<clock_timestamp()-interval '30 days'
 ORDER BY valid_until LIMIT 100 FOR UPDATE SKIP LOCKED
)
DELETE FROM passive_live_ptr_current WHERE ctid IN (SELECT ctid FROM stale)`)
	return err
}

func (s *DBStore) runPassiveLivePTRMaterializer(ctx context.Context, sensorID string) {
	if os.Getenv("PROXY_SENTINEL_PASSIVE_LIVE_PTR_DISABLED") == "true" {
		return
	}
	owner := fmt.Sprintf("passive-live-ptr-%d", os.Getpid())
	nextSweep := time.Time{}
	for ctx.Err() == nil {
		workCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		scope, err := parsePassiveDiscoveryScope(os.Getenv("PROXY_SENTINEL_DISCOVERY_CIDRS"))
		var cursor passiveLivePTRCursor
		claimed := false
		count := 0
		if err == nil {
			cursor, claimed, err = s.claimPassiveLivePTR(workCtx, sensorID, owner)
		}
		if err == nil && claimed {
			var events []normalized.Event
			var next passiveLivePTRCursor
			events, next, err = s.passiveLivePTREvents(workCtx, sensorID, cursor)
			count = len(events)
			if err == nil {
				err = s.finishPassiveLivePTR(workCtx, sensorID, next, events, scope)
			}
		}
		if err != nil && ctx.Err() == nil {
			if claimed {
				s.failPassiveLivePTR(sensorID, cursor.Owner, err)
			}
			fmt.Fprintf(os.Stderr, "passive live PTR materialize failed: %v\n", err)
		}
		cancel()
		if time.Now().After(nextSweep) {
			sweepCtx, sweepCancel := context.WithTimeout(ctx, 3*time.Second)
			if sweepErr := s.sweepPassiveLivePTR(sweepCtx); sweepErr != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "passive live PTR expiry failed: %v\n", sweepErr)
			}
			sweepCancel()
			nextSweep = time.Now().Add(30 * time.Second)
		}
		delay := 5 * time.Second
		if err == nil && claimed && count >= passiveLivePTRBatchSize {
			delay = 0
		} else if err == nil && claimed {
			delay = time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
