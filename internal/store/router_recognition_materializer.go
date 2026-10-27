package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/normalized"
)

type routerRecognitionCursor struct {
	Timestamp time.Time
	EventID   string
	Owner     string
}

// The rolling risk materializer may omit its expensive duplicate router replay
// only while this independent, cursor-based owner is making progress.
func (s *DBStore) DedicatedRouterObservationsHealthy(ctx context.Context, sensorID string, at time.Time) error {
	if sensorID == "" {
		return fmt.Errorf("dedicated router owner requires a sensor")
	}
	var success sql.NullTime
	var lastError string
	var ownerSensor string
	err := s.pg.db.QueryRowContext(ctx, `SELECT sensor_id,last_success_at,last_error FROM router_recognition_state WHERE singleton`).Scan(&ownerSensor, &success, &lastError)
	if err != nil {
		return err
	}
	if ownerSensor != sensorID || !success.Valid || success.Time.Before(at.Add(-2*time.Minute)) || lastError != "" {
		return fmt.Errorf("router recognition cursor is stale or failed")
	}
	var streamSourceActive bool
	if err := s.pg.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM stream_source_cutovers
 WHERE sensor_id=$1 AND state='active' AND source_kind IN ('zeek-dhcp-binding','device-signals','shared-device-signals'))`, sensorID).Scan(&streamSourceActive); err != nil {
		return err
	}
	if streamSourceActive {
		var streamSuccess sql.NullTime
		var streamError string
		if err := s.pg.db.QueryRowContext(ctx, `SELECT last_success_at,last_error FROM stream_router_recognition_state WHERE sensor_id=$1`, sensorID).Scan(&streamSuccess, &streamError); err != nil {
			return err
		}
		if !streamSuccess.Valid || streamSuccess.Time.Before(at.Add(-2*time.Minute)) || streamError != "" {
			return fmt.Errorf("stream router recognition cursor is stale or failed")
		}
	}
	return nil
}

type routerSignalRow struct {
	Timestamp       string  `json:"timestamp"`
	EventID         string  `json:"event_id"`
	Source          string  `json:"source"`
	SourceEventType string  `json:"source_event_type"`
	Type            string  `json:"type"`
	SensorID        string  `json:"sensor_id"`
	CampusID        string  `json:"campus_id"`
	EndpointID      string  `json:"endpoint_id"`
	SubjectIP       string  `json:"subject_ip"`
	SubjectMAC      string  `json:"subject_mac"`
	ObserverJSON    string  `json:"observer_json"`
	PayloadJSON     string  `json:"payload_json"`
	FlowJSON        string  `json:"flow_json"`
	Confidence      float64 `json:"confidence"`
}

func (s *DBStore) claimRouterRecognition(ctx context.Context, owner, sensorID string) (routerRecognitionCursor, bool, error) {
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return routerRecognitionCursor{}, false, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO router_recognition_state(singleton) VALUES(true) ON CONFLICT(singleton) DO NOTHING`); err != nil {
		return routerRecognitionCursor{}, false, err
	}
	var stamp sql.NullTime
	var eventID, materializedRuleVersion, ownerSensor string
	var leased bool
	if err = tx.QueryRowContext(ctx, `SELECT cursor_timestamp,cursor_event_id,lease_until>now(),rule_version,sensor_id FROM router_recognition_state WHERE singleton FOR UPDATE`).Scan(&stamp, &eventID, &leased, &materializedRuleVersion, &ownerSensor); err != nil {
		return routerRecognitionCursor{}, false, err
	}
	if ownerSensor != "" && ownerSensor != sensorID {
		return routerRecognitionCursor{}, false, fmt.Errorf("router recognition sensor owner mismatch")
	}
	if leased {
		return routerRecognitionCursor{}, false, tx.Commit()
	}
	currentRuleVersion := fingerprint.DefaultRouterRuleSet().Version
	if materializedRuleVersion != currentRuleVersion {
		ttl, parseErr := time.ParseDuration(fingerprint.DefaultRouterRuleSet().Thresholds.EvidenceTTL)
		if parseErr != nil {
			return routerRecognitionCursor{}, false, parseErr
		}
		rebuildFrom := time.Now().UTC().Add(-ttl)
		// Preserve history but remove obsolete rule output from active reads.
		// Replaying the bounded signal stream will rebuild only evidence that
		// still matches the newly installed rule set.
		if _, err = tx.ExecContext(ctx, `UPDATE router_evidence_facts SET expires_at=LEAST(expires_at,now()) WHERE expires_at>now()`); err != nil {
			return routerRecognitionCursor{}, false, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE router_assessments SET expires_at=LEAST(expires_at,now()),updated_at=now() WHERE expires_at>now()`); err != nil {
			return routerRecognitionCursor{}, false, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE router_recognition_state SET cursor_timestamp=$1,cursor_event_id='',rule_version=$2,updated_at=now() WHERE singleton`, rebuildFrom, currentRuleVersion); err != nil {
			return routerRecognitionCursor{}, false, err
		}
		stamp, eventID = sql.NullTime{Time: rebuildFrom, Valid: true}, ""
	}
	if _, err = tx.ExecContext(ctx, `UPDATE router_recognition_state SET lease_owner=$1,sensor_id=$2,lease_until=now()+interval '90 seconds',updated_at=now() WHERE singleton`, owner, sensorID); err != nil {
		return routerRecognitionCursor{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return routerRecognitionCursor{}, false, err
	}
	return routerRecognitionCursor{Timestamp: stamp.Time.UTC(), EventID: eventID, Owner: owner}, true, nil
}

func (s *DBStore) routerSignalBatch(ctx context.Context, sensorID string, cursor routerRecognitionCursor, limit int) ([]normalized.Event, routerRecognitionCursor, error) {
	if limit <= 0 || limit > 5000 {
		limit = 2000
	}
	where := "sensor_id=" + chQuote(sensorID)
	if !cursor.Timestamp.IsZero() {
		// 时间下界让分区与主键裁剪先发生；续读点用可索引的析取式表达，
		// 元组比较会让主键索引失效并退化为全表扫描。
		stamp := "parseDateTime64BestEffort(" + chQuote(cursor.Timestamp.Format(time.RFC3339Nano)) + ",6)"
		where += " AND timestamp>=" + stamp + " AND (" + chAfterBound([]chBoundKey{{Expr: "timestamp", Value: stamp}, {Expr: "event_id", Value: chQuote(cursor.EventID)}}) + ")"
	}
	data, err := s.ch.query(ctx, fmt.Sprintf(`SELECT timestamp,event_id,source,source_event_type,type,sensor_id,campus_id,endpoint_id,subject_ip,subject_mac,observer_json,payload_json,flow_json,confidence FROM router_signal_events_v1 WHERE %s ORDER BY timestamp,event_id LIMIT %d SETTINGS max_threads=1,max_memory_usage=268435456,max_execution_time=20 FORMAT JSONEachRow`, where, limit))
	if err != nil {
		return nil, cursor, err
	}
	rows := []routerSignalRow{}
	if err = decodeJSONEachRow(data, &rows); err != nil {
		return nil, cursor, err
	}
	events := make([]normalized.Event, 0, len(rows))
	next := cursor
	for _, row := range rows {
		stamp, parseErr := time.Parse(time.RFC3339Nano, normalizeClickHouseTimestamp(row.Timestamp))
		if parseErr != nil {
			return nil, cursor, parseErr
		}
		event := normalized.Event{
			SchemaVersion:   "v1",
			EventID:         row.EventID,
			Timestamp:       stamp.UTC().Format(time.RFC3339Nano),
			Source:          row.Source,
			SourceEventType: row.SourceEventType,
			Type:            row.Type,
			Observer:        map[string]any{"sensor_id": row.SensorID},
			Subject:         map[string]any{"ip": row.SubjectIP, "campus_id": row.CampusID},
			Payload:         map[string]any{},
			Flow:            map[string]any{},
			Confidence:      row.Confidence,
		}
		if row.EndpointID != "" {
			event.Subject["endpoint_id"] = row.EndpointID
		}
		if row.SubjectMAC != "" {
			event.Subject["mac"] = row.SubjectMAC
		}
		if row.SourceEventType == "lldp" || row.SourceEventType == "cdp" || row.SourceEventType == "ssdp" || row.SourceEventType == "vrrp" || row.SourceEventType == "hsrp" {
			event.Subject["entity_role"] = "network_device"
		}
		if strings.TrimSpace(row.ObserverJSON) != "" {
			if err = json.Unmarshal([]byte(row.ObserverJSON), &event.Observer); err != nil {
				return nil, cursor, fmt.Errorf("decode router observer metadata: %w", err)
			}
		}
		if event.Observer == nil {
			event.Observer = map[string]any{}
		}
		event.Observer["sensor_id"] = row.SensorID
		if strings.TrimSpace(row.PayloadJSON) != "" {
			if err = json.Unmarshal([]byte(row.PayloadJSON), &event.Payload); err != nil {
				return nil, cursor, err
			}
		}
		if strings.TrimSpace(row.FlowJSON) != "" {
			if err = json.Unmarshal([]byte(row.FlowJSON), &event.Flow); err != nil {
				return nil, cursor, err
			}
		}
		if _, ok := event.Subject["mac"]; !ok {
			if mac := firstNonEmpty(stringFromMap(event.Payload, "mac"), stringFromMap(event.Payload, "client_mac"), stringFromMap(event.Payload, "client_chaddr")); mac != "" {
				event.Subject["mac"] = mac
			}
		}
		events = append(events, event)
		next.Timestamp, next.EventID = stamp.UTC(), row.EventID
	}
	return events, next, nil
}

func (s *DBStore) finishRouterRecognition(parent context.Context, cursor routerRecognitionCursor, processed int, runErr error) error {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	if runErr != nil {
		_, err := s.pg.db.ExecContext(ctx, `UPDATE router_recognition_state SET lease_owner='',lease_until='-infinity',last_error=$2,updated_at=now() WHERE singleton AND lease_owner=$1`, cursor.Owner, runErr.Error())
		return err
	}
	var stamp any
	if !cursor.Timestamp.IsZero() {
		stamp = cursor.Timestamp
	}
	_, err := s.pg.db.ExecContext(ctx, `UPDATE router_recognition_state SET cursor_timestamp=COALESCE($2,cursor_timestamp),cursor_event_id=CASE WHEN $2::timestamptz IS NULL THEN cursor_event_id ELSE $3 END,processed_events=processed_events+$4,lease_owner='',lease_until='-infinity',last_success_at=now(),last_error='',updated_at=now() WHERE singleton AND lease_owner=$1`, cursor.Owner, stamp, cursor.EventID, processed)
	return err
}

func (s *DBStore) runRouterRecognitionMaterializer(ctx context.Context, sensorID string) {
	owner := fmt.Sprintf("router-recognition-%d", os.Getpid())
	for ctx.Err() == nil {
		workCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		cursor, claimed, err := s.claimRouterRecognition(workCtx, owner, sensorID)
		if err == nil && claimed {
			var events []normalized.Event
			var next routerRecognitionCursor
			events, next, err = s.routerSignalBatch(workCtx, sensorID, cursor, 2000)
			if err == nil && len(events) > 0 {
				err = s.analyzeAndWriteRouterEvents(workCtx, events)
			}
			if err == nil {
				_, err = s.pg.refreshExpiredRouterAssessments(workCtx, 50)
			}
			if err == nil {
				cursor = next
			}
			if finishErr := s.finishRouterRecognition(ctx, cursor, len(events), err); err == nil {
				err = finishErr
			}
		}
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "router recognition materialize failed: %v\n", err)
		}
		delay := 5 * time.Second
		if claimed && err == nil {
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

func (s *DBStore) analyzeAndWriteRouterEvents(ctx context.Context, events []normalized.Event) error {
	return s.analyzeAndWriteRouterEventsWithResolver(ctx, events, func(event normalized.Event) evidence.RouterAssociation {
		item, found, resolveErr := s.ResolveDeviceAt(ctx, DomainObservation{
			IP: stringFromMap(event.Subject, "ip"), Timestamp: event.Timestamp,
			SensorID: stringFromMap(event.Observer, "sensor_id"), CampusID: stringFromMap(event.Subject, "campus_id"),
		})
		if resolveErr != nil || !found {
			return evidence.RouterAssociation{}
		}
		association := evidence.RouterAssociation{EndpointID: item.EndpointID, Quality: "dhcp_lease", Ambiguous: item.Conflict, Reason: item.ConflictReason}
		if strings.HasPrefix(item.EndpointID, "mac:") {
			association.MAC = strings.TrimPrefix(item.EndpointID, "mac:")
		}
		return association
	})
}

func (s *DBStore) analyzeAndWriteStreamRouterEvents(ctx context.Context, events []normalized.Event) error {
	// The packet sidecar emits TTL-only observations without a verified MAC or
	// router fingerprint. A batch made only of those observations cannot create
	// a router fact, regardless of which DHCP lease owns each address. The
	// indexed events are still read and the caller advances its durable cursor.
	pureTTL := len(events) > 0
	for _, event := range events {
		if !isPurePacketRouterTTL(event) {
			pureTTL = false
			break
		}
	}
	if pureTTL {
		return nil
	}
	started := time.Now()
	associations, err := s.pg.resolveRouterLeaseBatch(ctx, events)
	leaseDuration := time.Since(started)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stream router lease batch events=%d lease_ms=%d error=%v\n", len(events), leaseDuration.Milliseconds(), err)
		return err
	}
	writeStarted := time.Now()
	err = s.analyzeAndWriteRouterEventsWithResolver(ctx, events, func(event normalized.Event) evidence.RouterAssociation {
		return associations[routerLeaseKeyFromEvent(event)]
	})
	if leaseDuration+time.Since(writeStarted) >= 2*time.Second || err != nil {
		fmt.Fprintf(os.Stderr, "stream router analysis events=%d lease_ms=%d write_ms=%d error=%v\n",
			len(events), leaseDuration.Milliseconds(), time.Since(writeStarted).Milliseconds(), err)
	}
	return err
}

func isPurePacketRouterTTL(event normalized.Event) bool {
	if event.Source != "packet-sidecar" || event.SourceEventType != "ttl" || event.Type != "device" ||
		stringFromMap(event.Subject, "endpoint_id") != "" || stringFromMap(event.Subject, "mac") != "" {
		return false
	}
	for key := range event.Payload {
		switch key {
		case "origin", "neighbor_mac", "neighbor_role", "ttl", "ip_version", "observed_count", "access_domain":
		default:
			return false
		}
	}
	for key := range event.Flow {
		switch key {
		case "src_ip", "direction", "ip_version", "traffic_scope":
		default:
			return false
		}
	}
	return true
}

func (s *DBStore) analyzeAndWriteRouterEventsWithResolver(ctx context.Context, events []normalized.Event, resolve func(normalized.Event) evidence.RouterAssociation) error {
	result, err := evidence.AnalyzeRouters(events, evidence.RouterOptions{
		AsOf:       time.Now().UTC(),
		ShadowMode: true,
		Resolve:    resolve,
	})
	if err != nil {
		return err
	}
	if len(result.Evidence) == 0 && len(result.Assessments) == 0 {
		return nil
	}
	return s.WriteRouterObservations(ctx, result)
}
