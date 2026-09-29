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

func (s *DBStore) claimRouterRecognition(ctx context.Context, owner string) (routerRecognitionCursor, bool, error) {
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return routerRecognitionCursor{}, false, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO router_recognition_state(singleton) VALUES(true) ON CONFLICT(singleton) DO NOTHING`); err != nil {
		return routerRecognitionCursor{}, false, err
	}
	var stamp sql.NullTime
	var eventID, materializedRuleVersion string
	var leased bool
	if err = tx.QueryRowContext(ctx, `SELECT cursor_timestamp,cursor_event_id,lease_until>now(),rule_version FROM router_recognition_state WHERE singleton FOR UPDATE`).Scan(&stamp, &eventID, &leased, &materializedRuleVersion); err != nil {
		return routerRecognitionCursor{}, false, err
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
	if _, err = tx.ExecContext(ctx, `UPDATE router_recognition_state SET lease_owner=$1,lease_until=now()+interval '90 seconds',updated_at=now() WHERE singleton`, owner); err != nil {
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
		where += " AND (timestamp,event_id)>(parseDateTime64BestEffort(" + chQuote(cursor.Timestamp.Format(time.RFC3339Nano)) + ",6)," + chQuote(cursor.EventID) + ")"
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
			_ = json.Unmarshal([]byte(row.ObserverJSON), &event.Observer)
			event.Observer["sensor_id"] = row.SensorID
		}
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

func (s *DBStore) finishRouterRecognition(ctx context.Context, cursor routerRecognitionCursor, processed int, runErr error) error {
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
		cursor, claimed, err := s.claimRouterRecognition(workCtx, owner)
		if err == nil && claimed {
			var events []normalized.Event
			var next routerRecognitionCursor
			events, next, err = s.routerSignalBatch(workCtx, sensorID, cursor, 2000)
			if err == nil && len(events) > 0 {
				result, analyzeErr := evidence.AnalyzeRouters(events, evidence.RouterOptions{
					AsOf:       time.Now().UTC(),
					ShadowMode: true,
					Resolve: func(event normalized.Event) evidence.RouterAssociation {
						item, found, resolveErr := s.ResolveDeviceAt(workCtx, DomainObservation{
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
					},
				})
				if analyzeErr != nil {
					err = analyzeErr
				} else {
					err = s.WriteRouterObservations(workCtx, result)
				}
			}
			if err == nil {
				cursor = next
			}
			if finishErr := s.finishRouterRecognition(context.WithoutCancel(workCtx), cursor, len(events), err); err == nil {
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
