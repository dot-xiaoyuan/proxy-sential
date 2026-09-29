package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"proxy-sentinel/internal/normalized"
	"sort"
	"time"
)

func (s *PostgresStore) ProcessDeviceNames(ctx context.Context, events []normalized.Event) error {
	return s.processDeviceNamesReceived(ctx, events, time.Time{})
}
func (s *PostgresStore) processDeviceNamesReceived(ctx context.Context, events []normalized.Event, received time.Time) error {
	// Address answers are persisted before service records, independent of packet order.
	ordered := append([]normalized.Event(nil), events...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return stringFromMap(ordered[i].Payload, "record_type") != "SRV" && stringFromMap(ordered[j].Payload, "record_type") == "SRV"
	})
	for _, e := range ordered {
		for _, n := range extractDeviceNames(e) {
			var err error
			n, err = s.attributeDeviceName(ctx, n)
			if err != nil {
				return err
			}
			if !received.IsZero() {
				latency := time.Since(received).Milliseconds()
				n.ProcessingLatencyMillis = &latency
			}
			raw, err := json.Marshal(n)
			if err != nil {
				return err
			}
			_, err = s.db.ExecContext(ctx, `INSERT INTO device_name_evidence(sensor_id,event_id,source,value,endpoint_id,observed_at,evidence) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(sensor_id,event_id,source,value) DO UPDATE SET endpoint_id=excluded.endpoint_id,evidence=jsonb_set(excluded.evidence,'{processing_latency_ms}',coalesce(nullif(device_name_evidence.evidence->'processing_latency_ms','null'::jsonb),excluded.evidence->'processing_latency_ms','null'::jsonb)),processed_at=now()`, n.SensorID, n.EventID, n.Source, n.Value, n.EndpointID, n.ObservedAt, raw)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *PostgresStore) DeviceNames(ctx context.Context, ids []string, now time.Time) (map[string]*DeviceName, error) {
	out := map[string]*DeviceName{}
	evidence := map[string][]DeviceNameEvidence{}
	rows, err := s.db.QueryContext(ctx, `SELECT n.endpoint_id,n.evidence, CASE WHEN n.source='mdns_hostname' THEN (SELECT min(l.observed_at) FROM device_address_leases l WHERE l.sensor_id=n.sensor_id AND l.campus_id=coalesce(n.evidence->>'campus_id','') AND host(l.ip)=n.evidence->>'address' AND l.observed_at>n.observed_at AND ((l.action='ack' AND l.endpoint_id<>n.endpoint_id) OR (l.action='stop' AND l.endpoint_id=n.endpoint_id))) END FROM (SELECT DISTINCT ON (endpoint_id,source,lower(value),sensor_id,coalesce(evidence->>'address','')) endpoint_id,sensor_id,source,observed_at,evidence FROM device_name_evidence WHERE endpoint_id=ANY($1::text[]) AND observed_at <= $2 ORDER BY endpoint_id,source,lower(value),sensor_id,coalesce(evidence->>'address',''),observed_at DESC,event_id DESC) n`, ids, now)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		var raw []byte
		var n DeviceNameEvidence
		var cutoff sql.NullTime
		if err = rows.Scan(&id, &raw, &cutoff); err != nil {
			rows.Close()
			return nil, err
		}
		if err = json.Unmarshal(raw, &n); err != nil {
			rows.Close()
			return nil, err
		}
		if cutoff.Valid && cutoff.Time.Before(n.ValidUntil) {
			n.ValidUntil = cutoff.Time
		}
		evidence[id] = append(evidence[id], n)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	notes := map[string]string{}
	rows, err = s.db.QueryContext(ctx, `SELECT endpoint_id,value FROM device_name_notes WHERE endpoint_id=ANY($1::text[])`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, v string
		if err = rows.Scan(&id, &v); err != nil {
			rows.Close()
			return nil, err
		}
		notes[id] = v
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		out[id] = selectDeviceName(evidence[id], notes[id], now)
	}
	return out, nil
}
func (s *PostgresStore) UpdateDeviceNameNote(ctx context.Context, id, value, actor string) error {
	if normalizeDeviceName(value) != value {
		return fmt.Errorf("设备备注须为不含控制字符的有效名称，最长255字符")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists string
	if err = tx.QueryRowContext(ctx, `SELECT endpoint_id FROM endpoint_entities WHERE endpoint_id=$1 FOR UPDATE`, id).Scan(&exists); err != nil {
		return err
	}
	var old string
	if err = tx.QueryRowContext(ctx, `SELECT coalesce((SELECT value FROM device_name_notes WHERE endpoint_id=$1),'')`, id).Scan(&old); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO device_name_notes(endpoint_id,value,updated_by) VALUES($1,$2,$3) ON CONFLICT(endpoint_id) DO UPDATE SET value=excluded.value,updated_by=excluded.updated_by,updated_at=now()`, id, value, actor); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO device_name_note_audit(endpoint_id,old_value,new_value,actor) VALUES($1,$2,$3,$4)`, id, old, value, actor); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *DBStore) UpdateDeviceNameNote(ctx context.Context, id, value, actor string) error {
	return s.pg.UpdateDeviceNameNote(ctx, id, value, actor)
}

type DeviceNameEvidencePage struct {
	Items []DeviceNameEvidence `json:"items"`
	Total int                  `json:"total"`
}

func (s *PostgresStore) ListDeviceNameEvidence(ctx context.Context, id string, limit, offset int) (DeviceNameEvidencePage, error) {
	out := DeviceNameEvidencePage{Items: []DeviceNameEvidence{}}
	if limit < 1 || limit > 200 || offset < 0 {
		return out, fmt.Errorf("invalid pagination")
	}
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM device_name_evidence WHERE endpoint_id=$1`, id).Scan(&out.Total); err != nil {
		return out, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT evidence FROM device_name_evidence WHERE endpoint_id=$1 ORDER BY observed_at DESC,event_id DESC,source,value LIMIT $2 OFFSET $3`, id, limit, offset)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var n DeviceNameEvidence
		if err = rows.Scan(&raw); err != nil {
			return out, err
		}
		if err = json.Unmarshal(raw, &n); err != nil {
			return out, err
		}
		out.Items = append(out.Items, n)
	}
	return out, rows.Err()
}
func (s *DBStore) ListDeviceNameEvidence(ctx context.Context, id string, limit, offset int) (DeviceNameEvidencePage, error) {
	return s.pg.ListDeviceNameEvidence(ctx, id, limit, offset)
}

func (s *PostgresStore) mdnsServiceOwners(ctx context.Context, n DeviceNameEvidence) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT evidence FROM (SELECT DISTINCT ON (coalesce(evidence->>'address','')) evidence FROM device_name_evidence WHERE sensor_id=$1 AND coalesce(evidence->>'campus_id','')=$2 AND source='mdns_hostname' AND lower(value)=lower($3) AND observed_at<=$4 ORDER BY coalesce(evidence->>'address',''),observed_at DESC,event_id DESC) latest`, n.SensorID, n.CampusID, n.ServiceTarget, n.ObservedAt)
	if err != nil {
		return nil, err
	}
	addresses := []DeviceNameEvidence{}
	for rows.Next() {
		var raw []byte
		var a DeviceNameEvidence
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, err
		}
		if err = json.Unmarshal(raw, &a); err != nil {
			rows.Close()
			return nil, err
		}
		addresses = append(addresses, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for _, a := range addresses {
		if !a.ValidUntil.After(n.ObservedAt) {
			continue
		}
		owner, ok, err := s.ResolveDeviceAt(ctx, DomainObservation{IP: a.Address, Timestamp: n.ObservedAt.Format(time.RFC3339Nano), SensorID: n.SensorID, CampusID: n.CampusID})
		if err != nil {
			return nil, err
		}
		if ok && !owner.Conflict && owner.EndpointID == a.EndpointID {
			ids[owner.EndpointID] = true
		}
	}
	out := []string{}
	for id := range ids {
		out = append(out, id)
	}
	return out, nil
}

func (s *PostgresStore) attributeDeviceName(ctx context.Context, n DeviceNameEvidence) (DeviceNameEvidence, error) {
	if n.Source == "mdns_hostname" || n.Kind == "service" {
		n.EndpointID = ""
		n.Attribution = "unresolved"
	}
	if n.Kind == "service" {
		candidates, err := s.mdnsServiceOwners(ctx, n)
		if err != nil {
			return n, err
		}
		if len(candidates) == 1 {
			n.EndpointID = candidates[0]
			n.Attribution = "mdns_target_address"
		} else if len(candidates) > 1 {
			n.Attribution = "conflict"
		}
	}
	if n.Source == "mdns_hostname" {
		owner, ok, err := s.ResolveDeviceAt(ctx, DomainObservation{IP: n.Address, Timestamp: n.ObservedAt.Format(time.RFC3339Nano), SensorID: n.SensorID, CampusID: n.CampusID})
		if err != nil {
			return n, err
		}
		if ok && !owner.Conflict {
			n.EndpointID = owner.EndpointID
			n.Attribution = "event_time_lease"
			var until time.Time
			err = s.db.QueryRowContext(ctx, `SELECT min(valid_until) FROM device_address_leases WHERE sensor_id=$1 AND campus_id=$2 AND ip=$3::inet AND endpoint_id=$4 AND action='ack' AND observed_at<=$5 AND valid_until>$5`, n.SensorID, n.CampusID, n.Address, n.EndpointID, n.ObservedAt).Scan(&until)
			if err != nil {
				return n, err
			}
			if until.Before(n.ValidUntil) {
				n.ValidUntil = until
			}
		} else if owner.Conflict {
			n.Attribution = "conflict"
		}
	}
	return n, nil
}

// A bounded retry pass repairs delayed address answers and identity updates.
func (s *PostgresStore) RetryDeviceNames(ctx context.Context, events []normalized.Event) error {
	sensors, ips := []string{}, []string{}
	for _, e := range events {
		if stringFromMap(e.Payload, "origin") == "dhcp" {
			sensors = append(sensors, stringFromMap(e.Observer, "sensor_id"))
			ips = append(ips, stringFromMap(e.Subject, "ip"))
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT evidence FROM device_name_evidence WHERE source IN ('mdns_hostname','mdns_service') AND observed_at>=now()-interval '7 days' AND (endpoint_id='' OR (sensor_id=ANY($1::text[]) AND (source='mdns_service' OR evidence->>'address'=ANY($2::text[])))) ORDER BY processed_at,event_id LIMIT 100`, sensors, ips)
	if err != nil {
		return err
	}
	pending := []DeviceNameEvidence{}
	for rows.Next() {
		var raw []byte
		var n DeviceNameEvidence
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		if err = json.Unmarshal(raw, &n); err != nil {
			rows.Close()
			return err
		}
		pending = append(pending, n)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, n := range pending {
		n, err = s.attributeDeviceName(ctx, n)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(n)
		if err != nil {
			return err
		}
		if _, err = s.db.ExecContext(ctx, `UPDATE device_name_evidence SET endpoint_id=$1,evidence=$2,processed_at=now() WHERE sensor_id=$3 AND event_id=$4 AND source=$5 AND value=$6`, n.EndpointID, raw, n.SensorID, n.EventID, n.Source, n.Value); err != nil {
			return err
		}
	}
	return nil
}
