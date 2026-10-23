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
	// Address answers are persisted before service records, independent of packet order:
	// service attribution reads the hostname rows, so hostnames and other names are written
	// first and services are attributed and written afterwards.
	var names, services []DeviceNameEvidence
	for _, e := range events {
		for _, n := range extractDeviceNames(e) {
			if n.Kind == "service" {
				services = append(services, n)
			} else {
				names = append(names, n)
			}
		}
	}
	for _, group := range [][]DeviceNameEvidence{names, services} {
		attributed := make([]DeviceNameEvidence, 0, len(group))
		for _, n := range group {
			var err error
			if n, err = s.attributeDeviceName(ctx, n); err != nil {
				return err
			}
			if !received.IsZero() {
				latency := time.Since(received).Milliseconds()
				n.ProcessingLatencyMillis = &latency
			}
			attributed = append(attributed, n)
		}
		if err := s.insertDeviceNamesBatch(ctx, attributed); err != nil {
			return err
		}
	}
	return nil
}

// insertDeviceNamesBatch writes one batch of name evidence in a single statement. One
// autocommitted INSERT per name cost a WAL fsync each (~108 ms on 184, 7.9k calls in a few
// hours) and kept the domain queue full; names are rebuildable evidence, so the batch
// also skips waiting for the fsync.
func (s *PostgresStore) insertDeviceNamesBatch(ctx context.Context, names []DeviceNameEvidence) error {
	if len(names) == 0 {
		return nil
	}
	type row struct {
		SensorID   string          `json:"sensor_id"`
		EventID    string          `json:"event_id"`
		Source     string          `json:"source"`
		Value      string          `json:"value"`
		EndpointID string          `json:"endpoint_id"`
		ObservedAt time.Time       `json:"observed_at"`
		Evidence   json.RawMessage `json:"evidence"`
	}
	latest := map[[4]string]row{}
	for _, n := range names {
		raw, err := json.Marshal(n)
		if err != nil {
			return err
		}
		// ON CONFLICT cannot touch the same row twice in one statement; keep the last.
		latest[[4]string{n.SensorID, n.EventID, n.Source, n.Value}] = row{n.SensorID, n.EventID, n.Source, n.Value, n.EndpointID, n.ObservedAt, raw}
	}
	rows := make([]row, 0, len(latest))
	for _, r := range latest {
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		return a.SensorID+"\x00"+a.EventID+"\x00"+a.Source+"\x00"+a.Value < b.SensorID+"\x00"+b.EventID+"\x00"+b.Source+"\x00"+b.Value
	})
	body, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL synchronous_commit = off`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO device_name_evidence(sensor_id,event_id,source,value,endpoint_id,observed_at,evidence)
 SELECT r.sensor_id,r.event_id,r.source,r.value,r.endpoint_id,r.observed_at,r.evidence
 FROM jsonb_to_recordset($1::jsonb) r(sensor_id text,event_id text,source text,value text,endpoint_id text,observed_at timestamptz,evidence jsonb)
 ON CONFLICT(sensor_id,event_id,source,value) DO UPDATE SET endpoint_id=excluded.endpoint_id,evidence=jsonb_set(excluded.evidence,'{processing_latency_ms}',coalesce(nullif(device_name_evidence.evidence->'processing_latency_ms','null'::jsonb),excluded.evidence->'processing_latency_ms','null'::jsonb)),processed_at=now()`, body); err != nil {
		return err
	}
	return tx.Commit()
}

// Seek one latest row per name stream. Strict key advancement preserves historical
// names without visiting every repeated announcement; both seeks honor as-of time.
const deviceNamesReadSQL = `SELECT n.endpoint_id,n.evidence, CASE WHEN n.source='mdns_hostname' AND n.observed_at > $2::timestamptz-interval '7 days' AND (n.evidence->>'valid_until')::timestamptz > $2 THEN (SELECT min(l.observed_at) FROM device_address_leases l WHERE l.sensor_id=n.sensor_id AND l.campus_id=coalesce(n.evidence->>'campus_id','') AND host(l.ip)=n.evidence->>'address' AND l.observed_at>n.observed_at AND ((l.action='ack' AND l.endpoint_id<>n.endpoint_id) OR (l.action='stop' AND l.endpoint_id=n.endpoint_id))) END FROM (SELECT DISTINCT unnest($1::text[]) AS endpoint_id) requested
 CROSS JOIN LATERAL (
 WITH RECURSIVE streams AS (
  (SELECT endpoint_id,sensor_id,source,lower(value) AS value_key,coalesce(evidence->>'address','') AS address_key,observed_at,event_id,evidence
   FROM device_name_evidence WHERE endpoint_id=requested.endpoint_id AND observed_at <= $2
   ORDER BY source,lower(value),sensor_id,coalesce(evidence->>'address',''),observed_at DESC,event_id DESC LIMIT 1)
  UNION ALL
  SELECT next.* FROM streams p CROSS JOIN LATERAL (
   SELECT endpoint_id,sensor_id,source,lower(value) AS value_key,coalesce(evidence->>'address','') AS address_key,observed_at,event_id,evidence
   FROM device_name_evidence WHERE endpoint_id=requested.endpoint_id AND observed_at <= $2
    AND (source,lower(value),sensor_id,coalesce(evidence->>'address','')) > (p.source,p.value_key,p.sensor_id,p.address_key)
   ORDER BY source,lower(value),sensor_id,coalesce(evidence->>'address',''),observed_at DESC,event_id DESC LIMIT 1
  ) next
 ) SELECT * FROM streams
 ) n`

func (s *PostgresStore) DeviceNames(ctx context.Context, ids []string, now time.Time) (map[string]*DeviceName, error) {
	out := map[string]*DeviceName{}
	evidence := map[string][]DeviceNameEvidence{}
	rows, err := s.db.QueryContext(ctx, deviceNamesReadSQL, ids, now)
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
	// A DHCP batch retries only the names its sensors and addresses can now resolve; the
	// unattributed backlog belongs to the periodic pass alone. Mixing both made every DHCP
	// batch re-walk the backlog inside the domain queue, which kept that queue full.
	query := `SELECT evidence FROM device_name_evidence WHERE source IN ('mdns_hostname','mdns_service') AND observed_at>=now()-interval '7 days' AND sensor_id=ANY($1::text[]) AND (source='mdns_service' OR evidence->>'address'=ANY($2::text[])) ORDER BY processed_at,event_id LIMIT 100`
	args := []any{sensors, ips}
	if len(events) == 0 {
		// The periodic pass stays inside the partial index device_name_retry_due.
		query = `SELECT evidence FROM device_name_evidence WHERE source IN ('mdns_hostname','mdns_service') AND endpoint_id='' AND retry_after<=now() AND observed_at>=now()-interval '7 days' ORDER BY retry_after,processed_at,event_id LIMIT 100`
		args = nil
	} else if len(sensors) == 0 {
		return nil
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
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
	// Attribute until the budget is nearly spent, then write every result in one statement.
	// A pass that runs out of time records what it finished instead of failing as a whole;
	// the rest stays due and the next pass continues from it.
	deadline, bounded := ctx.Deadline()
	done := make([]DeviceNameEvidence, 0, len(pending))
	for _, n := range pending {
		if bounded && time.Until(deadline) < deviceNameRetryReserve {
			break
		}
		attributed, attrErr := s.attributeDeviceName(ctx, n)
		if attrErr != nil {
			if ctx.Err() != nil {
				break
			}
			return attrErr
		}
		done = append(done, attributed)
	}
	if len(done) == 0 {
		return nil
	}
	type row struct {
		SensorID   string          `json:"sensor_id"`
		EventID    string          `json:"event_id"`
		Source     string          `json:"source"`
		Value      string          `json:"value"`
		EndpointID string          `json:"endpoint_id"`
		Evidence   json.RawMessage `json:"evidence"`
	}
	rowsJSON := make([]row, 0, len(done))
	for _, n := range done {
		raw, marshalErr := json.Marshal(n)
		if marshalErr != nil {
			return marshalErr
		}
		rowsJSON = append(rowsJSON, row{n.SensorID, n.EventID, n.Source, n.Value, n.EndpointID, raw})
	}
	body, err := json.Marshal(rowsJSON)
	if err != nil {
		return err
	}
	write, cancel := context.WithTimeout(context.WithoutCancel(ctx), deviceNameRetryReserve)
	defer cancel()
	_, err = s.db.ExecContext(write, `UPDATE device_name_evidence d SET endpoint_id=r.endpoint_id,evidence=r.evidence,processed_at=now(),
 retry_attempts=CASE WHEN r.endpoint_id='' THEN d.retry_attempts+1 ELSE 0 END,
 retry_after=CASE WHEN r.endpoint_id='' THEN now()+make_interval(secs=>least(21600,60*power(2,least(d.retry_attempts,9)))) ELSE '-infinity' END
 FROM jsonb_to_recordset($1::jsonb) r(sensor_id text,event_id text,source text,value text,endpoint_id text,evidence jsonb)
 WHERE d.sensor_id=r.sensor_id AND d.event_id=r.event_id AND d.source=r.source AND d.value=r.value`, body)
	return err
}

// deviceNameRetryReserve is the time kept back from a retry pass for its single write.
const deviceNameRetryReserve = 2 * time.Second
