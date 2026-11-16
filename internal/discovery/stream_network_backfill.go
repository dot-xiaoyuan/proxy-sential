package discovery

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
)

var ErrStreamNetworkBackfillBusy = errors.New("network backfill yielded to realtime projection")

func streamNetworkBackfillShouldYield(err error) bool {
	if errors.Is(err, ErrStreamNetworkBackfillBusy) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var pgErr interface{ SQLState() string }
	return errors.As(err, &pgErr) && (pgErr.SQLState() == "55P03" || pgErr.SQLState() == "57014")
}

// The 512 KiB step limit covers only the narrow key scan. A bounded per-device
// rebuild still decodes at most 257 fact documents, with its own byte ceiling.
const maxStreamNetworkRebuildBytes = 4 * 1024 * 1024

// StreamNetworkBackfillLimits bounds one explicitly invoked historical step.
// A step never schedules its successor or changes a source ingestion cursor.
type StreamNetworkBackfillLimits struct {
	MaxRows    int
	MaxDevices int
	MaxBytes   int
}

func (l StreamNetworkBackfillLimits) bounded() StreamNetworkBackfillLimits {
	if l.MaxRows <= 0 || l.MaxRows > 500 {
		l.MaxRows = 500
	}
	if l.MaxDevices <= 0 || l.MaxDevices > 1 {
		l.MaxDevices = 1
	}
	if l.MaxBytes <= 0 || l.MaxBytes > 512*1024 {
		l.MaxBytes = 512 * 1024
	}
	return l
}

type StreamNetworkBackfillStatus struct {
	Epoch            string `json:"epoch"`
	Status           string `json:"status"`
	CursorDevice     string `json:"cursor_device_key"`
	CursorFact       string `json:"cursor_fact_key"`
	ScannedRows      int64  `json:"scanned_rows"`
	ProjectedDevices int64  `json:"projected_devices"`
	UnresolvedGaps   int64  `json:"unresolved_gaps"`
	LastError        string `json:"last_error,omitempty"`
}

type streamNetworkBackfillFact struct {
	Device   string
	Fact     string
	Type     string
	Protocol string
}

type streamNetworkBackfillSelection struct {
	CursorDevice string
	CursorFact   string
	Scanned      int
	Devices      []string
	FactByDevice map[string]string
	Complete     bool
}

// The cursor stops before the first row that would exceed a bound. Fetching
// fewer than MaxRows proves the fixed snapshot was exhausted only when every
// fetched row was consumed.
func selectStreamNetworkBackfillPage(rows []streamNetworkBackfillFact, fetched int, limits StreamNetworkBackfillLimits) (streamNetworkBackfillSelection, error) {
	limits = limits.bounded()
	selected := streamNetworkBackfillSelection{FactByDevice: map[string]string{}}
	usedBytes := 0
	for _, row := range rows {
		rowBytes := len(row.Device) + len(row.Fact) + len(row.Type) + len(row.Protocol) + 32
		if selected.Scanned > 0 && usedBytes+rowBytes > limits.MaxBytes {
			break
		}
		if rowBytes > limits.MaxBytes {
			return selected, fmt.Errorf("network backfill fact key exceeds byte budget: device=%q fact=%q", row.Device, row.Fact)
		}
		kind := row.Type
		if row.Protocol == "active" || !isStreamNetworkType(kind) {
			kind = ""
		}
		if kind != "" {
			if _, exists := selected.FactByDevice[row.Device]; !exists {
				if len(selected.Devices) >= limits.MaxDevices {
					break
				}
				selected.Devices = append(selected.Devices, row.Device)
				selected.FactByDevice[row.Device] = row.Fact
			}
		}
		selected.CursorDevice, selected.CursorFact = row.Device, row.Fact
		selected.Scanned++
		usedBytes += rowBytes
	}
	selected.Complete = selected.Scanned == fetched && fetched < limits.MaxRows
	return selected, nil
}

func isStreamNetworkType(kind string) bool {
	switch kind {
	case "router", "gateway", "access_point", "switch", "firewall":
		return true
	}
	return false
}

// Resume creates an immutable-epoch checkpoint or retries the same cursor.
// A completed epoch is never reopened; new facts use normal live projection.
func (p StreamDiscoveryProjector) ResumeStreamNetworkBackfill(ctx context.Context, epoch string) (StreamNetworkBackfillStatus, error) {
	if p.DB == nil || strings.TrimSpace(epoch) == "" {
		return StreamNetworkBackfillStatus{}, errors.New("network backfill needs DB and fixed epoch")
	}
	var active bool
	if err := p.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM stream_source_cutovers WHERE epoch=$1 AND state='active')`, epoch).Scan(&active); err != nil {
		return StreamNetworkBackfillStatus{}, err
	}
	if !active {
		return StreamNetworkBackfillStatus{}, fmt.Errorf("network backfill epoch %q is not active", epoch)
	}
	_, err := p.DB.ExecContext(ctx, `INSERT INTO stream_discovery_network_backfill_progress(epoch,status) VALUES($1,'running')
 ON CONFLICT(epoch) DO UPDATE SET status='running',last_error='',updated_at=now()
 WHERE stream_discovery_network_backfill_progress.status<>'complete'`, epoch)
	if err != nil {
		return StreamNetworkBackfillStatus{}, err
	}
	return p.StreamNetworkBackfillStatus(ctx, epoch)
}

func (p StreamDiscoveryProjector) PauseStreamNetworkBackfill(ctx context.Context, epoch string) (StreamNetworkBackfillStatus, error) {
	if p.DB == nil || strings.TrimSpace(epoch) == "" {
		return StreamNetworkBackfillStatus{}, errors.New("network backfill needs DB and fixed epoch")
	}
	_, err := p.DB.ExecContext(ctx, `UPDATE stream_discovery_network_backfill_progress SET status='paused',updated_at=now()
 WHERE epoch=$1 AND status<>'complete'`, epoch)
	if err != nil {
		return StreamNetworkBackfillStatus{}, err
	}
	return p.StreamNetworkBackfillStatus(ctx, epoch)
}

func (p StreamDiscoveryProjector) StreamNetworkBackfillStatus(ctx context.Context, epoch string) (StreamNetworkBackfillStatus, error) {
	if p.DB == nil || strings.TrimSpace(epoch) == "" {
		return StreamNetworkBackfillStatus{}, errors.New("network backfill needs DB and fixed epoch")
	}
	var s StreamNetworkBackfillStatus
	err := p.DB.QueryRowContext(ctx, `SELECT p.epoch,p.status,p.cursor_device_key,p.cursor_fact_key,p.scanned_rows,p.projected_devices,p.last_error,
 (SELECT count(*) FROM stream_discovery_network_backfill_gaps g WHERE g.epoch=p.epoch AND g.resolved_at IS NULL)
 FROM stream_discovery_network_backfill_progress p WHERE p.epoch=$1`, epoch).
		Scan(&s.Epoch, &s.Status, &s.CursorDevice, &s.CursorFact, &s.ScannedRows, &s.ProjectedDevices, &s.LastError, &s.UnresolvedGaps)
	return s, err
}

// BackfillStreamNetworkStateStep executes one transaction and exits. Operators
// can pause/resume between steps while live projection always gets device and
// result-version advisory locks first.
func (p StreamDiscoveryProjector) BackfillStreamNetworkStateStep(ctx context.Context, epoch string, limits StreamNetworkBackfillLimits) (StreamNetworkBackfillStatus, error) {
	return p.backfillStreamNetworkStateStep(ctx, epoch, limits, backfillStreamNetworkDeviceStates)
}

func (p StreamDiscoveryProjector) backfillStreamNetworkStateStep(ctx context.Context, epoch string, limits StreamNetworkBackfillLimits, project func(context.Context, *sql.Tx, string, []string) error) (StreamNetworkBackfillStatus, error) {
	if p.DB == nil || strings.TrimSpace(epoch) == "" || project == nil {
		return StreamNetworkBackfillStatus{}, errors.New("network backfill needs DB, fixed epoch and projector")
	}
	// Low-priority historical work never holds a device or result-version lock
	// beyond this entire short transaction, including the commit/WAL flush.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	limits = limits.bounded()
	tx, err := p.DB.BeginTx(ctx, nil)
	if err != nil {
		return StreamNetworkBackfillStatus{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout='100ms'`); err != nil {
		return StreamNetworkBackfillStatus{}, err
	}
	if _, err = tx.ExecContext(ctx, `SET LOCAL statement_timeout='10s'`); err != nil {
		return StreamNetworkBackfillStatus{}, err
	}
	s := StreamNetworkBackfillStatus{Epoch: epoch}
	var active bool
	err = tx.QueryRowContext(ctx, `SELECT p.status,p.cursor_device_key,p.cursor_fact_key,p.scanned_rows,p.projected_devices,
 EXISTS(SELECT 1 FROM stream_source_cutovers c WHERE c.epoch=p.epoch AND c.state='active')
 FROM stream_discovery_network_backfill_progress p WHERE p.epoch=$1 FOR UPDATE OF p NOWAIT`, epoch).
		Scan(&s.Status, &s.CursorDevice, &s.CursorFact, &s.ScannedRows, &s.ProjectedDevices, &active)
	if err != nil {
		return s, err
	}
	if !active {
		return s, fmt.Errorf("network backfill epoch %q is not active", epoch)
	}
	if s.Status != "running" {
		return s, tx.Commit()
	}
	rows, err := tx.QueryContext(ctx, `SELECT device_key,fact_key,device_type,protocol FROM stream_discovery_facts
 WHERE epoch=$1 AND (device_key,fact_key)>($2,$3)
 ORDER BY device_key,fact_key LIMIT $4`, epoch, s.CursorDevice, s.CursorFact, limits.MaxRows)
	if err != nil {
		return s, err
	}
	facts := make([]streamNetworkBackfillFact, 0, limits.MaxRows)
	for rows.Next() {
		var fact streamNetworkBackfillFact
		if err = rows.Scan(&fact.Device, &fact.Fact, &fact.Type, &fact.Protocol); err != nil {
			break
		}
		facts = append(facts, fact)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return s, err
	}
	selected, err := selectStreamNetworkBackfillPage(facts, len(facts), limits)
	if err != nil {
		_ = tx.Rollback()
		if selected.Scanned < len(facts) {
			fact := facts[selected.Scanned]
			if recordErr := p.recordStreamNetworkBackfillGap(epoch, fact.Device, fact.Fact, err); recordErr != nil {
				return s, fmt.Errorf("%w; failed to persist backfill gap: %v", err, recordErr)
			}
		}
		return s, err
	}
	toProject := selected.Devices
	if len(toProject) > 0 {
		seen := map[string]bool{}
		processed, queryErr := tx.QueryContext(ctx, `SELECT device_key FROM stream_discovery_network_backfill_devices
 WHERE epoch=$1 AND device_key=ANY($2::text[])`, epoch, toProject)
		if queryErr != nil {
			return s, queryErr
		}
		for processed.Next() {
			var key string
			if err = processed.Scan(&key); err != nil {
				break
			}
			seen[key] = true
		}
		if err == nil {
			err = processed.Err()
		}
		processed.Close()
		if err != nil {
			return s, err
		}
		toProject = make([]string, 0, len(selected.Devices))
		for _, key := range selected.Devices {
			if !seen[key] {
				toProject = append(toProject, key)
			}
		}
	}
	sort.Strings(toProject)
	if len(toProject) > 0 {
		if err := project(ctx, tx, epoch, toProject); err != nil {
			_ = tx.Rollback()
			if streamNetworkBackfillShouldYield(err) {
				return s, err
			}
			key := toProject[0]
			var deviceErr *streamNetworkBackfillDeviceError
			if errors.As(err, &deviceErr) {
				key = deviceErr.Device
			}
			if recordErr := p.recordStreamNetworkBackfillGap(epoch, key, selected.FactByDevice[key], err); recordErr != nil {
				return s, fmt.Errorf("%w; failed to persist backfill gap: %v", err, recordErr)
			}
			return s, err
		}
	}
	if len(toProject) > 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO stream_discovery_network_backfill_devices(epoch,device_key)
	SELECT $1,v.device_key FROM unnest($2::text[]) AS v(device_key) ON CONFLICT DO NOTHING`, epoch, toProject); err != nil {
			return s, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE stream_discovery_network_backfill_gaps SET resolved_at=now()
 WHERE epoch=$1 AND device_key=ANY($2::text[]) AND resolved_at IS NULL`, epoch, toProject); err != nil {
			return s, err
		}
	}
	status := "running"
	if selected.Complete {
		status = "complete"
	}
	cursorDevice, cursorFact := s.CursorDevice, s.CursorFact
	if selected.Scanned > 0 {
		cursorDevice, cursorFact = selected.CursorDevice, selected.CursorFact
	}
	if _, err := tx.ExecContext(ctx, `UPDATE stream_discovery_network_backfill_progress
 SET cursor_device_key=$2,cursor_fact_key=$3,scanned_rows=scanned_rows+$4,projected_devices=projected_devices+$5,
 status=$6,last_error='',updated_at=now(),completed_at=CASE WHEN $6='complete' THEN now() ELSE NULL END
 WHERE epoch=$1`, epoch, cursorDevice, cursorFact, selected.Scanned, len(toProject), status); err != nil {
		return s, err
	}
	if err := tx.Commit(); err != nil {
		return s, err
	}
	s.Status, s.CursorDevice, s.CursorFact = status, cursorDevice, cursorFact
	s.ScannedRows += int64(selected.Scanned)
	s.ProjectedDevices += int64(len(toProject))
	return s, nil
}

func (p StreamDiscoveryProjector) recordStreamNetworkBackfillGap(epoch, device, fact string, cause error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tx, err := p.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	reason := cause.Error()
	if len(reason) > 1000 {
		reason = reason[:1000]
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO stream_discovery_network_backfill_gaps(epoch,device_key,fact_key,reason)
 VALUES($1,$2,$3,$4) ON CONFLICT(epoch,device_key,fact_key) DO UPDATE SET
 reason=EXCLUDED.reason,attempts=stream_discovery_network_backfill_gaps.attempts+1,last_failed_at=now(),resolved_at=NULL`, epoch, device, fact, reason); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE stream_discovery_network_backfill_progress SET status='failed',last_error=$2,updated_at=now()
 WHERE epoch=$1 AND status='running'`, epoch, reason); err != nil {
		return err
	}
	return tx.Commit()
}

// This repair uses the normal bounded state builder, then writes only its
// network-type document fields and sparse lookup. No fact, source receipt,
// primary state field or source cursor is rewritten.
type streamNetworkBackfillDeviceError struct {
	Device string
	Err    error
}

func (e *streamNetworkBackfillDeviceError) Error() string { return e.Err.Error() }
func (e *streamNetworkBackfillDeviceError) Unwrap() error { return e.Err }

type streamNetworkBackfillPlan struct {
	Key        string
	Scope      string
	Version    int64
	State      streamDiscoveryState
	NetworkDoc map[string]any
	Watermark  []streamNetworkBackfillWatermark
	Changed    bool
}

type streamNetworkBackfillWatermark struct {
	Device, Fact, Type, Protocol, SemanticHash, Event, VisibleEvent string
	Revision                                                        int64
	FirstObserved, Observed, ValidUntil                             string
	Withdrawn                                                       bool
}

func streamNetworkFactWatermark(f streamDiscoveryFact) streamNetworkBackfillWatermark {
	return streamNetworkBackfillWatermark{Device: f.Device, Fact: f.Key, Type: f.DeviceType, Protocol: f.Protocol,
		SemanticHash: f.SemanticHash, Event: f.Event, VisibleEvent: f.EvidenceEvent, Revision: f.Revision,
		FirstObserved: f.FirstObserved.UTC().Format(time.RFC3339Nano), Observed: f.Observed.UTC().Format(time.RFC3339Nano),
		ValidUntil: f.ValidUntil.UTC().Format(time.RFC3339Nano), Withdrawn: f.Withdrawn}
}

func sortedStreamNetworkFactWatermarks(facts []streamDiscoveryFact) []streamNetworkBackfillWatermark {
	result := make([]streamNetworkBackfillWatermark, 0)
	for _, fact := range facts {
		if passiveStreamNetworkType(fact) != "" {
			result = append(result, streamNetworkFactWatermark(fact))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Fact < result[j].Fact })
	return result
}

func backfillStreamNetworkDeviceStates(ctx context.Context, tx *sql.Tx, epoch string, keys []string) error {
	if len(keys) != 1 {
		return errors.New("network backfill requires exactly one device key")
	}
	plans := make([]streamNetworkBackfillPlan, 0, len(keys))
	for _, key := range keys {
		fail := func(err error) error { return &streamNetworkBackfillDeviceError{Device: key, Err: err} }
		var scope string
		var version int64
		var raw []byte
		if err := tx.QueryRowContext(ctx, `SELECT scope_id,result_version,document FROM stream_discovery_device_state
 WHERE epoch=$1 AND device_key=$2`, epoch, key).Scan(&scope, &version, &raw); err != nil {
			return fail(fmt.Errorf("network backfill current state %s: %w", key, err))
		}
		oldDoc := map[string]any{}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&oldDoc); err != nil {
			return fail(err)
		}
		rows, err := tx.QueryContext(ctx, `SELECT to_jsonb(f) FROM stream_discovery_facts f
 WHERE epoch=$1 AND device_key=$2 AND scope_id=$3
 ORDER BY observed_at DESC,event_key DESC LIMIT 257`, epoch, key, scope)
		if err != nil {
			return fail(err)
		}
		facts := make([]streamDiscoveryFact, 0, maxStreamFactsPerDevice+1)
		factBytes := 0
		for rows.Next() {
			var factRaw []byte
			if err = rows.Scan(&factRaw); err != nil {
				break
			}
			factBytes += len(factRaw)
			if factBytes > maxStreamNetworkRebuildBytes {
				err = fmt.Errorf("network backfill device %s exceeds %d fact bytes; bounded repair required", key, maxStreamNetworkRebuildBytes)
				break
			}
			var fact streamDiscoveryFact
			if err = json.Unmarshal(factRaw, &fact); err != nil {
				break
			}
			facts = append(facts, fact)
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return fail(err)
		}
		if len(facts) == 0 || len(facts) > maxStreamFactsPerDevice {
			return fail(fmt.Errorf("network backfill device %s has %d visible-scope facts; bounded repair required", key, len(facts)))
		}
		state, err := buildStreamDiscoveryState(epoch, key, facts, nil, time.Now().UTC())
		if err != nil {
			return fail(err)
		}
		networkDoc := streamNetworkDocument(state.Document)
		plans = append(plans, streamNetworkBackfillPlan{Key: key, Scope: scope, Version: version, State: state,
			NetworkDoc: networkDoc, Watermark: sortedStreamNetworkFactWatermarks(facts),
			Changed: !streamDiscoveryDocumentsEqual(streamNetworkDocument(oldDoc), networkDoc)})
	}
	// The full-document reads and type derivation above do not hold any live
	// projection lock. Bound every short validation/write statement below.
	if _, err := tx.ExecContext(ctx, `SET LOCAL statement_timeout='100ms'`); err != nil {
		return err
	}
	lockedKeys := append([]string(nil), keys...)
	sort.Strings(lockedKeys)
	for _, key := range lockedKeys {
		var locked bool
		if err := tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,9184))`, key).Scan(&locked); err != nil {
			return err
		}
		if !locked {
			return ErrStreamNetworkBackfillBusy
		}
	}
	if err := validateStreamNetworkBackfillPlans(ctx, tx, epoch, plans); err != nil {
		return err
	}
	// All bounded device reads/builds happen before the global result-version
	// lock. This lock then covers only the short derived writes and checkpoint.
	for _, plan := range plans {
		if plan.Changed {
			var locked bool
			if err := tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(9184,213)`).Scan(&locked); err != nil {
				return err
			}
			if !locked {
				return ErrStreamNetworkBackfillBusy
			}
			break
		}
	}
	for _, plan := range plans {
		fail := func(err error) error { return &streamNetworkBackfillDeviceError{Device: plan.Key, Err: err} }
		var err error
		if plan.Changed {
			networkRaw, err := json.Marshal(plan.NetworkDoc)
			if err != nil {
				return fail(err)
			}
			result, err := tx.ExecContext(ctx, `UPDATE stream_discovery_device_state SET
 document=(document - ARRAY['network_device_type','last_network_device_type','network_type_status','network_type_first_seen',
 'network_type_last_seen','network_type_valid_until','network_type_evidence_ids','network_type_reason']) || $3::jsonb,
 result_version=nextval('stream_discovery_result_version'),updated_at=now()
 WHERE epoch=$1 AND device_key=$2`, epoch, plan.Key, networkRaw)
			if err != nil {
				return fail(err)
			}
			if count, err := result.RowsAffected(); err != nil || count != 1 {
				return fail(fmt.Errorf("network backfill current state changed: device=%s rows=%d: %v", plan.Key, count, err))
			}
		}
		state := plan.State
		if state.NetworkTypeStatus == "clue" || state.NetworkTypeStatus == "expired" {
			kind := state.NetworkDeviceType
			if state.NetworkTypeStatus == "expired" {
				kind = state.LastNetworkDeviceType
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO stream_discovery_network_state(epoch,device_key,scope_id,network_device_type,status,type_last_seen,type_valid_until)
 VALUES($1,$2,$3,$4,$5,$6,$7)
 ON CONFLICT(epoch,device_key) DO UPDATE SET scope_id=EXCLUDED.scope_id,network_device_type=EXCLUDED.network_device_type,
 status=EXCLUDED.status,type_last_seen=EXCLUDED.type_last_seen,type_valid_until=EXCLUDED.type_valid_until,updated_at=now()
 WHERE (stream_discovery_network_state.scope_id,stream_discovery_network_state.network_device_type,stream_discovery_network_state.status,
 stream_discovery_network_state.type_last_seen,stream_discovery_network_state.type_valid_until)
 IS DISTINCT FROM (EXCLUDED.scope_id,EXCLUDED.network_device_type,EXCLUDED.status,EXCLUDED.type_last_seen,EXCLUDED.type_valid_until)`, epoch, plan.Key, plan.Scope, kind, state.NetworkTypeStatus, state.NetworkTypeLastSeen, state.NetworkTypeValidUntil)
		} else {
			_, err = tx.ExecContext(ctx, `DELETE FROM stream_discovery_network_state WHERE epoch=$1 AND device_key=$2`, epoch, plan.Key)
		}
		if err != nil {
			return fail(err)
		}
	}
	return nil
}

// A real-time writer changes its device result version in the same transaction
// as any visible network-type update. The narrow fact watermark also detects
// a corrected, withdrawn or late network fact when the visible state is still
// unchanged. Recheck both only after acquiring the same per-device locks.
func validateStreamNetworkBackfillPlans(ctx context.Context, tx *sql.Tx, epoch string, plans []streamNetworkBackfillPlan) error {
	keys := make([]string, 0, len(plans))
	versions := make(map[string]streamNetworkBackfillPlan, len(plans))
	type scopeKey struct {
		Device string `json:"device_key"`
		Scope  string `json:"scope_id"`
	}
	scopes := make([]scopeKey, 0, len(plans))
	for _, plan := range plans {
		keys = append(keys, plan.Key)
		versions[plan.Key] = plan
		scopes = append(scopes, scopeKey{plan.Key, plan.Scope})
	}
	rows, err := tx.QueryContext(ctx, `SELECT device_key,scope_id,result_version FROM stream_discovery_device_state
 WHERE epoch=$1 AND device_key=ANY($2::text[]) FOR UPDATE NOWAIT`, epoch, keys)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for rows.Next() {
		var key, scope string
		var version int64
		if err = rows.Scan(&key, &scope, &version); err != nil {
			break
		}
		plan, ok := versions[key]
		if !ok || seen[key] || scope != plan.Scope || version != plan.Version {
			err = ErrStreamNetworkBackfillBusy
			break
		}
		seen[key] = true
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	if len(seen) != len(plans) {
		return ErrStreamNetworkBackfillBusy
	}
	scopeRaw, err := json.Marshal(scopes)
	if err != nil {
		return err
	}
	rows, err = tx.QueryContext(ctx, `SELECT f.device_key,f.fact_key,f.device_type,f.protocol,f.semantic_hash,f.event_key,f.visible_event_key,
 f.revision,f.first_observed_at,f.observed_at,f.valid_until,f.withdrawn
 FROM jsonb_to_recordset($2::jsonb) AS v(device_key text,scope_id text)
 JOIN LATERAL (
  SELECT f.device_key,f.fact_key,f.device_type,f.protocol,f.semantic_hash,f.event_key,f.visible_event_key,
   f.revision,f.first_observed_at,f.observed_at,f.valid_until,f.withdrawn
  FROM stream_discovery_facts f WHERE f.epoch=$1 AND f.device_key=v.device_key AND f.scope_id=v.scope_id
   AND f.protocol<>'active' AND f.device_type IN ('router','gateway','access_point','switch','firewall')
  ORDER BY f.fact_key LIMIT 257
 ) f ON true ORDER BY f.device_key,f.fact_key LIMIT 258`, epoch, scopeRaw)
	if err != nil {
		return err
	}
	watermarks := map[string][]streamNetworkBackfillWatermark{}
	count := 0
	for rows.Next() {
		var row streamNetworkBackfillWatermark
		var first, observed, valid time.Time
		if err = rows.Scan(&row.Device, &row.Fact, &row.Type, &row.Protocol, &row.SemanticHash, &row.Event, &row.VisibleEvent,
			&row.Revision, &first, &observed, &valid, &row.Withdrawn); err != nil {
			break
		}
		row.FirstObserved, row.Observed, row.ValidUntil = first.UTC().Format(time.RFC3339Nano), observed.UTC().Format(time.RFC3339Nano), valid.UTC().Format(time.RFC3339Nano)
		watermarks[row.Device] = append(watermarks[row.Device], row)
		count++
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	if count > len(plans)*maxStreamFactsPerDevice {
		return ErrStreamNetworkBackfillBusy
	}
	for _, plan := range plans {
		got := watermarks[plan.Key]
		if len(got) != len(plan.Watermark) {
			return ErrStreamNetworkBackfillBusy
		}
		if len(got) > 0 && !reflect.DeepEqual(got, plan.Watermark) {
			return ErrStreamNetworkBackfillBusy
		}
	}
	return nil
}
