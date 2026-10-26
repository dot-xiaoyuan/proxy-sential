package discovery

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/streamlog"
)

var ErrUnsupportedStreamProjection = errors.New("selected stream event has no discovery projector")

// StreamDiscoveryProjector writes only selected discovery facts. The source
// body is never copied into PostgreSQL; all receipts and device changes carry
// an immutable ClickHouse body locator.
type StreamDiscoveryProjector struct{ DB *sql.DB }

// Expiry is a separate bounded maintenance lane. It never scans event bodies
// and serializes with normal projection using the same device locks.
func (p StreamDiscoveryProjector) ExpireStreamDiscoveryStates(ctx context.Context, limit int) (int, error) {
	if p.DB == nil {
		return 0, errors.New("stream discovery expiry needs DB")
	}
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	tx, err := p.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT epoch,device_key FROM stream_discovery_device_state WHERE expires_at<=now() ORDER BY expires_at,epoch,device_key LIMIT $1`, limit)
	if err != nil {
		return 0, err
	}
	groups := map[string][]string{}
	keys := []string{}
	seen := map[string]bool{}
	count := 0
	for rows.Next() {
		var epoch, key string
		if err = rows.Scan(&epoch, &key); err != nil {
			break
		}
		groups[epoch] = append(groups[epoch], key)
		if !seen[key] {
			keys = append(keys, key)
			seen[key] = true
		}
		count++
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return 0, err
	}
	if count == 0 {
		return 0, tx.Commit()
	}
	sort.Strings(keys)
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(device_key,9184)) FROM (SELECT unnest($1::text[]) AS device_key ORDER BY device_key) ordered`, keys); err != nil {
		return 0, err
	}
	epochs := make([]string, 0, len(groups))
	for epoch := range groups {
		epochs = append(epochs, epoch)
	}
	sort.Strings(epochs)
	for _, epoch := range epochs {
		if err := publishStreamDiscoveryStates(ctx, tx, epoch, groups[epoch], nil); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

// Called only after archive, search and projection acknowledgements are all
// durable. Confirmation is distinct from case-time archive hash verification.
func (p StreamDiscoveryProjector) MarkStreamArchiveConfirmed(ctx context.Context, _ string, segment streamlog.Segment) error {
	if p.DB == nil {
		return errors.New("stream discovery archive confirmation needs DB")
	}
	items, err := prepareStreamDiscovery(segment)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return ErrUnsupportedStreamProjection
	}
	raw, err := json.Marshal(streamReceiptList(items))
	if err != nil {
		return err
	}
	result, err := p.DB.ExecContext(ctx, `UPDATE stream_discovery_receipts r
 SET archive_state=CASE WHEN r.archive_state='verified' THEN 'verified' ELSE 'confirmed' END,archive_confirmed_at=coalesce(r.archive_confirmed_at,now())
 FROM stream_discovery_event_keys k
 JOIN jsonb_to_recordset($2::jsonb) AS v(scope_id text,event_key text,content_sha256 text)
 ON k.scope_id=v.scope_id AND k.event_key=v.event_key AND k.content_sha256=v.content_sha256
 WHERE k.epoch=$1 AND r.epoch=k.epoch AND r.scope_id=k.scope_id AND r.event_key=k.event_key
 AND r.accepted_month=k.accepted_month AND r.content_sha256=k.content_sha256`, segment.Epoch, raw)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != int64(len(items)) {
		return fmt.Errorf("stream archive confirmation missing receipt: %w", streamlog.ErrUnconfirmed)
	}
	return nil
}

type streamRiskDirtySubject struct {
	Sensor   string    `json:"sensor_id"`
	Type     string    `json:"subject_type"`
	ID       string    `json:"subject_id"`
	Observed time.Time `json:"observed_at"`
}

// A confirmed stream segment wakes only the subjects it touched. Repeating a
// segment after a crash does not create another dirty generation.
func (p StreamDiscoveryProjector) MarkStreamRiskSubjectsDirty(ctx context.Context, id string, segment streamlog.Segment) error {
	subjects := map[string]streamRiskDirtySubject{}
	for _, event := range segment.Events {
		if !evidence.StreamRiskFeatureEligible(event) {
			continue
		}
		sensor := str(event.Observer, "sensor_id")
		observed, err := time.Parse(time.RFC3339Nano, event.Timestamp)
		if sensor == "" || err != nil {
			return errors.New("risk feature subject lacks sensor or observation time")
		}
		for _, subject := range []streamRiskDirtySubject{{Sensor: sensor, Type: "ip", ID: str(event.Subject, "ip"), Observed: observed.UTC()}, {Sensor: sensor, Type: "account", ID: str(event.Subject, "account_id"), Observed: observed.UTC()}} {
			if subject.ID == "" {
				continue
			}
			key := subject.Sensor + "\x00" + subject.Type + "\x00" + subject.ID
			if prior, found := subjects[key]; !found || subject.Observed.After(prior.Observed) {
				subjects[key] = subject
			}
		}
	}
	if len(subjects) == 0 {
		return nil
	}
	if id == "" || segment.Epoch == "" || segment.AcceptedAt.IsZero() {
		return errors.New("risk feature receipt lacks fixed segment identity")
	}
	body, err := json.Marshal(segment.Events)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	rows := make([]streamRiskDirtySubject, 0, len(subjects))
	for _, subject := range subjects {
		rows = append(rows, subject)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Sensor != rows[j].Sensor {
			return rows[i].Sensor < rows[j].Sensor
		}
		if rows[i].Type != rows[j].Type {
			return rows[i].Type < rows[j].Type
		}
		return rows[i].ID < rows[j].ID
	})
	raw, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	tx, err := p.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	lastSensor := ""
	for _, subject := range rows {
		if subject.Sensor == lastSensor {
			continue
		}
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('stream-risk-fresh-cutover'),hashtext($1))`, subject.Sensor); err != nil {
			return err
		}
		lastSensor = subject.Sensor
	}
	var inserted string
	err = tx.QueryRowContext(ctx, `INSERT INTO risk_feature_segment_receipts(segment_id,segment_sha256,source_epoch,accepted_at)
 VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING segment_id`, id, digest, segment.Epoch, segment.AcceptedAt).Scan(&inserted)
	if errors.Is(err, sql.ErrNoRows) {
		var existing string
		if err := tx.QueryRowContext(ctx, `SELECT segment_sha256 FROM risk_feature_segment_receipts WHERE segment_id=$1`, id).Scan(&existing); err != nil {
			return err
		}
		if existing != digest {
			return streamlog.ErrContentConflict
		}
		return tx.Commit()
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO risk_feature_dirty_subjects(sensor_id,subject_type,subject_id,generation,last_observed_at)
 SELECT r.sensor_id,r.subject_type,r.subject_id,nextval('risk_feature_dirty_generation'),r.observed_at
 FROM jsonb_to_recordset($1::jsonb) AS r(sensor_id text,subject_type text,subject_id text,observed_at timestamptz)
 WHERE NOT EXISTS (SELECT 1 FROM stream_risk_fresh_cutovers c
                   WHERE c.sensor_id=r.sensor_id AND $2::timestamptz<c.accepted_after)
 ON CONFLICT(sensor_id,subject_type,subject_id) DO UPDATE
 SET generation=nextval('risk_feature_dirty_generation'),last_dirty_at=now(),
     last_observed_at=GREATEST(risk_feature_dirty_subjects.last_observed_at,EXCLUDED.last_observed_at)`, raw, segment.AcceptedAt.UTC())
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (p StreamDiscoveryProjector) ReconcileStreamProjection(ctx context.Context, id string, segment streamlog.Segment) error {
	return p.ProjectStreamSegment(ctx, id, segment)
}

func (p StreamDiscoveryProjector) ProjectStreamSegment(ctx context.Context, id string, segment streamlog.Segment) error {
	stage, stageStarted := "validate", time.Now()
	mark := func(next string) {
		if elapsed := time.Since(stageStarted); elapsed >= 100*time.Millisecond {
			log.Printf("stream projection stage segment=%s events=%d stage=%s seconds=%.3f", id, len(segment.Events), stage, elapsed.Seconds())
		}
		stage, stageStarted = next, time.Now()
	}
	defer mark("done")
	if p.DB == nil || id == "" || segment.ArchiveMonth == "" {
		return errors.New("stream discovery projector needs DB, segment ID and archive month")
	}
	for _, event := range segment.Events {
		if event.Type == "identity" || event.Type == "risk" || event.Type == "router" {
			return fmt.Errorf("%s: %w", event.Type, ErrUnsupportedStreamProjection)
		}
	}
	prepared, err := prepareStreamDiscovery(segment)
	if err != nil {
		return err
	}
	if len(prepared) == 0 {
		return ErrUnsupportedStreamProjection
	}
	mark("begin_tx")
	segmentHash := contentHash(struct {
		Epoch, Source, Path, File, RawSHA string
		Start, End                        int64
		Events                            []streamDiscoveryReceipt
	}{segment.Epoch, segment.Source, segment.SourcePath, segment.FileID, segment.RawSHA256, segment.StartOffset, segment.EndOffset, streamReceiptList(prepared)})
	month := streamAcceptedMonth(segment.AcceptedAt)
	tx, err := p.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	mark("insert_segment")
	result, err := tx.ExecContext(ctx, `INSERT INTO stream_projection_segments(segment_id,epoch,source_kind,source_path,content_sha256,accepted_at,event_count)
 VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, id, segment.Epoch, segment.Source, segment.SourcePath, segmentHash, segment.AcceptedAt, len(prepared))
	if err != nil {
		return err
	}
	mark("load_receipts")
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 0 {
		var prior string
		if err := tx.QueryRowContext(ctx, `SELECT content_sha256 FROM stream_projection_segments WHERE segment_id=$1 FOR UPDATE`, id).Scan(&prior); err != nil {
			return err
		}
		if prior != segmentHash {
			return streamlog.ErrContentConflict
		}
		return tx.Commit()
	}
	priorReceipts, err := loadStreamDiscoveryReceipts(ctx, tx, segment.Epoch, prepared)
	if err != nil {
		return err
	}
	mark("lock_devices")
	fresh := make([]streamPreparedDiscovery, 0, len(prepared))
	for _, item := range prepared {
		key := item.Receipt.Scope + "\x00" + item.Receipt.Key
		if old, exists := priorReceipts[key]; exists {
			if old != item.Receipt.Hash {
				return streamlog.ErrContentConflict
			}
			continue
		}
		fresh = append(fresh, item)
	}
	if len(fresh) == 0 {
		return tx.Commit()
	}
	keys := make([]string, 0)
	seenDevices := map[string]bool{}
	for _, item := range fresh {
		if item.HasFact && !seenDevices[item.Fact.Device] {
			seenDevices[item.Fact.Device] = true
			keys = append(keys, item.Fact.Device)
		}
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(device_key,9184))
 FROM (SELECT unnest($1::text[]) AS device_key ORDER BY device_key) ordered`, keys); err != nil {
			return err
		}
	}
	mark("load_fact_versions")
	versions, err := loadStreamFactVersions(ctx, tx, segment.Epoch, fresh)
	if err != nil {
		return err
	}
	mark("merge_facts")
	factWrites := map[string]streamDiscoveryFact{}
	newFactCounts := map[string]int{}
	changedDevices := map[string]bool{}
	changes := make([]streamDiscoveryChange, 0)
	for index := range fresh {
		item := &fresh[index]
		if !item.HasFact {
			continue
		}
		identity := item.Fact.Device + "\x00" + item.Fact.Key
		prior, hasPrior := versions[identity]
		var priorPtr *streamDiscoveryFact
		if hasPrior {
			priorPtr = &prior
		}
		decision := mergeStreamDiscoveryFact(priorPtr, item.Fact)
		item.Receipt.Result = decision.Result
		item.Fact.EvidenceEvent = decision.EvidenceEvent
		if !decision.WriteFact {
			continue
		}
		if !hasPrior {
			newFactCounts[item.Fact.Device]++
		}
		if hasPrior && prior.FirstObserved.Before(item.Fact.FirstObserved) {
			item.Fact.FirstObserved = prior.FirstObserved
		}
		versions[identity] = item.Fact
		factWrites[identity] = item.Fact
		changedDevices[item.Fact.Device] = true
		if decision.VisibleChanged {
			before := ""
			if hasPrior {
				before = prior.SemanticHash
			}
			changes = append(changes, streamDiscoveryChange{Epoch: segment.Epoch, Device: item.Fact.Device, Event: item.Fact.Event, Accepted: segment.AcceptedAt, Observed: item.Fact.Observed, Kind: decision.Result, BeforeHash: before, AfterHash: item.Fact.SemanticHash, BodyRef: streamDiscoveryBodyRef(segment, item.Receipt)})
		}
	}
	mark("write_facts")
	if err := writeStreamDiscoveryFacts(ctx, tx, factWrites); err != nil {
		return err
	}
	mark("publish_state")
	stateKeys := make([]string, 0, len(changedDevices))
	for key := range changedDevices {
		stateKeys = append(stateKeys, key)
	}
	sort.Strings(stateKeys)
	if err := publishStreamDiscoveryStates(ctx, tx, segment.Epoch, stateKeys, newFactCounts); err != nil {
		return err
	}
	mark("write_changes")
	if err := writeStreamDiscoveryChanges(ctx, tx, changes); err != nil {
		return err
	}
	mark("write_receipts")
	if err := writeStreamDiscoveryReceipts(ctx, tx, month, segment, fresh); err != nil {
		return err
	}
	mark("commit")
	return tx.Commit()
}

func streamAcceptedMonth(at time.Time) time.Time {
	at = at.UTC()
	return time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC)
}

func streamReceiptList(items []streamPreparedDiscovery) []streamDiscoveryReceipt {
	out := make([]streamDiscoveryReceipt, 0, len(items))
	for _, item := range items {
		out = append(out, item.Receipt)
	}
	return out
}

func streamDiscoveryBodyRef(segment streamlog.Segment, receipt streamDiscoveryReceipt) json.RawMessage {
	ref, _ := json.Marshal(map[string]string{"epoch": segment.Epoch, "class": "evidence", "month": segment.ArchiveMonth, "scope": receipt.Scope, "key": receipt.Key, "sha256": receipt.Hash})
	return ref
}

func loadStreamDiscoveryReceipts(ctx context.Context, tx *sql.Tx, epoch string, items []streamPreparedDiscovery) (map[string]string, error) {
	input := make([]streamDiscoveryReceipt, 0, len(items))
	for _, item := range items {
		input = append(input, item.Receipt)
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT r.scope_id,r.event_key,r.content_sha256
 FROM stream_discovery_event_keys r
 JOIN jsonb_to_recordset($2::jsonb) AS v(scope_id text,event_key text) USING(scope_id,event_key)
 WHERE r.epoch=$1`, epoch, raw)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]string, len(items))
	for rows.Next() {
		var scope, key, hash string
		if err := rows.Scan(&scope, &key, &hash); err != nil {
			return nil, err
		}
		result[scope+"\x00"+key] = hash
	}
	return result, rows.Err()
}

func loadStreamFactVersions(ctx context.Context, tx *sql.Tx, epoch string, items []streamPreparedDiscovery) (map[string]streamDiscoveryFact, error) {
	type keyRow struct {
		Device string `json:"device_key"`
		Fact   string `json:"fact_key"`
	}
	keys := make([]keyRow, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		if !item.HasFact {
			continue
		}
		identity := item.Fact.Device + "\x00" + item.Fact.Key
		if !seen[identity] {
			seen[identity] = true
			keys = append(keys, keyRow{item.Fact.Device, item.Fact.Key})
		}
	}
	result := make(map[string]streamDiscoveryFact, len(keys))
	if len(keys) == 0 {
		return result, nil
	}
	raw, err := json.Marshal(keys)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT f.device_key,f.fact_key,f.event_key,f.visible_event_key,f.revision,f.first_observed_at,f.observed_at,f.valid_until,f.withdrawn,f.semantic_hash
 FROM jsonb_to_recordset($2::jsonb) AS v(device_key text,fact_key text)
 JOIN stream_discovery_facts f ON f.epoch=$1 AND f.device_key=v.device_key AND f.fact_key=v.fact_key`, epoch, raw)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var fact streamDiscoveryFact
		if err := rows.Scan(&fact.Device, &fact.Key, &fact.Event, &fact.EvidenceEvent, &fact.Revision, &fact.FirstObserved, &fact.Observed, &fact.ValidUntil, &fact.Withdrawn, &fact.SemanticHash); err != nil {
			return nil, err
		}
		fact.Epoch = epoch
		result[fact.Device+"\x00"+fact.Key] = fact
	}
	return result, rows.Err()
}

func writeStreamDiscoveryFacts(ctx context.Context, tx *sql.Tx, facts map[string]streamDiscoveryFact) error {
	if len(facts) == 0 {
		return nil
	}
	keys := make([]string, 0, len(facts))
	for key := range facts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	input := make([]streamDiscoveryFact, 0, len(keys))
	for _, key := range keys {
		input = append(input, facts[key])
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO stream_discovery_facts(epoch,device_key,fact_key,scope_id,source_id,protocol,service_instance,event_key,visible_event_key,revision,first_observed_at,observed_at,valid_until,withdrawn,semantic_hash,ip,mac,name,manufacturer,model_name,device_type,candidate_type,candidate_reason,excluded,capabilities,address_binding,sensor_id,site,domain,vlan,vrf,interface_name)
 SELECT v.epoch,v.device_key,v.fact_key,v.scope_id,v.source_id,v.protocol,v.service_instance,v.event_key,v.visible_event_key,v.revision,v.first_observed_at,v.observed_at,v.valid_until,v.withdrawn,v.semantic_hash,v.ip,v.mac,v.name,v.manufacturer,v.model_name,v.device_type,v.candidate_type,v.candidate_reason,v.excluded,coalesce(v.capabilities,'{}'::text[]),v.address_binding,v.sensor_id,v.site,v.domain,v.vlan,v.vrf,v.interface_name
 FROM jsonb_to_recordset($1::jsonb) AS v(epoch text,device_key text,fact_key text,scope_id text,source_id text,protocol text,service_instance text,event_key text,visible_event_key text,revision bigint,first_observed_at timestamptz,observed_at timestamptz,valid_until timestamptz,withdrawn boolean,semantic_hash text,ip text,mac text,name text,manufacturer text,model_name text,device_type text,candidate_type text,candidate_reason text,excluded boolean,capabilities text[],address_binding boolean,sensor_id text,site text,domain text,vlan text,vrf text,interface_name text)
 ON CONFLICT(epoch,device_key,fact_key) DO UPDATE SET scope_id=EXCLUDED.scope_id,source_id=EXCLUDED.source_id,protocol=EXCLUDED.protocol,service_instance=EXCLUDED.service_instance,event_key=EXCLUDED.event_key,visible_event_key=EXCLUDED.visible_event_key,revision=EXCLUDED.revision,first_observed_at=least(stream_discovery_facts.first_observed_at,EXCLUDED.first_observed_at),observed_at=EXCLUDED.observed_at,valid_until=EXCLUDED.valid_until,withdrawn=EXCLUDED.withdrawn,semantic_hash=EXCLUDED.semantic_hash,ip=EXCLUDED.ip,mac=EXCLUDED.mac,name=EXCLUDED.name,manufacturer=EXCLUDED.manufacturer,model_name=EXCLUDED.model_name,device_type=EXCLUDED.device_type,candidate_type=EXCLUDED.candidate_type,candidate_reason=EXCLUDED.candidate_reason,excluded=EXCLUDED.excluded,capabilities=EXCLUDED.capabilities,address_binding=EXCLUDED.address_binding,sensor_id=EXCLUDED.sensor_id,site=EXCLUDED.site,domain=EXCLUDED.domain,vlan=EXCLUDED.vlan,vrf=EXCLUDED.vrf,interface_name=EXCLUDED.interface_name
 WHERE (EXCLUDED.event_key=stream_discovery_facts.event_key AND EXCLUDED.revision>stream_discovery_facts.revision)
 OR (EXCLUDED.event_key<>stream_discovery_facts.event_key AND (EXCLUDED.observed_at,EXCLUDED.event_key)>(stream_discovery_facts.observed_at,stream_discovery_facts.event_key))`, raw)
	return err
}

type streamDiscoveryChange struct {
	Epoch      string          `json:"epoch"`
	Device     string          `json:"device_key"`
	Event      string          `json:"event_key"`
	Accepted   time.Time       `json:"accepted_at"`
	Observed   time.Time       `json:"observed_at"`
	Kind       string          `json:"change_kind"`
	BeforeHash string          `json:"before_hash"`
	AfterHash  string          `json:"after_hash"`
	BodyRef    json.RawMessage `json:"body_ref"`
}

func writeStreamDiscoveryChanges(ctx context.Context, tx *sql.Tx, changes []streamDiscoveryChange) error {
	if len(changes) == 0 {
		return nil
	}
	raw, err := json.Marshal(changes)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO stream_discovery_changes(epoch,device_key,event_key,accepted_at,observed_at,change_kind,before_hash,after_hash,body_ref)
 SELECT v.epoch,v.device_key,v.event_key,v.accepted_at,v.observed_at,v.change_kind,v.before_hash,v.after_hash,v.body_ref
 FROM jsonb_to_recordset($1::jsonb) AS v(epoch text,device_key text,event_key text,accepted_at timestamptz,observed_at timestamptz,change_kind text,before_hash text,after_hash text,body_ref jsonb)`, raw)
	return err
}

func writeStreamDiscoveryReceipts(ctx context.Context, tx *sql.Tx, month time.Time, segment streamlog.Segment, items []streamPreparedDiscovery) error {
	type row struct {
		streamDiscoveryReceipt
		BodyRef json.RawMessage `json:"body_ref"`
	}
	input := make([]row, 0, len(items))
	for _, item := range items {
		input = append(input, row{item.Receipt, streamDiscoveryBodyRef(segment, item.Receipt)})
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	keysResult, err := tx.ExecContext(ctx, `INSERT INTO stream_discovery_event_keys(epoch,scope_id,event_key,content_sha256,accepted_month,first_accepted_at)
 SELECT $1,v.scope_id,v.event_key,v.content_sha256,$2,v.accepted_at
 FROM jsonb_to_recordset($3::jsonb) AS v(scope_id text,event_key text,content_sha256 text,accepted_at timestamptz)
 ON CONFLICT DO NOTHING`, segment.Epoch, month, raw)
	if err != nil {
		return err
	}
	keyCount, err := keysResult.RowsAffected()
	if err != nil {
		return err
	}
	if keyCount != int64(len(items)) {
		return fmt.Errorf("stream discovery key raced with another segment: %w", streamlog.ErrUnconfirmed)
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO stream_discovery_receipts(accepted_month,epoch,scope_id,event_key,content_sha256,accepted_at,result,body_ref)
 SELECT $1,$2,v.scope_id,v.event_key,v.content_sha256,v.accepted_at,v.result,v.body_ref
 FROM jsonb_to_recordset($3::jsonb) AS v(scope_id text,event_key text,content_sha256 text,accepted_at timestamptz,result text,body_ref jsonb)
 ON CONFLICT DO NOTHING`, month, segment.Epoch, raw)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != int64(len(items)) {
		return fmt.Errorf("stream discovery receipt raced with another segment: %w", streamlog.ErrUnconfirmed)
	}
	return nil
}
