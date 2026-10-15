package discovery

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"proxy-sentinel/internal/normalized"
	"sort"
	"strings"
	"time"
)

func contentHash(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// AcceptDiscoveryBatch durably retains input before any cross-store write.
// The existing ingestion ledger is the sole batch confirmation authority.
func (r Repository) AcceptDiscoveryBatch(ctx context.Context, id string, events []normalized.Event) error {
	return r.AcceptDiscoveryBatchLane(ctx, id, events, "realtime")
}
func (r Repository) AcceptDiscoveryBatchLane(ctx context.Context, id string, events []normalized.Event, lane string) error {
	if lane != "realtime" && lane != "backfill" && lane != "rules" {
		return fmt.Errorf("invalid discovery lane")
	}

	if id == "" || len(events) == 0 || len(events) > 2000 {
		return fmt.Errorf("invalid discovery batch size or ID")
	}
	raw, err := EncodeDiscoveryBatch(events)
	if err != nil {
		return err
	}
	sensor := str(events[0].Observer, "sensor_id")
	if sensor == "" {
		return fmt.Errorf("discovery sensor required")
	}
	for _, e := range events {
		if str(e.Observer, "sensor_id") != sensor || e.EventID == "" {
			return fmt.Errorf("invalid discovery batch scope")
		}
	}
	hash := contentHash(events)
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO ingest_batches(batch_id,sensor_id,source_kind,source_path,file_id,start_offset,end_offset,checksum,status,event_count,started_at) VALUES($1,$2,'discovery-v2',$1,$1,0,$3,$4,'started',$3,now()) ON CONFLICT DO NOTHING`, id, sensor, len(events), hash)
	if err != nil {
		return err
	}
	var prior string
	if err = tx.QueryRowContext(ctx, `SELECT checksum FROM ingest_batches WHERE batch_id=$1 FOR UPDATE`, id).Scan(&prior); err != nil {
		return err
	}
	if prior != hash {
		return fmt.Errorf("discovery batch ID content conflict")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO discovery_batch_work(batch_id,events,lane) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, id, raw, lane)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// A row lock fences every claim including ClickHouse export. Only this batch
// is locked; unrelated batches and queries remain independent. A lost process
// rolls back progress and the input remains available for idempotent recovery.
func (r Repository) ProcessDiscoveryBatch(ctx context.Context) (bool, error) {
	return r.ProcessDiscoveryLane(ctx, "realtime")
}
func (r Repository) ProcessDiscoveryLane(ctx context.Context, lane string) (bool, error) {
	if lane != "realtime" && lane != "backfill" && lane != "rules" {
		return false, fmt.Errorf("invalid discovery lane")
	}

	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var id, sourceKind string
	var raw []byte
	var offset int
	var archived bool
	var accepted time.Time
	err = tx.QueryRowContext(ctx, `SELECT w.batch_id,w.events,w.processed_offset,w.archived,b.started_at,b.source_kind
FROM discovery_batch_work w JOIN LATERAL (
 SELECT started_at,source_kind FROM ingest_batches b WHERE b.batch_id=w.batch_id
 AND (b.source_kind='discovery-v2' OR b.status='committed') LIMIT 1
) b ON true WHERE w.lane=$1 AND NOT w.completed AND w.next_attempt_at<=now()
ORDER BY w.next_attempt_at,w.created_at FOR UPDATE OF w SKIP LOCKED LIMIT 1`, lane).Scan(&id, &raw, &offset, &archived, &accepted, &sourceKind)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	fail := func(cause error) (bool, error) {
		_ = tx.Rollback()
		report, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_, _ = r.DB.ExecContext(report, `UPDATE discovery_batch_work SET attempts=attempts+1,error=$2,next_attempt_at=now()+least(interval '60 seconds',interval '1 second'*power(2,least(attempts,5))) WHERE batch_id=$1 AND NOT completed`, id, cause.Error())
		return true, cause
	}
	var events []normalized.Event
	if err = decodeDiscoveryBatch(raw, &events); err != nil {
		return fail(err)
	}
	end := min(offset+50, len(events))
	if !archived {
		if sourceKind == "discovery-v2" && r.Archive == nil {
			return fail(fmt.Errorf("discovery archive unavailable"))
		}
		if sourceKind == "discovery-v2" {
			if err = r.Archive(ctx, events[offset:end]); err != nil {
				return fail(err)
			}
		}
		if r.ArchiveDiscovery != nil {
			if err = r.ArchiveDiscovery(ctx, fmt.Sprintf("%s/segment/%d", id, offset), accepted, events[offset:end]); err != nil {
				return fail(err)
			}
		}
	}
	now := time.Now().UTC()
	// Acquire all device locks in one stable order before taking any fact locks.
	lockKeys := map[string]bool{}
	for _, e := range events[offset:end] {
		a, pe := AdaptDiscoveryEvent(e)
		if pe != nil {
			continue
		}
		o, pe := FromEvent(a)
		if pe == nil && (o.IP == "" || IsPrivateDiscoveryAddress(o.IP)) {
			lockKeys[discoveryStateKey(o)] = true
		}
	}
	orderedLocks := make([]string, 0, len(lockKeys))
	for key := range lockKeys {
		orderedLocks = append(orderedLocks, key)
	}
	sort.Strings(orderedLocks)
	for _, key := range orderedLocks {
		if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,9183))`, key); err != nil {
			return fail(err)
		}
	}
	touched := map[string]bool{}
	type runtimeDelta struct{ admitted, rejected, received, parsed int64 }
	runtime := map[string]runtimeDelta{}
	for _, e := range events[offset:end] {
		revision := int64(number(e.Payload, "revision"))
		hash := contentHash(e)
		var prior string
		err = tx.QueryRowContext(ctx, `SELECT content_hash FROM discovery_event_receipts WHERE sensor_id=$1 AND source_id=$2 AND event_id=$3 AND revision=$4`, str(e.Observer, "sensor_id"), firstText(str(e.Observer, "source_id"), e.Source), e.EventID, revision).Scan(&prior)
		if err == nil {
			if hash != prior {
				return fail(fmt.Errorf("event revision content conflict: %s", e.EventID))
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fail(err)
		}
		adapted, parseErr := AdaptDiscoveryEvent(e)
		var o Observation
		if parseErr == nil {
			o, parseErr = FromEvent(adapted)
		}
		result := "applied"
		if parseErr != nil {
			result = "rejected: " + parseErr.Error()
		} else if !IsPrivateDiscoveryAddress(o.IP) && o.IP != "" {
			result = "outside_private_scope"
		} else {
			key := discoveryStateKey(o)
			// Stable per-device locks serialize simultaneous protocol batches.
			touched[key] = true
			fact := discoveryFactKey(o)
			encoded, _ := json.Marshal(o)
			semantic := o
			semantic.ID = ""
			semantic.EventID = ""
			semantic.ObservedAt = time.Time{}
			semantic.ValidUntil = time.Time{}
			payload := map[string]any{}
			for k, v := range o.Evidence.Payload {
				if k != "ttl" && k != "record_ttl" {
					payload[k] = v
				}
			}
			semantic.Evidence = normalized.Event{Payload: payload}
			semanticHash := contentHash(semantic)
			var previousHash string
			err = tx.QueryRowContext(ctx, `SELECT content_hash FROM discovery_service_facts_v2 WHERE device_key=$1 AND fact_key=$2`, key, fact).Scan(&previousHash)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return fail(err)
			}
			res, e2 := tx.ExecContext(ctx, `INSERT INTO discovery_service_facts_v2(device_key,fact_key,sensor_id,domain,vlan,interface_name,source_id,protocol,service_instance,ip,mac,event_id,revision,observed_at,valid_until,withdrawn,observation,content_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) ON CONFLICT(device_key,fact_key) DO UPDATE SET event_id=EXCLUDED.event_id,revision=EXCLUDED.revision,observed_at=EXCLUDED.observed_at,valid_until=EXCLUDED.valid_until,withdrawn=EXCLUDED.withdrawn,observation=EXCLUDED.observation,content_hash=EXCLUDED.content_hash WHERE (EXCLUDED.event_id=discovery_service_facts_v2.event_id AND EXCLUDED.revision>discovery_service_facts_v2.revision) OR (EXCLUDED.event_id<>discovery_service_facts_v2.event_id AND (EXCLUDED.observed_at,EXCLUDED.event_id)>(discovery_service_facts_v2.observed_at,discovery_service_facts_v2.event_id))`, key, fact, o.Node, o.Domain, o.VLAN, o.Interface, o.SourceID, o.Origin, serviceInstance(o), o.IP, o.MAC, o.ID, revision, o.ObservedAt, o.ValidUntil, o.Withdrawn, encoded, semanticHash)
			if e2 != nil {
				return fail(e2)
			}
			changed, _ := res.RowsAffected()
			if changed == 0 {
				result = "late_history"
			}
			if changed == 0 || previousHash != semanticHash {
				if _, err = tx.ExecContext(ctx, `INSERT INTO discovery_device_changes_v2(device_key,event_id,ingested_at,observed_at,change_kind,document,archive_verified_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, key, o.ID, accepted, o.ObservedAt, result, encoded, archiveVerifiedTime(r.ArchiveDiscovery != nil)); err != nil {
					return fail(err)
				}
			}
		}
		protocol := firstText(e.SourceEventType, str(e.Payload, "origin"))
		delta := runtime[str(e.Observer, "sensor_id")+"\x00"+protocol]
		delta.admitted += int64(discoveryAdmissionCount(result))
		delta.rejected += int64(discoveryRejectionCount(result))
		delta.received += int64(discoveryZeekCount(e.Source))
		delta.parsed += int64(discoveryZeekCount(e.Source))
		runtime[str(e.Observer, "sensor_id")+"\x00"+protocol] = delta
		if _, err = tx.ExecContext(ctx, `INSERT INTO discovery_event_receipts(sensor_id,source_id,event_id,revision,content_hash,batch_id,accepted_at,result) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, str(e.Observer, "sensor_id"), firstText(str(e.Observer, "source_id"), e.Source), e.EventID, revision, hash, id, accepted, result); err != nil {
			return fail(err)
		}
	}

	keys := make([]string, 0, len(touched))
	for key := range touched {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err = refreshDiscoveryState(ctx, tx, key, now); err != nil {
			return fail(err)
		}
	}
	runtimeKeys := make([]string, 0, len(runtime))
	for key := range runtime {
		runtimeKeys = append(runtimeKeys, key)
	}
	sort.Strings(runtimeKeys)
	for _, key := range runtimeKeys {
		delta := runtime[key]
		parts := strings.SplitN(key, "\x00", 2)
		if _, err = tx.ExecContext(ctx, `INSERT INTO discovery_protocol_runtime(sensor_id,protocol,admitted,rejected,received,parsed,last_success) VALUES($1,$2,$3,$4,$5,$6,CASE WHEN $3::bigint>0 THEN now() ELSE NULL END) ON CONFLICT(sensor_id,protocol) DO UPDATE SET admitted=discovery_protocol_runtime.admitted+EXCLUDED.admitted,rejected=discovery_protocol_runtime.rejected+EXCLUDED.rejected,received=discovery_protocol_runtime.received+EXCLUDED.received,parsed=discovery_protocol_runtime.parsed+EXCLUDED.parsed,last_success=coalesce(EXCLUDED.last_success,discovery_protocol_runtime.last_success)`, parts[0], parts[1], delta.admitted, delta.rejected, delta.received, delta.parsed); err != nil {
			return fail(err)
		}
	}
	// Publish the shared ingestion watermark only after expensive per-device
	// work. Retried/later slices must not lock or rewrite an already confirmed
	// batch, and concurrent devices must not serialize on the singleton early.
	if !archived {
		if _, err = tx.ExecContext(ctx, `UPDATE ingest_batches SET status='committed',committed_at=started_at WHERE batch_id=$1 AND committed_at IS NULL`, id); err != nil {
			return fail(err)
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE discovery_batch_work SET archived=archived OR $3,processed_offset=$2,completed=$3,completed_at=CASE WHEN $3 THEN now() ELSE NULL END,error='',next_attempt_at=now() WHERE batch_id=$1`, id, end, end == len(events)); err != nil {
		return fail(err)
	}
	return true, tx.Commit()
}
func serviceInstance(o Observation) string {
	return firstText(str(o.Evidence.Payload, "service_instance"), firstText(str(o.Evidence.Payload, "endpoint_reference"), firstText(str(o.Evidence.Payload, "usn"), str(o.Evidence.Payload, "service_type"))))
}
func discoveryStateKey(o Observation) string {
	identity := o.IP
	if identity == "" && o.MAC != "" {
		identity = "mac:" + o.MAC
	}
	if identity == "" {
		identity = serviceInstance(o)
	}
	// Sensor and L2 domain are mandatory parts; an IP is an observation identity,
	// never an automatic cross-network asset merge.
	return contentHash([]string{o.Node, o.Site, o.Domain, o.VLAN, o.VRF, o.Interface, identity})[:32]
}
func discoveryFactKey(o Observation) string {
	return contentHash([]string{o.SourceID, o.Origin, serviceInstance(o), o.IP, o.Port})
}

func refreshDiscoveryState(ctx context.Context, tx *sql.Tx, key string, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `SELECT observation FROM discovery_service_facts_v2 WHERE device_key=$1 ORDER BY observed_at DESC,event_id LIMIT 1025`, key)
	if err != nil {
		return err
	}
	observations := []Observation{}
	for rows.Next() {
		var raw []byte
		var o Observation
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		if err = json.Unmarshal(raw, &o); err != nil {
			rows.Close()
			return err
		}
		observations = append(observations, o)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(observations) > 1024 {
		return fmt.Errorf("device candidate fact budget exceeded; repair required")
	}
	if len(observations) == 0 {
		return nil
	}
	var oldRaw []byte
	var lastType, lastCategory string
	var first time.Time
	err = tx.QueryRowContext(ctx, `SELECT document,last_device_type,last_category,first_seen FROM discovery_device_state_v2 WHERE device_key=$1`, key).Scan(&oldRaw, &lastType, &lastCategory, &first)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	o := observations[0]
	// Only protocol-level client bindings establish a device MAC. Ethernet sender
	// MACs on mirrored/routed service packets stay transport evidence.
	boundMAC := ""
	for _, fact := range observations {
		if (fact.Origin == "dhcp" || fact.Origin == "arp" || fact.Origin == "ndp") && fact.Evidence.Payload["address_binding"] == true && fact.Current(now) && fact.MAC != "" {
			boundMAC = fact.MAC
			break
		}
	}
	var previous struct {
		MAC string `json:"mac"`
	}
	_ = json.Unmarshal(oldRaw, &previous)
	if previous.MAC != "" && boundMAC != "" && previous.MAC != boundMAC {
		for at := range observations {
			if observations[at].Origin != "dhcp" && observations[at].Origin != "arp" && observations[at].Origin != "ndp" {
				observations[at].Withdrawn = true
				if _, err = tx.ExecContext(ctx, `UPDATE discovery_service_facts_v2 SET withdrawn=true,observation=jsonb_set(observation,'{withdrawn}','true') WHERE device_key=$1 AND fact_key=$2`, key, discoveryFactKey(observations[at])); err != nil {
					return err
				}
			}
		}
		lastType = ""
		lastCategory = ""
	}
	o.MAC = boundMAC
	for _, fact := range observations {
		if boundMAC != "" {
			fact.MAC = boundMAC
		}
		if err = queueEnrichment(ctx, tx, key, fact); err != nil {
			return err
		}
	}
	last := o.ObservedAt
	if first.IsZero() {
		first = last
	}
	// Confirm the publisher owns the explicitly declared device MAC before
	// using a forwarded MQTT declaration as hardware evidence.
	for at := range observations {
		o := observations[at]
		if o.Origin != "mqtt" {
			continue
		}
		mac := str(o.Evidence.Payload, "declared_mac")
		if mac == "" {
			continue
		}
		for _, binding := range observations {
			if (binding.Origin == "dhcp" || binding.Origin == "arp" || binding.Origin == "ndp") && binding.Evidence.Payload["address_binding"] == true && binding.IP == o.IP && binding.MAC == mac && binding.Current(now) {
				payload := map[string]any{}
				for k, v := range o.Evidence.Payload {
					payload[k] = v
				}
				payload["self_binding_verified"] = true
				o.Evidence.Payload = payload
				observations[at] = o
				break
			}
		}
	}
	classification := ClassifyIoT(observations, now)
	if lastType == "" && len(oldRaw) == 0 && classification.DeviceType == "" && !classification.Conflict {
		for _, v := range observations {
			if v.Withdrawn || v.ObservedAt.After(now) {
				continue
			}
			historic := ClassifyIoT([]Observation{v}, v.ObservedAt.Add(time.Nanosecond))
			if historic.DeviceType != "" {
				lastType = historic.DeviceType
				lastCategory = historic.Category
				break
			}
		}
	}
	state := "candidate"
	if classification.DeviceType != "" {
		state = "identified"
		lastType = classification.DeviceType
		lastCategory = classification.Category
	} else if classification.Conflict {
		state = "conflict"
	} else if lastType != "" {
		state = "expired"
	}
	// Only retract the last conclusion when all of its supporting facts have
	// been explicitly replaced/withdrawn. An unrelated service withdrawal cannot
	// erase an aged classification from another service instance.
	if state == "expired" && len(oldRaw) > 0 {
		var prior struct {
			Classification IoTClassification `json:"classification"`
		}
		_ = json.Unmarshal(oldRaw, &prior)
		remaining := false
		for _, previousID := range prior.Classification.EvidenceIDs {
			for _, fact := range observations {
				if fact.ID == previousID && !fact.Withdrawn {
					remaining = true
				}
			}
		}
		if len(prior.Classification.EvidenceIDs) > 0 && !remaining {
			lastType = ""
			lastCategory = ""
			state = "candidate"
		}
	}
	if state == "expired" {
		var prior struct {
			Classification IoTClassification `json:"classification"`
		}
		_ = json.Unmarshal(oldRaw, &prior)
		classification.EvidenceIDs = prior.Classification.EvidenceIDs
	}
	addresses := []string{}
	protocols := []string{}
	caps := []string{}
	seenIP := map[string]bool{}
	seenProtocol := map[string]bool{}
	seenCap := map[string]bool{}
	var expiry *time.Time
	name, manufacturer, model := "", "", ""
	current := false
	for _, v := range observations {
		if v.ObservedAt.Before(first) {
			first = v.ObservedAt
		}
		if name == "" {
			name = v.Name
		}
		if manufacturer == "" {
			manufacturer = v.Manufacturer
		}
		if model == "" {
			model = v.ModelName
		}
		if v.Current(now) {
			current = true
			if v.IP != "" && v.Evidence.Payload["address_binding"] == true && !seenIP[v.IP] {
				addresses = append(addresses, v.IP)
				seenIP[v.IP] = true
			}
			if expiry == nil || v.ValidUntil.Before(*expiry) {
				at := v.ValidUntil
				expiry = &at
			}
		}
		if v.ObservedAt.After(now) && (expiry == nil || v.ObservedAt.Before(*expiry)) {
			at := v.ObservedAt
			expiry = &at
		}
		if !seenProtocol[v.Origin] {
			protocols = append(protocols, v.Origin)
			seenProtocol[v.Origin] = true
		}
		for _, capability := range v.Capabilities {
			if !seenCap[capability] {
				caps = append(caps, capability)
				seenCap[capability] = true
			}
		}
	}
	summary := observations
	if len(summary) > 5 {
		summary = summary[:5]
	}
	document := map[string]any{"id": key, "name": name, "mac": o.MAC, "primary_ip": o.IP, "last_observed_ip": o.IP, "addresses": addresses, "current_addresses": addresses, "device_type": classification.DeviceType, "category": classification.Category, "last_device_type": lastType, "last_category": lastCategory, "classification_status": state, "classification": classification, "identity_kind": "scoped_observation", "protocols": protocols, "capabilities": caps, "first_seen": first, "last_seen": last, "current": current, "evidence_count": len(observations), "observations": summary, "sensor_id": o.Node, "domain": o.Domain, "vlan": o.VLAN, "interface": o.Interface, "manufacturer": manufacturer, "model_name": model}
	// Lists contain a bounded summary; raw standard events are read through history.
	for at := range summary {
		copy := summary[at]
		copy.Evidence = normalized.Event{}
		summary[at] = copy
	}
	document["observations"] = summary
	encoded, _ := json.Marshal(document)
	_, err = tx.ExecContext(ctx, `INSERT INTO discovery_device_state_v2(device_key,sensor_id,domain,vlan,interface_name,name,manufacturer,model_name,device_type,category,last_device_type,last_category,classification_status,first_seen,last_seen,expires_at,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) ON CONFLICT(device_key) DO UPDATE SET name=EXCLUDED.name,manufacturer=EXCLUDED.manufacturer,model_name=EXCLUDED.model_name,device_type=EXCLUDED.device_type,category=EXCLUDED.category,last_device_type=EXCLUDED.last_device_type,last_category=EXCLUDED.last_category,classification_status=EXCLUDED.classification_status,first_seen=least(discovery_device_state_v2.first_seen,EXCLUDED.first_seen),last_seen=greatest(discovery_device_state_v2.last_seen,EXCLUDED.last_seen),expires_at=EXCLUDED.expires_at,document=EXCLUDED.document,result_version=nextval('discovery_result_version'),updated_at=now()`, key, o.Node, o.Domain, o.VLAN, o.Interface, name, manufacturer, model, classification.DeviceType, classification.Category, lastType, lastCategory, state, first, last, expiry, encoded)
	return err
}

func (r Repository) ExpireDiscoveryStates(ctx context.Context) error {
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT device_key FROM discovery_device_state_v2 WHERE expires_at<=now() ORDER BY expires_at LIMIT 100`)
	if err != nil {
		return err
	}
	keys := []string{}
	for rows.Next() {
		var key string
		if err = rows.Scan(&key); err != nil {
			rows.Close()
			return err
		}
		keys = append(keys, key)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	sort.Strings(keys)
	for _, key := range keys {
		var locked bool
		if err = tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,9183))`, key).Scan(&locked); err != nil {
			return err
		}
		if !locked {
			continue
		}
		if err = refreshDiscoveryState(ctx, tx, key, time.Now().UTC()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func DiscoveryProtocol(origin string) string { return strings.ToLower(strings.TrimSpace(origin)) }

func archiveVerifiedTime(verified bool) any {
	if verified {
		return time.Now().UTC()
	}
	return nil
}

func discoveryAdmissionCount(result string) int {
	if result == "applied" || result == "late_history" {
		return 1
	}
	return 0
}
func discoveryRejectionCount(result string) int {
	if discoveryAdmissionCount(result) == 0 {
		return 1
	}
	return 0
}
func discoveryZeekCount(source string) int {
	if source == "zeek" {
		return 1
	}
	return 0
}
