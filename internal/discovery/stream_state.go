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
	"time"
)

// The current-state summary reads at most this many narrow facts. All facts,
// event receipts and paginated history remain stored when a device exceeds it.
const maxStreamFactsPerDevice = 256

var ErrStreamFactScopeMismatch = errors.New("stream fact scope or device mismatch")

type streamDiscoveryState struct {
	Epoch                string         `json:"epoch"`
	Device               string         `json:"device_key"`
	Scope                string         `json:"scope_id"`
	Sensor               string         `json:"sensor_id"`
	Site                 string         `json:"site"`
	Domain               string         `json:"domain"`
	VLAN                 string         `json:"vlan"`
	Interface            string         `json:"interface_name"`
	Name                 string         `json:"name"`
	Manufacturer         string         `json:"manufacturer"`
	Model                string         `json:"model_name"`
	DeviceType           string         `json:"device_type"`
	Category             string         `json:"category"`
	LastDeviceType       string         `json:"last_device_type"`
	LastCategory         string         `json:"last_category"`
	ClassificationStatus string         `json:"classification_status"`
	FirstSeen            time.Time      `json:"first_seen"`
	LastSeen             time.Time      `json:"last_seen"`
	ExpiresAt            *time.Time     `json:"expires_at"`
	Document             map[string]any `json:"document"`
}

func buildStreamDiscoveryState(epoch, key string, facts []streamDiscoveryFact, previous *streamDiscoveryState, now time.Time) (streamDiscoveryState, error) {
	return buildStreamDiscoveryStateSummary(epoch, key, facts, previous, now, len(facts), false, nil, nil)
}

func buildStreamDiscoveryStateSummary(epoch, key string, facts []streamDiscoveryFact, previous *streamDiscoveryState, now time.Time, totalCount int, truncated bool, activeUntil, nextFuture *time.Time) (streamDiscoveryState, error) {
	if epoch == "" || key == "" || len(facts) == 0 || len(facts) > maxStreamFactsPerDevice ||
		(truncated && totalCount <= maxStreamFactsPerDevice) ||
		(!truncated && totalCount != len(facts)) {
		return streamDiscoveryState{}, fmt.Errorf("stream device fact budget or identity invalid; repair required: epoch=%s device=%s sampled=%d total=%d truncated=%t prior=%t", epoch, key, len(facts), totalCount, truncated, previous != nil)
	}
	sort.Slice(facts, func(i, j int) bool {
		if facts[i].Observed.Equal(facts[j].Observed) {
			return facts[i].Event > facts[j].Event
		}
		return facts[i].Observed.After(facts[j].Observed)
	})
	newest := facts[0]
	state := streamDiscoveryState{Epoch: epoch, Device: key, Scope: newest.Scope, Sensor: newest.Sensor, Site: newest.Site, Domain: newest.Domain, VLAN: newest.VLAN, Interface: newest.Interface, FirstSeen: newest.FirstObserved, LastSeen: newest.Observed}
	kinds := map[string]string{}
	evidence := []string{}
	excluded := false
	current := false
	addresses, protocols, caps := []string{}, []string{}, []string{}
	seenIP, seenProtocol, seenCap := map[string]bool{}, map[string]bool{}, map[string]bool{}
	boundMAC := ""
	for _, fact := range facts {
		if fact.Epoch != epoch || fact.Device != key || fact.Scope != state.Scope {
			return state, ErrStreamFactScopeMismatch
		}
		if fact.FirstObserved.Before(state.FirstSeen) {
			state.FirstSeen = fact.FirstObserved
		}
		if fact.Observed.After(state.LastSeen) {
			state.LastSeen = fact.Observed
		}
		if state.Name == "" {
			state.Name = fact.Name
		}
		if state.Manufacturer == "" {
			state.Manufacturer = fact.Manufacturer
		}
		if state.Model == "" {
			state.Model = fact.Model
		}
		if fact.Protocol != "" && !seenProtocol[fact.Protocol] {
			protocols = append(protocols, fact.Protocol)
			seenProtocol[fact.Protocol] = true
		}
		for _, cap := range fact.Capabilities {
			if cap != "" && !seenCap[cap] {
				caps = append(caps, cap)
				seenCap[cap] = true
			}
		}
		if !fact.Withdrawn && fact.Observed.After(now) && (state.ExpiresAt == nil || fact.Observed.Before(*state.ExpiresAt)) {
			at := fact.Observed
			state.ExpiresAt = &at
		}
		if fact.Withdrawn || fact.Observed.After(now) || !fact.ValidUntil.After(now) {
			continue
		}
		current = true
		if state.ExpiresAt == nil || fact.ValidUntil.Before(*state.ExpiresAt) {
			at := fact.ValidUntil
			state.ExpiresAt = &at
		}
		if fact.AddressBinding && fact.IP != "" && !seenIP[fact.IP] {
			addresses = append(addresses, fact.IP)
			seenIP[fact.IP] = true
		}
		if fact.AddressBinding && fact.MAC != "" && (fact.Protocol == "dhcp" || fact.Protocol == "arp" || fact.Protocol == "ndp") && boundMAC == "" {
			boundMAC = fact.MAC
		}
		if fact.Excluded {
			excluded = true
		}
		if fact.CandidateType != "" {
			kinds[fact.CandidateType] = fact.CandidateReason
			evidence = append(evidence, streamVisibleEvidenceEvent(fact))
		}
	}
	if previous != nil && previous.FirstSeen.Before(state.FirstSeen) {
		state.FirstSeen = previous.FirstSeen
	}
	if truncated {
		// An older fact outside the recent sample can still be active, or can
		// expire before every sampled fact. Indexed boundary lookups make the
		// current flag and next maintenance wake exact without reading its body.
		current = activeUntil != nil
		state.ExpiresAt = nil
		for _, boundary := range []*time.Time{activeUntil, nextFuture} {
			if boundary != nil && (state.ExpiresAt == nil || boundary.Before(*state.ExpiresAt)) {
				at := *boundary
				state.ExpiresAt = &at
			}
		}
	}
	if _, printer := kinds["printer"]; printer {
		delete(kinds, "scanner")
	}
	classification := IoTClassification{RuleVersion: IoTRuleVersion, EvidenceIDs: evidence}
	if truncated {
		classification.EvidenceIDs = nil
		classification.Reason = "设备事实超出实时摘要范围，分类待核验"
		state.ClassificationStatus = "candidate"
	} else if len(kinds) > 1 || excluded && len(kinds) > 0 {
		classification.Conflict = true
		classification.Reason = "设备类型证据冲突"
		state.ClassificationStatus = "conflict"
	} else if !excluded {
		for kind, reason := range kinds {
			classification.DeviceType, classification.Category, classification.Confidence, classification.Reason = kind, iotCategory(kind), "strong", reason
			state.DeviceType, state.Category = kind, classification.Category
			state.LastDeviceType, state.LastCategory = kind, classification.Category
			state.ClassificationStatus = "identified"
		}
	}
	if state.ClassificationStatus == "" {
		state.ClassificationStatus = "candidate"
		if previous != nil && previous.LastDeviceType != "" {
			oldIDs := streamClassificationEvidence(previous.Document)
			remaining := len(oldIDs) == 0
			for _, id := range oldIDs {
				for _, fact := range facts {
					if streamVisibleEvidenceEvent(fact) == id && !fact.Withdrawn {
						remaining = true
					}
				}
			}
			if remaining {
				state.LastDeviceType, state.LastCategory = previous.LastDeviceType, previous.LastCategory
				state.ClassificationStatus = "expired"
				classification.EvidenceIDs = oldIDs
			}
		}
		if previous == nil {
			for _, fact := range facts {
				if !fact.Withdrawn && fact.CandidateType != "" && !fact.Observed.After(now) {
					state.LastDeviceType, state.LastCategory = fact.CandidateType, iotCategory(fact.CandidateType)
					state.ClassificationStatus = "expired"
					classification.EvidenceIDs = []string{streamVisibleEvidenceEvent(fact)}
					break
				}
			}
		}
	} else if state.ClassificationStatus == "conflict" && previous != nil {
		state.LastDeviceType, state.LastCategory = previous.LastDeviceType, previous.LastCategory
	}
	if state.FirstSeen.IsZero() || state.LastSeen.IsZero() {
		return state, errors.New("stream fact has no observation time")
	}
	primaryIP := ""
	if len(addresses) > 0 {
		primaryIP = addresses[0]
	}
	state.Document = map[string]any{
		"id": key, "epoch": epoch, "freshness": "new", "name": state.Name, "mac": boundMAC,
		"primary_ip": primaryIP, "last_observed_ip": newest.IP, "addresses": addresses, "current_addresses": addresses,
		"device_type": state.DeviceType, "category": state.Category, "last_device_type": state.LastDeviceType, "last_category": state.LastCategory,
		"classification_status": state.ClassificationStatus, "classification": classification, "identity_kind": "scoped_observation",
		"protocols": protocols, "capabilities": caps, "first_seen": state.FirstSeen, "last_seen": state.LastSeen,
		"current": current, "evidence_count": totalCount, "facts_truncated": truncated, "sensor_id": state.Sensor, "site": state.Site,
		"domain": state.Domain, "vlan": state.VLAN, "interface": state.Interface,
		"manufacturer": state.Manufacturer, "model_name": state.Model,
	}
	return state, nil
}

func streamVisibleEvidenceEvent(fact streamDiscoveryFact) string {
	if fact.EvidenceEvent != "" {
		return fact.EvidenceEvent
	}
	return fact.Event
}

// Receipts still record every observation immediately. Current-state rows may
// coalesce a semantically identical heartbeat for at most five seconds.
func coalesceStreamDiscoveryStateFreshness(previous *streamDiscoveryState, next streamDiscoveryState, now time.Time) streamDiscoveryState {
	if previous == nil || previous.ExpiresAt == nil || next.ExpiresAt == nil ||
		!previous.ExpiresAt.After(now.Add(5*time.Second)) || next.ExpiresAt.Before(*previous.ExpiresAt) ||
		!next.LastSeen.After(previous.LastSeen) || next.LastSeen.Sub(previous.LastSeen) >= 5*time.Second ||
		!next.FirstSeen.Equal(previous.FirstSeen) {
		return next
	}
	priorDoc := make(map[string]any, len(previous.Document))
	for k, v := range previous.Document {
		if k != "last_seen" {
			priorDoc[k] = v
		}
	}
	nextDoc := make(map[string]any, len(next.Document))
	for k, v := range next.Document {
		if k != "last_seen" {
			nextDoc[k] = v
		}
	}
	if !streamDiscoveryDocumentsEqual(priorDoc, nextDoc) {
		return next
	}
	next.LastSeen = previous.LastSeen
	next.ExpiresAt = previous.ExpiresAt
	next.Document["last_seen"] = previous.Document["last_seen"]
	return next
}

func streamClassificationEvidence(doc map[string]any) []string {
	if doc == nil {
		return nil
	}
	switch c := doc["classification"].(type) {
	case IoTClassification:
		return append([]string(nil), c.EvidenceIDs...)
	case map[string]any:
		var ids []string
		if raw, ok := c["evidence_ids"].([]any); ok {
			for _, id := range raw {
				if s, ok := id.(string); ok {
					ids = append(ids, s)
				}
			}
		}
		return ids
	}
	return nil
}

// Normalize a Go document to the shape returned by decoding jsonb. UseNumber
// preserves large integers exactly; a failed conversion forces a SQL check.
func streamDiscoveryJSONValue(document any) (any, bool) {
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, false
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, false
	}
	return value, true
}

func streamDiscoveryDocumentsEqual(left, right map[string]any) bool {
	leftValue, ok := streamDiscoveryJSONValue(left)
	if !ok {
		return false
	}
	rightValue, ok := streamDiscoveryJSONValue(right)
	return ok && reflect.DeepEqual(leftValue, rightValue)
}

// A structural match with exact JSON numbers is a sufficient (though not
// necessary) condition for PostgreSQL jsonb equality. The previous document
// was decoded with UseNumber, and device advisory locks protect its snapshot
// from concurrent state writers until commit.
func streamDiscoveryStateMatchesStored(old streamDiscoveryState, next streamDiscoveryState) bool {
	if !old.FirstSeen.Equal(next.FirstSeen) || !old.LastSeen.Equal(next.LastSeen) ||
		(old.ExpiresAt == nil) != (next.ExpiresAt == nil) ||
		(old.ExpiresAt != nil && !old.ExpiresAt.Equal(*next.ExpiresAt)) {
		return false
	}
	current, ok := streamDiscoveryJSONValue(next.Document)
	return ok && reflect.DeepEqual(old.Document, current)
}

func publishStreamDiscoveryStates(ctx context.Context, tx *sql.Tx, epoch string, keys []string, newFactCounts map[string]int) error {
	if len(keys) == 0 {
		return nil
	}
	oldStates := map[string]streamDiscoveryState{}
	rows, err := tx.QueryContext(ctx, `SELECT device_key,scope_id,last_device_type,last_category,first_seen,last_seen,expires_at,document FROM stream_discovery_device_state WHERE epoch=$1 AND device_key=ANY($2::text[])`, epoch, keys)
	if err != nil {
		return err
	}
	for rows.Next() {
		var old streamDiscoveryState
		var raw []byte
		var expires sql.NullTime
		if err = rows.Scan(&old.Device, &old.Scope, &old.LastDeviceType, &old.LastCategory, &old.FirstSeen, &old.LastSeen, &expires, &raw); err != nil {
			break
		}
		if expires.Valid {
			old.ExpiresAt = &expires.Time
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		err = decoder.Decode(&old.Document)
		if err != nil {
			break
		}
		oldStates[old.Device] = old
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	factsByDevice := map[string][]streamDiscoveryFact{}
	rows, err = tx.QueryContext(ctx, `SELECT v.device_key,to_jsonb(f) FROM unnest($2::text[]) AS v(device_key)
 JOIN LATERAL (SELECT scope_id FROM stream_discovery_facts
   WHERE epoch=$1 AND device_key=v.device_key ORDER BY observed_at DESC,event_key DESC LIMIT 1) latest ON true
 JOIN LATERAL (SELECT * FROM stream_discovery_facts
   WHERE epoch=$1 AND device_key=v.device_key AND scope_id=latest.scope_id
   ORDER BY observed_at DESC,event_key DESC LIMIT 257) f ON true`, epoch, keys)
	if err != nil {
		return err
	}
	for rows.Next() {
		var key string
		var raw []byte
		if err = rows.Scan(&key, &raw); err != nil {
			break
		}
		var fact streamDiscoveryFact
		err = json.Unmarshal(raw, &fact)
		if err != nil {
			break
		}
		factsByDevice[key] = append(factsByDevice[key], fact)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	states := make([]streamDiscoveryState, 0, len(keys))
	now := time.Now().UTC()
	overflowKeys := make([]string, 0)
	for _, key := range keys {
		if len(factsByDevice[key]) > maxStreamFactsPerDevice {
			overflowKeys = append(overflowKeys, key)
		}
	}
	type boundaries struct{ active, future *time.Time }
	indexedBoundaries := make(map[string]boundaries, len(overflowKeys))
	if len(overflowKeys) > 0 {
		rows, err = tx.QueryContext(ctx, `SELECT v.device_key,
 (SELECT f.valid_until FROM stream_discovery_facts f WHERE f.epoch=$1 AND f.device_key=v.device_key
  AND f.scope_id=latest.scope_id
  AND NOT f.withdrawn AND f.observed_at<=$3 AND f.valid_until>$3 ORDER BY f.valid_until LIMIT 1),
 (SELECT f.observed_at FROM stream_discovery_facts f WHERE f.epoch=$1 AND f.device_key=v.device_key
  AND f.scope_id=latest.scope_id
  AND NOT f.withdrawn AND f.observed_at>$3 AND f.valid_until>f.observed_at ORDER BY f.observed_at LIMIT 1)
 FROM unnest($2::text[]) AS v(device_key)
 JOIN LATERAL (SELECT scope_id FROM stream_discovery_facts WHERE epoch=$1 AND device_key=v.device_key
  ORDER BY observed_at DESC,event_key DESC LIMIT 1) latest ON true`, epoch, overflowKeys, now)
		if err != nil {
			return err
		}
		for rows.Next() {
			var key string
			var active, future sql.NullTime
			if err = rows.Scan(&key, &active, &future); err != nil {
				break
			}
			b := boundaries{}
			if active.Valid {
				b.active = &active.Time
			}
			if future.Valid {
				b.future = &future.Time
			}
			indexedBoundaries[key] = b
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return err
		}
	}
	// A capture-scope transition keeps older facts and receipts as evidence,
	// but starts a new current summary. Count the new scope only on transition;
	// ordinary updates continue using the stored count and narrow delta.
	transitionCounts := map[string]int{}
	for _, key := range keys {
		if facts := factsByDevice[key]; len(facts) > 0 {
			if old, ok := oldStates[key]; ok && old.Scope != facts[0].Scope {
				var count int
				if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM stream_discovery_facts
 WHERE epoch=$1 AND device_key=$2 AND scope_id=$3`, epoch, key, facts[0].Scope).Scan(&count); err != nil {
					return err
				}
				transitionCounts[key] = count
			}
		}
	}
	for _, key := range keys {
		old, exists := oldStates[key]
		var prior *streamDiscoveryState
		_, transitioned := transitionCounts[key]
		if exists && !transitioned {
			prior = &old
		}
		facts := factsByDevice[key]
		truncated := len(facts) > maxStreamFactsPerDevice
		totalCount := len(facts)
		if prior != nil {
			previousCount, valid := streamDiscoveryEvidenceCount(prior.Document)
			if !valid || newFactCounts[key] < 0 {
				return fmt.Errorf("stream device fact count invalid; repair required")
			}
			totalCount = previousCount + newFactCounts[key]
		} else if transitioned {
			totalCount = transitionCounts[key]
		}
		if truncated {
			facts = facts[:maxStreamFactsPerDevice]
		}
		b := indexedBoundaries[key]
		state, err := buildStreamDiscoveryStateSummary(epoch, key, facts, prior, now, totalCount, truncated, b.active, b.future)
		if err != nil {
			return err
		}
		state = coalesceStreamDiscoveryStateFreshness(prior, state, now)
		if exists && !transitioned && streamDiscoveryStateMatchesStored(old, state) {
			continue
		}
		states = append(states, state)
	}
	if len(states) == 0 {
		return nil
	}
	raw, err := json.Marshal(states)
	if err != nil {
		return err
	}
	// Result versions are sequence values assigned before commit. Serialize
	// their assignment until commit so a later version cannot become visible
	// before an earlier one and pass the current-ledger cursor permanently.
	// Device locks were acquired before this lock by every state writer.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(9184,213)`); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO stream_discovery_device_state(epoch,device_key,scope_id,sensor_id,site,domain,vlan,interface_name,name,manufacturer,model_name,device_type,category,last_device_type,last_category,classification_status,first_seen,last_seen,expires_at,document)
 SELECT v.epoch,v.device_key,v.scope_id,v.sensor_id,v.site,v.domain,v.vlan,v.interface_name,v.name,v.manufacturer,v.model_name,v.device_type,v.category,v.last_device_type,v.last_category,v.classification_status,v.first_seen,v.last_seen,v.expires_at,v.document
 FROM jsonb_to_recordset($1::jsonb) AS v(epoch text,device_key text,scope_id text,sensor_id text,site text,domain text,vlan text,interface_name text,name text,manufacturer text,model_name text,device_type text,category text,last_device_type text,last_category text,classification_status text,first_seen timestamptz,last_seen timestamptz,expires_at timestamptz,document jsonb)
 ON CONFLICT(epoch,device_key) DO UPDATE SET scope_id=EXCLUDED.scope_id,sensor_id=EXCLUDED.sensor_id,site=EXCLUDED.site,domain=EXCLUDED.domain,vlan=EXCLUDED.vlan,interface_name=EXCLUDED.interface_name,name=EXCLUDED.name,manufacturer=EXCLUDED.manufacturer,model_name=EXCLUDED.model_name,device_type=EXCLUDED.device_type,category=EXCLUDED.category,last_device_type=EXCLUDED.last_device_type,last_category=EXCLUDED.last_category,classification_status=EXCLUDED.classification_status,first_seen=EXCLUDED.first_seen,last_seen=EXCLUDED.last_seen,expires_at=EXCLUDED.expires_at,document=EXCLUDED.document,result_version=nextval('stream_discovery_result_version'),updated_at=now()
 WHERE stream_discovery_device_state.document IS DISTINCT FROM EXCLUDED.document
 OR stream_discovery_device_state.first_seen IS DISTINCT FROM EXCLUDED.first_seen
 OR stream_discovery_device_state.last_seen IS DISTINCT FROM EXCLUDED.last_seen
 OR stream_discovery_device_state.expires_at IS DISTINCT FROM EXCLUDED.expires_at`, raw)
	return err
}

func streamDiscoveryEvidenceCount(document map[string]any) (int, bool) {
	switch value := document["evidence_count"].(type) {
	case json.Number:
		if count, err := value.Int64(); err == nil && count >= 0 && count <= 1e12 {
			return int(count), true
		}
		if count, err := value.Float64(); err == nil && count >= 0 && count <= 1e12 && count == float64(int(count)) {
			return int(count), true
		}
	case float64:
		if value >= 0 && value <= 1e12 && value == float64(int(value)) {
			return int(value), true
		}
	case int:
		if value >= 0 {
			return value, true
		}
	}
	return 0, false
}
