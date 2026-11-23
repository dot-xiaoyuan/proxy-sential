package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"proxy-sentinel/internal/census"
	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/normalized"
)

type HardwareDetails struct {
	HardwareType              string                       `json:"hardware_type,omitempty"`
	HardwareTypeStatus        string                       `json:"hardware_type_status,omitempty"`
	HardwareModel             string                       `json:"hardware_model,omitempty"`
	HardwareModelStatus       string                       `json:"hardware_model_status,omitempty"`
	HardwareConflictingTypes  []string                     `json:"hardware_conflicting_types,omitempty"`
	HardwareConflictingModels []string                     `json:"hardware_conflicting_models,omitempty"`
	TypeEvidenceAt            *time.Time                   `json:"type_evidence_at,omitempty"`
	TypeRuleVersion           string                       `json:"type_rule_version,omitempty"`
	TypeSources               []fingerprint.HardwareSource `json:"type_sources,omitempty"`
	ActivityStatus            string                       `json:"activity_status,omitempty"`
	ClassificationVersion     string                       `json:"classification_version,omitempty"`
}

type HardwareState struct {
	HardwareDetails
	IdentityKey      string                             `json:"identity_key"`
	ScopeKey         string                             `json:"scope_key"`
	DeviceKey        string                             `json:"device_key"`
	SensorID         string                             `json:"sensor_id"`
	CampusID         string                             `json:"campus_id"`
	AccessDomain     string                             `json:"access_domain"`
	VLAN             string                             `json:"vlan"`
	VRF              string                             `json:"vrf"`
	MAC              string                             `json:"mac"`
	Manufacturer     string                             `json:"manufacturer,omitempty"`
	Capabilities     []string                           `json:"capabilities,omitempty"`
	FirstSeen        time.Time                          `json:"first_seen"`
	LastSeen         time.Time                          `json:"last_seen"`
	ActiveUntil      time.Time                          `json:"active_until"`
	TypeChangedAt    *time.Time                         `json:"type_changed_at,omitempty"`
	AddressOnlySince *time.Time                         `json:"address_only_since,omitempty"`
	SourceReports    []fingerprint.HardwareSourceReport `json:"source_reports,omitempty"`
}

func EvaluateHardwareFacts(facts []HardwareFact, previous *HardwareState, now time.Time) (HardwareState, error) {
	return evaluateHardwareFacts(facts, previous, now, fingerprint.EvaluateHardware)
}

// ReplayHardwareFacts uses a verified snapshot catalog without changing the
// installed library, while sharing the current projection's evaluation.
func ReplayHardwareFacts(facts []HardwareFact, previous *HardwareState, now time.Time, catalog *fingerprint.HardwareCatalog) (HardwareState, error) {
	return evaluateHardwareFacts(facts, previous, now, catalog.Evaluate)
}

func evaluateHardwareFacts(facts []HardwareFact, previous *HardwareState, now time.Time, evaluate func(fingerprint.HardwareInput, time.Time) fingerprint.HardwareResult) (HardwareState, error) {
	if len(facts) == 0 || len(facts) > 512 {
		return HardwareState{}, fmt.Errorf("hardware identity has %d facts; expected 1..512", len(facts))
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].FactKey < facts[j].FactKey })
	first := facts[0]
	s := HardwareState{IdentityKey: first.IdentityKey, ScopeKey: census.ScopeKey(first.SensorID, first.CampusID, first.AccessDomain, first.VLAN, first.VRF), DeviceKey: first.DeviceKey, SensorID: first.SensorID, CampusID: first.CampusID, AccessDomain: first.AccessDomain, VLAN: first.VLAN, VRF: first.VRF, MAC: first.MAC, FirstSeen: first.FirstSeen, LastSeen: first.ObservedAt}
	evidence := []fingerprint.EvidenceSignal{}
	var originalRecords map[string]bool
	addressOnly := true
	var latestNonAddress, latestAddress, firstAddress time.Time
	revoked := false
	for _, f := range facts {
		if f.IdentityKey != s.IdentityKey {
			return s, fmt.Errorf("hardware facts cross identity scope")
		}
		if f.FirstSeen.Before(s.FirstSeen) {
			s.FirstSeen = f.FirstSeen
		}
		if f.ObservedAt.After(s.LastSeen) {
			s.LastSeen = f.ObservedAt
			s.DeviceKey = f.DeviceKey
		}
		if f.ActiveUntil.After(s.ActiveUntil) && !f.Revoked {
			s.ActiveUntil = f.ActiveUntil
		}
		addressOnly = addressOnly && f.AddressOnly
		if f.AddressOnly && !f.Revoked {
			if f.ObservedAt.After(latestAddress) {
				latestAddress = f.ObservedAt
			}
			if firstAddress.IsZero() || f.FirstSeen.Before(firstAddress) {
				firstAddress = f.FirstSeen
			}
		}
		if !f.AddressOnly && f.ObservedAt.After(latestNonAddress) {
			latestNonAddress = f.ObservedAt
		}
		revoked = revoked || f.Revoked && len(f.Signals) > 0
		evidence = append(evidence, f.Evidence()...)
		if f.hasReferencedProductRecord() {
			if originalRecords == nil {
				originalRecords = make(map[string]bool)
			}
			originalRecords[f.EvidenceID] = true
		}
	}
	result := evaluate(fingerprint.HardwareInput{IdentityTrusted: true, Evidence: evidence, MAC: first.MAC, OriginalRecords: originalRecords}, now)
	if result.Incomplete {
		return HardwareState{}, fmt.Errorf("incomplete hardware evaluation: %s", result.Error)
	}
	s.HardwareDetails = HardwareDetails{HardwareType: result.Type, HardwareTypeStatus: result.TypeStatus, HardwareModel: result.Model, HardwareModelStatus: result.ModelStatus, HardwareConflictingTypes: result.ConflictingTypes, HardwareConflictingModels: result.ConflictingModels, TypeRuleVersion: result.Version, TypeSources: result.Sources, ClassificationVersion: normalized.HardwareClassificationVersion}
	if s.HardwareTypeStatus == "" {
		s.HardwareTypeStatus = "candidate"
	}
	if s.HardwareType == "" && s.HardwareTypeStatus != "conflict" && (revoked || previous != nil && (previous.HardwareType != "" || len(previous.TypeSources) > 0)) {
		s.HardwareTypeStatus = "revoked"
		if previous != nil {
			s.HardwareType = previous.HardwareType
		}
	}
	s.Manufacturer = result.Manufacturer
	s.Capabilities = result.Capabilities
	s.SourceReports = result.SourceReports
	for _, source := range result.Sources {
		if s.TypeEvidenceAt == nil || source.ObservedAt.After(*s.TypeEvidenceAt) {
			at := source.ObservedAt
			s.TypeEvidenceAt = &at
		}
	}
	if s.HardwareTypeStatus == "candidate" && !latestAddress.IsZero() && (addressOnly || latestAddress.After(latestNonAddress)) {
		at := latestAddress
		if addressOnly || firstAddress.After(latestNonAddress) {
			at = firstAddress
		}
		if previous != nil && previous.AddressOnlySince != nil && !latestNonAddress.After(*previous.AddressOnlySince) {
			at = *previous.AddressOnlySince
		}
		s.AddressOnlySince = &at
	}
	if previous != nil {
		s.TypeChangedAt = previous.TypeChangedAt
		if previous.HardwareTypeStatus == "identified" && (previous.HardwareType != s.HardwareType || s.HardwareTypeStatus != "identified") {
			at := now
			s.TypeChangedAt = &at
		}
	}
	return s, nil
}

type HardwareExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

// EnqueueHardwareObservations must share the observation transaction. It folds
// repeated inputs before writes, then queues only identities whose facts changed.
func EnqueueHardwareObservations(ctx context.Context, db HardwareExecer, observations []Observation) error {
	if len(observations) > 20000 {
		return fmt.Errorf("hardware observation batch exceeds 20000")
	}
	dedup := map[string]HardwareFact{}
	for _, o := range observations {
		f, err := HardwareFactFromObservation(o)
		if err != nil {
			return err
		}
		if f == nil {
			continue
		}
		key := f.IdentityKey + f.FactKey
		if old, ok := dedup[key]; !ok {
			dedup[key] = *f
		} else if HardwareFactNewer(*f, old) {
			if old.FirstSeen.Before(f.FirstSeen) {
				f.FirstSeen = old.FirstSeen
			}
			dedup[key] = *f
		} else {
			if f.FirstSeen.Before(old.FirstSeen) {
				old.FirstSeen = f.FirstSeen
				dedup[key] = old
			}
		}
	}
	if len(dedup) == 0 {
		return nil
	}
	facts := make([]HardwareFact, 0, len(dedup))
	for _, f := range dedup {
		facts = append(facts, f)
	}
	sort.Slice(facts, func(i, j int) bool {
		if facts[i].IdentityKey != facts[j].IdentityKey {
			return facts[i].IdentityKey < facts[j].IdentityKey
		}
		return facts[i].FactKey < facts[j].FactKey
	})
	for start := 0; start < len(facts); start += 100 {
		end := min(start+100, len(facts))
		if err := enqueueHardwareFacts(ctx, db, facts[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func enqueueHardwareFacts(ctx context.Context, db HardwareExecer, facts []HardwareFact) error {
	raw, err := json.Marshal(facts)
	if err != nil {
		return err
	}
	if len(raw) > 2*1024*1024 {
		return fmt.Errorf("hardware fact batch exceeds 2 MiB")
	}
	// DO UPDATE ... WHERE false takes the conflict-row lock without rewriting
	// an unchanged queue entry. DO NOTHING does not wait for a projecting worker:
	// its subsequent DELETE could otherwise erase a concurrent new observation.
	_, err = db.ExecContext(ctx, `WITH incoming AS (SELECT r.*,to_jsonb(r) data FROM jsonb_to_recordset($1::jsonb) AS r(identity_key text,fact_key text,claim_key text,sensor_id text,campus_id text,access_domain text,vlan text,vrf text,mac text,device_key text,source text,first_seen timestamptz,observed_at timestamptz,active_until timestamptz,revoked boolean,evidence_id text,raw_ref jsonb,signals jsonb,address_only boolean)), changed AS (
 INSERT INTO passive_hardware_facts(identity_key,fact_key,claim_key,sensor_id,campus_id,access_domain,vlan,vrf,mac,device_key,source,first_seen,observed_at,active_until,revoked,evidence_id,data)
 SELECT i.identity_key,i.fact_key,i.claim_key,i.sensor_id,i.campus_id,i.access_domain,i.vlan,i.vrf,i.mac,i.device_key,i.source,i.first_seen,i.observed_at,i.active_until,
 i.revoked OR EXISTS(SELECT 1 FROM passive_hardware_facts old WHERE old.identity_key=i.identity_key AND old.claim_key=i.claim_key AND old.revoked AND old.observed_at>=i.observed_at),i.evidence_id,i.data FROM incoming i ORDER BY i.identity_key,i.fact_key
 ON CONFLICT(identity_key,fact_key) DO UPDATE SET observed_at=greatest(passive_hardware_facts.observed_at,EXCLUDED.observed_at),
 active_until=CASE WHEN EXCLUDED.observed_at>=passive_hardware_facts.observed_at THEN EXCLUDED.active_until ELSE passive_hardware_facts.active_until END,
 revoked=CASE WHEN EXCLUDED.observed_at>=passive_hardware_facts.observed_at THEN EXCLUDED.revoked OR (EXCLUDED.observed_at=passive_hardware_facts.observed_at AND passive_hardware_facts.revoked) ELSE passive_hardware_facts.revoked END,
 evidence_id=CASE WHEN EXCLUDED.observed_at>=passive_hardware_facts.observed_at THEN EXCLUDED.evidence_id ELSE passive_hardware_facts.evidence_id END,
 data=CASE WHEN EXCLUDED.observed_at>=passive_hardware_facts.observed_at THEN EXCLUDED.data ELSE passive_hardware_facts.data END,
 first_seen=least(passive_hardware_facts.first_seen,EXCLUDED.first_seen)
 WHERE EXCLUDED.first_seen<passive_hardware_facts.first_seen OR EXCLUDED.observed_at>passive_hardware_facts.observed_at OR (EXCLUDED.observed_at=passive_hardware_facts.observed_at AND EXCLUDED.revoked AND NOT passive_hardware_facts.revoked)
 RETURNING identity_key,sensor_id)
 INSERT INTO passive_hardware_dirty(identity_key,sensor_id,reason)
 SELECT DISTINCT identity_key,sensor_id,'observation' FROM changed ORDER BY identity_key,sensor_id
 ON CONFLICT(identity_key) DO UPDATE SET identity_key=EXCLUDED.identity_key WHERE false`, string(raw))
	if err != nil {
		return err
	}
	for _, f := range facts {
		if f.Revoked {
			_, err = db.ExecContext(ctx, `UPDATE passive_hardware_facts SET revoked=true,observed_at=$3 WHERE identity_key=$1 AND claim_key=$2 AND observed_at<=$3 AND NOT revoked`, f.IdentityKey, f.ClaimKey, f.ObservedAt)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// RequeueHardwareRuleVersion is a bounded resumable rule sweep. Already queued
// identities are skipped; successful workers advance their projection version.
func RequeueHardwareRuleVersion(ctx context.Context, db *sql.DB, sensor, version string) (int64, error) {
	result, err := db.ExecContext(ctx, `INSERT INTO passive_hardware_dirty(identity_key,sensor_id,reason)
 SELECT c.identity_key,c.sensor_id,'rule_version' FROM passive_hardware_current c
 WHERE c.sensor_id=$1 AND c.rule_version<>$2 AND NOT EXISTS(SELECT 1 FROM passive_hardware_dirty d WHERE d.identity_key=c.identity_key)
 ORDER BY c.identity_key LIMIT 100 ON CONFLICT DO NOTHING`, sensor, version)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// RequeueHardwareRule is useful for a specific revoked rule; the dependency
// index bounds each batch and also covers devices that have become silent.
func RequeueHardwareRule(ctx context.Context, db *sql.DB, ruleID, version string) (int64, error) {
	result, err := db.ExecContext(ctx, `INSERT INTO passive_hardware_dirty(identity_key,sensor_id,reason)
 SELECT c.identity_key,c.sensor_id,'rule_revoked' FROM passive_hardware_rule_dependencies dep JOIN passive_hardware_current c USING(identity_key)
 WHERE dep.rule_id=$1 AND dep.rule_version=$2 AND NOT EXISTS(SELECT 1 FROM passive_hardware_dirty d WHERE d.identity_key=c.identity_key)
 ORDER BY c.identity_key LIMIT 100 ON CONFLICT DO NOTHING`, ruleID, version)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func ProcessHardwareProjection(ctx context.Context, db *sql.DB, sensor string, limit int) (int, error) {
	return ProcessHardwareProjectionWithin(ctx, db, sensor, limit, 0)
}

// ProcessHardwareProjectionWithin stops claiming new identities before a
// worker cycle runs out of time. Each completed identity is already committed,
// so the remaining dirty rows stay eligible for the next cycle.
func ProcessHardwareProjectionWithin(ctx context.Context, db *sql.DB, sensor string, limit int, budget time.Duration) (int, error) {
	return processHardwareProjectionsWithin(ctx, db, sensor, limit, budget, 1)
}

// ProcessHardwareProjectionBatchedWithin retains the same claim/time limits but
// commits at most four identities together. A failed group rolls back entirely;
// only committed identities count as processed. Each identity reads <= 1 MiB,
// so a group is also bounded to 4 MiB of fact input.
func ProcessHardwareProjectionBatchedWithin(ctx context.Context, db *sql.DB, sensor string, limit int, budget time.Duration) (int, error) {
	return processHardwareProjectionsWithin(ctx, db, sensor, limit, budget, 4)
}

func processHardwareProjectionsWithin(ctx context.Context, db *sql.DB, sensor string, limit int, budget time.Duration, groupSize int) (int, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	var stopAt time.Time
	if budget > 0 {
		stopAt = time.Now().Add(budget)
	}
	count := 0
	for count < limit {
		identityCtx := ctx
		cancel := func() {}
		if !stopAt.IsZero() {
			remaining := time.Until(stopAt) - time.Second
			if remaining < 2*time.Second {
				return count, nil
			}
			identityCtx, cancel = context.WithTimeout(ctx, min(remaining, 7*time.Second))
		}
		processed, key, err := processHardwareIdentityGroup(identityCtx, db, sensor, min(groupSize, limit-count))
		cancel()
		if err != nil {
			if key != "" {
				failureCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
				_, _ = db.ExecContext(failureCtx, `UPDATE passive_hardware_dirty SET attempts=attempts+1,last_error=$2,next_attempt_at=now()+interval '30 seconds' WHERE identity_key=$1`, key, err.Error())
				cancel()
			}
			return count, err
		}
		if processed == 0 {
			break
		}
		count += processed
	}
	return count, nil
}

// A source may be refreshed with a newer observation while depending on the
// same installed rules. Dependency rows only need to move when that rule set
// changes; evidence and last-seen changes are kept in the current projection.
func hardwareRuleDependenciesChanged(before, after []fingerprint.HardwareSource) bool {
	set := func(sources []fingerprint.HardwareSource) map[string]struct{} {
		result := make(map[string]struct{}, len(sources))
		for _, source := range sources {
			result[source.RuleID+"\x00"+source.RuleVersion] = struct{}{}
		}
		return result
	}
	a, b := set(before), set(after)
	if len(a) != len(b) {
		return true
	}
	for key := range a {
		if _, ok := b[key]; !ok {
			return true
		}
	}
	return false
}

func processHardwareIdentityGroup(ctx context.Context, db *sql.DB, sensor string, limit int) (int, string, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, "", err
	}
	defer tx.Rollback()
	// Claim a small oldest candidate set, but acquire all row locks in the
	// same identity order as fact writers. Two lanes can skip each other's four
	// claims without introducing a reversed multi-row lock order.
	rows, err := tx.QueryContext(ctx, `WITH candidates AS MATERIALIZED (
 SELECT identity_key FROM passive_hardware_dirty WHERE sensor_id=$1 AND next_attempt_at<=now()
 ORDER BY first_enqueued_at,identity_key LIMIT $2
 ) SELECT d.identity_key,d.reason FROM passive_hardware_dirty d JOIN candidates c USING(identity_key)
 ORDER BY d.identity_key LIMIT $3 FOR UPDATE OF d SKIP LOCKED`, sensor, limit*2, limit)
	if err != nil {
		return 0, "", err
	}
	type claim struct{ key, reason string }
	claims := []claim{}
	for rows.Next() {
		var c claim
		if err = rows.Scan(&c.key, &c.reason); err != nil {
			rows.Close()
			return 0, "", err
		}
		claims = append(claims, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, "", err
	}
	count := 0
	lastKey := ""
	for _, c := range claims {
		processed, key, err := processHardwareIdentityTx(ctx, tx, c.key, c.reason)
		if err != nil {
			return 0, key, err
		}
		if !processed {
			break
		}
		count++
		lastKey = key
	}
	if count == 0 {
		return 0, "", nil
	}
	if err = tx.Commit(); err != nil {
		return 0, lastKey, err
	}
	return count, "", nil
}

func processHardwareIdentityTx(ctx context.Context, tx *sql.Tx, key, reason string) (bool, string, error) {
	now := time.Now().UTC()
	facts, err := loadHardwareFacts(ctx, tx, `WITH bounded AS MATERIALIZED (
 SELECT fact_key,data,first_seen,observed_at,active_until,revoked
 FROM passive_hardware_facts WHERE identity_key=$1 ORDER BY fact_key LIMIT 513
)
SELECT data,first_seen,observed_at,active_until,revoked
FROM bounded WHERE (SELECT count(*) FROM bounded)<=512 ORDER BY fact_key`, key)
	if err != nil {
		return false, key, err
	}
	if len(facts) == 0 {
		facts, err = loadHardwareFacts(ctx, tx, compactHardwareFactSQL, key, now)
		if err != nil {
			return false, key, err
		}
	}
	return updateHardwareIdentity(ctx, tx, key, reason, facts, now)
}

// DNS-SD instance names may vary while the classifier input stays identical.
// For overflowing identities only, retain one event per identical DNS-SD
// payload and fold activity bounds across its copies. Receiver/model matching
// compares event times, so preserve the input events for that cohort.
const compactHardwareFactSQL = `WITH retained AS MATERIALIZED (
 SELECT fact_key,source,first_seen,observed_at,active_until,revoked,data->'signals' signals,
 coalesce((data->>'address_only')::boolean,false) address_only
 FROM passive_hardware_facts WHERE identity_key=$1 ORDER BY fact_key LIMIT 4097
), classified AS MATERIALIZED (
 SELECT *,source='dns_sd' AND NOT revoked AND NOT address_only AND observed_at<=$2
 AND NOT EXISTS (
  SELECT 1 FROM retained WHERE NOT revoked AND signals @> '[{"field":"dns_sd_receiver_implementation"}]'::jsonb
 ) AS foldable
 FROM retained WHERE (SELECT count(*) FROM retained)<=4096
), folded AS (
 SELECT DISTINCT ON (signals) fact_key,
 min(first_seen) OVER (PARTITION BY signals) first_seen,observed_at,
 max(active_until) OVER (PARTITION BY signals) active_until,revoked
 FROM classified WHERE foldable
 ORDER BY signals,observed_at DESC,fact_key
), selected AS (
 SELECT fact_key,first_seen,observed_at,active_until,revoked FROM folded
 UNION ALL
 SELECT fact_key,first_seen,observed_at,active_until,revoked FROM classified WHERE NOT foldable
 ORDER BY fact_key LIMIT 513
)
SELECT f.data,s.first_seen,s.observed_at,s.active_until,s.revoked
FROM selected s JOIN passive_hardware_facts f ON f.identity_key=$1 AND f.fact_key=s.fact_key
ORDER BY s.fact_key`

func loadHardwareFacts(ctx context.Context, tx *sql.Tx, statement string, args ...any) ([]HardwareFact, error) {
	rows, err := tx.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	facts := []HardwareFact{}
	factBytes := 0
	for rows.Next() {
		var raw []byte
		var f HardwareFact
		var first, observed, until time.Time
		var revoked bool
		if err = rows.Scan(&raw, &first, &observed, &until, &revoked); err != nil {
			return nil, err
		}
		factBytes += len(raw)
		if factBytes > 1<<20 {
			return nil, fmt.Errorf("hardware identity fact input exceeds 1 MiB")
		}
		if err = json.Unmarshal(raw, &f); err != nil {
			return nil, err
		}
		f.FirstSeen = first
		f.ObservedAt = observed
		f.ActiveUntil = until
		f.Revoked = revoked
		facts = append(facts, f)
	}
	return facts, rows.Err()
}

func updateHardwareIdentity(ctx context.Context, tx *sql.Tx, key, reason string, facts []HardwareFact, now time.Time) (bool, string, error) {
	var previous *HardwareState
	var oldRaw []byte
	err := tx.QueryRowContext(ctx, `SELECT data FROM passive_hardware_current WHERE identity_key=$1`, key).Scan(&oldRaw)
	if err == nil {
		previous = &HardwareState{}
		if err = json.Unmarshal(oldRaw, previous); err != nil {
			return false, key, err
		}
	} else if err != sql.ErrNoRows {
		return false, key, err
	}
	state, err := EvaluateHardwareFacts(facts, previous, now)
	if err != nil {
		return false, key, err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return false, key, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO passive_hardware_current(identity_key,scope_key,device_key,sensor_id,campus_id,access_domain,vlan,vrf,mac,hardware_type,hardware_type_status,hardware_model,hardware_model_status,first_seen,last_seen,active_until,type_evidence_at,type_changed_at,address_only_since,rule_version,data)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
 ON CONFLICT(identity_key) DO UPDATE SET device_key=EXCLUDED.device_key,hardware_type=EXCLUDED.hardware_type,hardware_type_status=EXCLUDED.hardware_type_status,hardware_model=EXCLUDED.hardware_model,hardware_model_status=EXCLUDED.hardware_model_status,first_seen=least(passive_hardware_current.first_seen,EXCLUDED.first_seen),last_seen=EXCLUDED.last_seen,active_until=EXCLUDED.active_until,type_evidence_at=EXCLUDED.type_evidence_at,type_changed_at=EXCLUDED.type_changed_at,address_only_since=EXCLUDED.address_only_since,rule_version=EXCLUDED.rule_version,data=EXCLUDED.data,result_version=passive_hardware_current.result_version+1,updated_at=now()
 WHERE passive_hardware_current.data IS DISTINCT FROM EXCLUDED.data`, state.IdentityKey, state.ScopeKey, state.DeviceKey, state.SensorID, state.CampusID, state.AccessDomain, state.VLAN, state.VRF, state.MAC, state.HardwareType, state.HardwareTypeStatus, state.HardwareModel, state.HardwareModelStatus, state.FirstSeen, state.LastSeen, state.ActiveUntil, state.TypeEvidenceAt, state.TypeChangedAt, state.AddressOnlySince, state.TypeRuleVersion, string(raw))
	if err != nil {
		return false, key, err
	}
	beforeType, beforeStatus := "", ""
	if previous != nil {
		beforeType = previous.HardwareType
		beforeStatus = previous.HardwareTypeStatus
	}
	if beforeType != state.HardwareType || beforeStatus != state.HardwareTypeStatus {
		sources, _ := json.Marshal(state.TypeSources)
		_, err = tx.ExecContext(ctx, `INSERT INTO passive_hardware_changes(identity_key,reason,before_type,after_type,before_status,after_status,rule_version,sources) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, key, reason, beforeType, state.HardwareType, beforeStatus, state.HardwareTypeStatus, state.TypeRuleVersion, string(sources))
		if err != nil {
			return false, key, err
		}
	}
	if previous == nil || hardwareRuleDependenciesChanged(previous.TypeSources, state.TypeSources) {
		if _, err = tx.ExecContext(ctx, `DELETE FROM passive_hardware_rule_dependencies WHERE identity_key=$1`, key); err != nil {
			return false, key, err
		}
		deps := map[string]bool{}
		for _, s := range state.TypeSources {
			dep := s.RuleID + "\x00" + s.RuleVersion
			if deps[dep] {
				continue
			}
			deps[dep] = true
			if _, err = tx.ExecContext(ctx, `INSERT INTO passive_hardware_rule_dependencies(rule_id,rule_version,identity_key) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, s.RuleID, s.RuleVersion, key); err != nil {
				return false, key, err
			}
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM passive_hardware_dirty WHERE identity_key=$1`, key); err != nil {
		return false, key, err
	}
	return true, key, nil
}
