package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/sharedaccess"
)

type sharedDeviceProfileJob struct {
	SubjectKey, SensorID, CampusID, EndpointID, MAC, IP, VLAN, LeaseOwner string
	ObservedAt                                                            time.Time
	DirtyGeneration                                                       int64
	Attempts                                                              int
	DHCPConfirmed                                                         bool
}

type sharedProfileSource struct {
	Assessment *evidence.RouterAssessment
	Discovery  *discovery.Observation
	Shared     *sharedaccess.BehaviorAssessment
}

const sharedDeviceProfileWorkerCount = 8

func normalizedSharedProfileMAC(value string) string {
	parsed, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil || len(parsed) != 6 || parsed[0]&1 != 0 {
		return ""
	}
	return strings.ReplaceAll(parsed.String(), ":", "")
}

func sharedProfileMACDisplay(value string) string {
	normalized := normalizedSharedProfileMAC(value)
	if len(normalized) != 12 {
		return ""
	}
	parts := make([]string, 0, 6)
	for index := 0; index < len(normalized); index += 2 {
		parts = append(parts, normalized[index:index+2])
	}
	return strings.Join(parts, ":")
}

func locallyAdministeredSharedProfileMAC(value string) bool {
	parsed, err := net.ParseMAC(strings.TrimSpace(value))
	return err == nil && len(parsed) == 6 && parsed[0]&2 != 0
}

// A locally administered MAC is not a stable hardware identity by itself. It
// becomes usable only while an event-time DHCP ACK confirms the generated MAC
// endpoint, or when an independent non-MAC endpoint is already present.
func (s *DBStore) normalizeSharedProfileJobIdentity(ctx context.Context, job sharedDeviceProfileJob) (sharedDeviceProfileJob, error) {
	mac := sharedProfileMACDisplay(job.MAC)
	if mac == "" && strings.HasPrefix(job.EndpointID, "mac:") {
		mac = sharedProfileMACDisplay(strings.TrimPrefix(job.EndpointID, "mac:"))
	}
	if mac == "" {
		job.MAC = mac
		return job, nil
	}
	generatedEndpoint := "mac:" + mac
	leaseEndpoint := firstNonEmpty(job.EndpointID, generatedEndpoint)
	var confirmed bool
	err := s.pg.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM device_address_leases
WHERE sensor_id=$1 AND endpoint_id=$2 AND action='ack' AND observed_at<=$3 AND valid_until>=$3)`,
		firstNonEmpty(job.SensorID, s.pg.sensorID), leaseEndpoint, job.ObservedAt).Scan(&confirmed)
	if err != nil {
		return job, err
	}
	job.DHCPConfirmed = confirmed
	if !locallyAdministeredSharedProfileMAC(mac) || job.EndpointID != "" && job.EndpointID != generatedEndpoint {
		job.MAC = mac
		return job, nil
	}
	if confirmed {
		job.EndpointID, job.MAC = generatedEndpoint, mac
		return job, nil
	}
	job.MAC = ""
	if job.EndpointID == generatedEndpoint {
		job.EndpointID = ""
	}
	return job, nil
}

func (s *DBStore) claimSharedDeviceProfileJob(ctx context.Context, worker string) (sharedDeviceProfileJob, bool, error) {
	owner := worker + ":" + appToken()
	row := s.pg.db.QueryRowContext(ctx, `WITH picked AS (
 SELECT subject_key FROM shared_device_profile_jobs
 WHERE ((processed_generation<dirty_generation AND not_before<=now()) OR next_run_at<=now())
 AND lease_until<now() ORDER BY CASE WHEN processed_generation<dirty_generation THEN 0 ELSE 1 END,
 CASE WHEN processed_generation<dirty_generation THEN dirty_since ELSE next_run_at END,subject_key
 FOR UPDATE SKIP LOCKED LIMIT 1)
UPDATE shared_device_profile_jobs j SET lease_owner=$1,lease_until=now()+interval '1 minute',
 dirty_generation=CASE WHEN j.next_run_at<=now() AND j.processed_generation>=j.dirty_generation THEN j.dirty_generation+1 ELSE j.dirty_generation END,
 dirty_since=CASE WHEN j.next_run_at<=now() AND j.processed_generation>=j.dirty_generation THEN now() ELSE j.dirty_since END,
 next_run_at=NULL,updated_at=now() FROM picked p WHERE j.subject_key=p.subject_key
RETURNING j.subject_key,j.sensor_id,j.campus_id,j.endpoint_id,j.mac,coalesce(host(j.ip),''),j.vlan,j.observed_at,j.dirty_generation,j.attempts,j.lease_owner`, owner)
	var job sharedDeviceProfileJob
	if err := row.Scan(&job.SubjectKey, &job.SensorID, &job.CampusID, &job.EndpointID, &job.MAC, &job.IP, &job.VLAN, &job.ObservedAt, &job.DirtyGeneration, &job.Attempts, &job.LeaseOwner); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sharedDeviceProfileJob{}, false, nil
		}
		return sharedDeviceProfileJob{}, false, err
	}
	return job, true, nil
}

func sharedProfileKeyValues(sensor, campus, endpoint, mac, ip, vlan string) [][2]string {
	keys := make([][2]string, 0, 3)
	if endpoint = strings.TrimSpace(endpoint); endpoint != "" {
		keys = append(keys, [2]string{"endpoint", endpoint})
	}
	if mac = normalizedSharedProfileMAC(mac); mac != "" {
		keys = append(keys, [2]string{"mac", mac})
	}
	if ip = strings.TrimSpace(ip); ip != "" {
		keys = append(keys, [2]string{"address", campus + ":" + vlan + ":" + ip})
	}
	return keys
}

func (s *DBStore) existingSharedProfileID(ctx context.Context, sensor, campus string, keys [][2]string, allowAddressPromotion bool) (string, bool, error) {
	if len(keys) == 0 {
		return "", false, nil
	}
	// A scoped address is never allowed to override a stronger physical key.
	// Search one identity class at a time so IP reuse cannot merge hardware.
	for _, keyType := range []string{"endpoint", "mac", "address"} {
		hadKey := false
		for _, key := range keys {
			if key[0] != keyType {
				continue
			}
			hadKey = true
			var id string
			err := s.pg.db.QueryRowContext(ctx, `SELECT profile_id FROM shared_device_profile_keys
WHERE sensor_id=$1 AND campus_id=$2 AND key_type=$3 AND key_value=$4`, sensor, campus, key[0], key[1]).Scan(&id)
			if err == nil {
				return id, false, nil
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return "", false, err
			}
		}
		if hadKey && keyType == "endpoint" {
			hasMAC := false
			for _, key := range keys {
				hasMAC = hasMAC || key[0] == "mac"
			}
			if !hasMAC && !allowAddressPromotion {
				return "", false, nil
			}
		}
		if hadKey && keyType == "mac" && !allowAddressPromotion {
			return "", false, nil
		}
		if hadKey && keyType == "address" {
			parts := strings.SplitN(keys[len(keys)-1][1], ":", 3)
			if len(parts) != 3 || net.ParseIP(parts[2]) == nil {
				return "", false, nil
			}
			addressOnlyClause := ""
			if allowAddressPromotion {
				addressOnlyClause = " AND address_only=true"
			}
			rows, err := s.pg.db.QueryContext(ctx, `SELECT profile_id FROM shared_device_profiles
WHERE sensor_id=$1 AND campus_id=$2 AND primary_ip=$3::inet`+addressOnlyClause+`
 AND merged_into_profile_id IS NULL ORDER BY profile_id LIMIT 2`, sensor, campus, parts[2])
			if err != nil {
				return "", false, err
			}
			ids := []string{}
			for rows.Next() {
				var id string
				if err = rows.Scan(&id); err != nil {
					rows.Close()
					return "", false, err
				}
				ids = append(ids, id)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return "", false, err
			}
			if len(ids) == 1 {
				return ids[0], false, nil
			}
			return "", len(ids) > 1, nil
		}
	}
	return "", false, nil
}

func (s *DBStore) sharedProfileCutover(ctx context.Context) (time.Time, error) {
	var cutover time.Time
	err := s.pg.db.QueryRowContext(ctx, `SELECT cutover_at FROM shared_device_profile_runtime WHERE singleton`).Scan(&cutover)
	return cutover, err
}

func (s *DBStore) loadSharedProfileSources(ctx context.Context, job sharedDeviceProfileJob, existing bool, cutover time.Time) (sharedProfileSource, error) {
	source := sharedProfileSource{}
	mac := normalizedSharedProfileMAC(job.MAC)
	var raw []byte
	var first, last, expires time.Time
	err := s.pg.db.QueryRowContext(ctx, `SELECT assessment,first_seen,last_seen,expires_at FROM router_assessments
	WHERE ($1<>'' AND endpoint_id=$1) OR ($2<>'' AND regexp_replace(lower(mac),'[^0-9a-f]','','g')=$2) OR ($1='' AND $2='' AND $3<>'' AND ip=$3::inet)
ORDER BY CASE status WHEN 'confirmed' THEN 0 WHEN 'likely' THEN 1 ELSE 2 END,
 CASE WHEN brand_reference_only THEN 1 ELSE 0 END,confidence DESC,last_seen DESC,assessment_id LIMIT 1`, job.EndpointID, mac, job.IP).Scan(&raw, &first, &last, &expires)
	if err == nil {
		var item evidence.RouterAssessment
		if err = json.Unmarshal(raw, &item); err != nil {
			return source, err
		}
		item.FirstSeen, item.LastSeen, item.ExpiresAt = first.UTC().Format(time.RFC3339Nano), last.UTC().Format(time.RFC3339Nano), expires.UTC().Format(time.RFC3339Nano)
		if existing || !last.Before(cutover) {
			source.Assessment = &item
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return source, err
	}

	raw = nil
	err = s.pg.db.QueryRowContext(ctx, `SELECT d.data,d.observed_at,d.valid_until FROM discovery_observation_latest d
LEFT JOIN discovery_identity_links l ON l.observation_id=d.id
WHERE (($1<>'' AND l.endpoint_id=$1) OR ($2<>'' AND regexp_replace(lower(coalesce(d.data->>'mac','')),'[^0-9a-f]','','g')=$2) OR ($1='' AND $2='' AND $3<>'' AND d.data->>'ip'=$3))
 AND coalesce(d.data->>'device_type','') IN('router','gateway','access_point','switch','network_device')
ORDER BY d.observed_at DESC,d.id DESC LIMIT 1`, job.EndpointID, mac, job.IP).Scan(&raw, &last, &expires)
	if err == nil {
		var item discovery.Observation
		if err = json.Unmarshal(raw, &item); err != nil {
			return source, err
		}
		item.ObservedAt, item.ValidUntil = last, expires
		if existing || !last.Before(cutover) {
			source.Discovery = &item
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return source, err
	}

	raw = nil
	err = s.pg.db.QueryRowContext(ctx, `SELECT observation,first_seen,last_seen,expires_at FROM shared_behavior_observations
WHERE status='confirmed' AND coverage_state='verified'
 AND coalesce(observation->>'strong_anchor','') IN('ieee1905_association','coexisting_device_models')
 AND coalesce((observation->>'device_lower_bound')::int,0)>=2
 AND (($1<>'' AND endpoint_id=$1) OR ($1='' AND $2<>'' AND ip=$2::inet))
ORDER BY last_seen DESC,observation_id DESC LIMIT 1`, job.EndpointID, job.IP).Scan(&raw, &first, &last, &expires)
	if err == nil {
		var item sharedaccess.BehaviorAssessment
		if err = json.Unmarshal(raw, &item); err != nil {
			return source, err
		}
		item.FirstSeen, item.LastSeen, item.ExpiresAt = first, last, expires
		if existing || !last.Before(cutover) {
			source.Shared = &item
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return source, err
	}
	return source, nil
}

func qualifyingSharedProfileSource(source sharedProfileSource) bool {
	if source.Assessment != nil {
		a := source.Assessment
		if !a.BrandReferenceOnly && !a.Ambiguous && (a.Role == "router" || a.Role == "ap") && (a.Status == "likely" || a.Status == "confirmed") {
			return true
		}
		if a.Infrastructure && !a.Ambiguous {
			return true
		}
	}
	return source.Discovery != nil || source.Shared != nil
}

type sharedProfileAccount struct {
	Binding        evidence.RouterAuthBinding
	At             time.Time
	Active         bool
	Conflict       bool
	NextTransition time.Time
}

func (s *DBStore) latestSharedProfileAccount(ctx context.Context, endpoint, mac string) (sharedProfileAccount, error) {
	mac = normalizedSharedProfileMAC(mac)
	rows, err := s.pg.db.QueryContext(ctx, `WITH candidates AS (
 SELECT p.document,p.confirmed_at,CASE WHEN coalesce(p.document->>'ended_at','')='' THEN
  coalesce(src.observed_at,p.confirmed_at)+make_interval(secs=>GREATEST(60,LEAST(86400,coalesce(nullif(p.document->>'reconcile_interval_seconds','')::int,1800)))*3)
  ELSE p.confirmed_at END active_until FROM account_identity_session_projection p
 LEFT JOIN account_identity_projection_sources src USING(source,sensor_id,campus_id,access_domain)
 WHERE $1<>'' AND coalesce(p.document->>'endpoint_id','')<>'' AND p.document->>'endpoint_id'=$1
 UNION ALL
 SELECT p.document,p.confirmed_at,CASE WHEN coalesce(p.document->>'ended_at','')='' THEN
  coalesce(src.observed_at,p.confirmed_at)+make_interval(secs=>GREATEST(60,LEAST(86400,coalesce(nullif(p.document->>'reconcile_interval_seconds','')::int,1800)))*3)
  ELSE p.confirmed_at END active_until FROM account_identity_session_projection p
 LEFT JOIN account_identity_projection_sources src USING(source,sensor_id,campus_id,access_domain)
 WHERE $2<>'' AND coalesce(p.document->>'mac','')<>''
  AND regexp_replace(lower(coalesce(p.document->>'mac','')),'[^0-9a-f]','','g')=$2
  AND ($1='' OR coalesce(p.document->>'endpoint_id','')<>$1)
 UNION ALL
 SELECT to_jsonb(s)||coalesce(s.policy_metadata,'{}'::jsonb),s.updated_at,
  CASE WHEN s.ended_at IS NULL THEN s.updated_at+interval '90 minutes' ELSE s.updated_at END FROM account_sessions s
 WHERE $1<>'' AND coalesce(s.endpoint_id,'')<>'' AND s.endpoint_id=$1
 UNION ALL
 SELECT to_jsonb(s)||coalesce(s.policy_metadata,'{}'::jsonb),s.updated_at,
  CASE WHEN s.ended_at IS NULL THEN s.updated_at+interval '90 minutes' ELSE s.updated_at END FROM account_sessions s
 WHERE $2<>'' AND coalesce(s.mac,'')<>'' AND regexp_replace(lower(coalesce(s.mac,'')),'[^0-9a-f]','','g')=$2
  AND ($1='' OR coalesce(s.endpoint_id,'')<>$1)
) SELECT document,confirmed_at,active_until FROM candidates ORDER BY confirmed_at DESC,document->>'account_id',document->>'session_id' LIMIT 16`, endpoint, mac)
	if err != nil {
		return sharedProfileAccount{}, err
	}
	defer rows.Close()
	result := sharedProfileAccount{}
	activeAccounts := map[string]bool{}
	now := time.Now()
	for rows.Next() {
		var raw []byte
		var at time.Time
		var activeUntil time.Time
		if err = rows.Scan(&raw, &at, &activeUntil); err != nil {
			return result, err
		}
		var session AccountSession
		if err = json.Unmarshal(raw, &session); err != nil {
			return result, err
		}
		if session.AccountID == "" || session.SessionID == "" {
			continue
		}
		active := session.EndedAt == "" && activeUntil.After(now)
		if active {
			activeAccounts[session.AccountID] = true
			result.NextTransition = earliestProfileTime(result.NextTransition, activeUntil)
		}
		if result.Binding.AccountID != "" {
			continue
		}
		basis := "exact_mac"
		if endpoint != "" && session.EndpointID == endpoint {
			basis = "exact_endpoint"
		}
		result = sharedProfileAccount{At: at, Active: active, NextTransition: result.NextTransition, Binding: evidence.RouterAuthBinding{
			SessionID: session.SessionID, AccountID: session.AccountID, AssignedIPs: []string{}, MAC: session.MAC,
			VLAN: session.VLAN, NASIP: session.NASIP, AccessID: session.AccessID, Source: session.Source,
			MatchBasis: basis, StartedAt: session.StartedAt, LastConfirmedAt: at.UTC().Format(time.RFC3339Nano),
		}}
		if session.IP != "" {
			result.Binding.AssignedIPs = []string{session.IP}
		}
	}
	result.Conflict = len(activeAccounts) > 1
	return result, rows.Err()
}

func parseProfileTime(raw string) time.Time {
	value, _ := time.Parse(time.RFC3339Nano, raw)
	return value
}

func latestProfileTime(values ...time.Time) time.Time {
	var latest time.Time
	for _, value := range values {
		if value.After(latest) {
			latest = value
		}
	}
	return latest
}

func earliestProfileTime(values ...time.Time) time.Time {
	var earliest time.Time
	for _, value := range values {
		if value.IsZero() {
			continue
		}
		if earliest.IsZero() || value.Before(earliest) {
			earliest = value
		}
	}
	return earliest
}

func sharedProfileProjectionChanged(previous []byte, current SharedDeviceProfile) bool {
	if len(previous) == 0 {
		return true
	}
	var old SharedDeviceProfile
	if json.Unmarshal(previous, &old) != nil {
		return true
	}
	old.MaterializedAt = time.Time{}
	current.MaterializedAt = time.Time{}
	oldRaw, _ := json.Marshal(old)
	currentRaw, _ := json.Marshal(current)
	return !bytes.Equal(oldRaw, currentRaw)
}

func (s *DBStore) buildSharedDeviceProfile(ctx context.Context, job sharedDeviceProfileJob) (SharedDeviceProfile, [][2]string, time.Time, bool, error) {
	sensor := strings.TrimSpace(job.SensorID)
	if sensor == "" {
		sensor = s.pg.sensorID
	}
	job.SensorID = sensor
	var err error
	job, err = s.normalizeSharedProfileJobIdentity(ctx, job)
	if err != nil {
		return SharedDeviceProfile{}, nil, time.Time{}, false, err
	}
	keys := sharedProfileKeyValues(sensor, job.CampusID, job.EndpointID, job.MAC, job.IP, job.VLAN)
	profileID, keyConflict, err := s.existingSharedProfileID(ctx, sensor, job.CampusID, keys, job.DHCPConfirmed)
	if err != nil {
		return SharedDeviceProfile{}, nil, time.Time{}, false, err
	}
	existing := profileID != ""
	cutover, err := s.sharedProfileCutover(ctx)
	if err != nil {
		return SharedDeviceProfile{}, nil, time.Time{}, false, err
	}
	profile := SharedDeviceProfile{SensorID: sensor, CampusID: job.CampusID, EndpointID: job.EndpointID, MAC: sharedProfileMACDisplay(job.MAC), IP: job.IP, VLAN: job.VLAN, AddressState: "unbound", IdentityState: "reference", IdentityConflict: keyConflict, MaterializedAt: time.Now().UTC()}
	if existing {
		var raw []byte
		if err = s.pg.db.QueryRowContext(ctx, `SELECT list_item FROM shared_device_profiles WHERE profile_id=$1`, profileID).Scan(&raw); err != nil {
			return profile, keys, time.Time{}, false, err
		}
		if err = json.Unmarshal(raw, &profile); err != nil {
			return profile, keys, time.Time{}, false, err
		}
		profile.EndpointID = firstNonEmpty(job.EndpointID, profile.EndpointID)
		profile.MAC = firstNonEmpty(sharedProfileMACDisplay(job.MAC), profile.MAC)
		profile.MaterializedAt = time.Now().UTC()
		profile.IdentityConflict = profile.IdentityConflict || keyConflict
	}
	sourceJob := job
	if existing && sourceJob.EndpointID == "" && sourceJob.MAC == "" {
		sourceJob.EndpointID, sourceJob.MAC = profile.EndpointID, profile.MAC
	}
	sources, err := s.loadSharedProfileSources(ctx, sourceJob, existing, cutover)
	if err != nil {
		return SharedDeviceProfile{}, nil, time.Time{}, false, err
	}
	if !existing && !qualifyingSharedProfileSource(sources) {
		return SharedDeviceProfile{}, keys, time.Time{}, false, nil
	}
	if profileID == "" {
		identity := job.IP
		if len(keys) > 0 {
			identity = keys[0][0] + ":" + keys[0][1]
		}
		profileID = stableSharedBehaviorID("shared-device-profile-v2", sensor+"|"+job.CampusID+"|"+identity)
	}
	profile.ProfileID = profileID
	now := time.Now().UTC()
	firstSeen := earliestProfileTime(job.ObservedAt, profile.FirstSeen)
	lastObserved := latestProfileTime(job.ObservedAt, profile.LastObservedAt)
	nextTransition := time.Time{}
	if a := sources.Assessment; a != nil {
		first, last, expires := parseProfileTime(a.FirstSeen), parseProfileTime(a.LastSeen), parseProfileTime(a.ExpiresAt)
		firstSeen, lastObserved = earliestProfileTime(firstSeen, first), latestProfileTime(lastObserved, last)
		profile.EndpointID, profile.IP = firstNonEmpty(job.EndpointID, profile.EndpointID), firstNonEmpty(a.IP, profile.IP)
		profile.MAC = firstNonEmpty(sharedProfileMACDisplay(job.MAC), profile.MAC)
		profile.Brand, profile.Model, profile.Role = a.Brand, a.Model, a.Role
		profile.Confidence, profile.IdentityConflict = a.Confidence, profile.IdentityConflict || a.Ambiguous || len(a.Conflicts) > 0
		profile.IdentityAssessmentID, profile.IdentityEvidenceID = a.AssessmentID, ""
		if len(a.Evidence) > 0 {
			profile.IdentityBasis = a.Evidence[0].Explanation
		}
		profile.RuleVersion = a.RuleVersion
		profile.IdentityAt, profile.IdentityExpiresAt = last, expires
		profile.IdentityCurrent = expires.After(now) && !a.Ambiguous && !a.BrandReferenceOnly && (a.Status == "likely" || a.Status == "confirmed")
		profile.IdentityState = "historical"
		if profile.IdentityCurrent {
			profile.IdentityState = "supported"
		}
		if expires.After(now) {
			nextTransition = earliestProfileTime(nextTransition, expires)
		}
	}
	if d := sources.Discovery; d != nil {
		firstSeen, lastObserved = earliestProfileTime(firstSeen, d.ObservedAt), latestProfileTime(lastObserved, d.ObservedAt)
		profile.EndpointID, profile.IP = firstNonEmpty(profile.EndpointID, job.EndpointID), firstNonEmpty(profile.IP, d.IP)
		profile.MAC = firstNonEmpty(profile.MAC, sharedProfileMACDisplay(job.MAC))
		if profile.Role == "" {
			profile.Role = d.DeviceType
		}
		if profile.DisplayName == "" {
			profile.DisplayName = d.Name
		}
		if profile.IdentityAt.IsZero() || d.ObservedAt.After(profile.IdentityAt) {
			profile.IdentityAt, profile.IdentityExpiresAt = d.ObservedAt, d.ValidUntil
			profile.IdentityBasis = d.Explanation
		}
		if d.ValidUntil.After(now) {
			profile.IdentityCurrent = true
			if profile.IdentityState == "reference" {
				profile.IdentityState = "supported"
			}
			nextTransition = earliestProfileTime(nextTransition, d.ValidUntil)
		}
	}
	if shared := sources.Shared; shared != nil {
		firstSeen, lastObserved = earliestProfileTime(firstSeen, shared.FirstSeen), latestProfileTime(lastObserved, shared.LastSeen)
		profile.LastSharedAt, profile.LastSharedObservationID = &shared.LastSeen, shared.ObservationID
		profile.CurrentShared = shared.ExpiresAt.After(now) && shared.WindowEnd.After(now.Add(-20*time.Minute))
		profile.SharedConfidence = shared.Confidence
		if profile.Role == "" {
			profile.Role = "shared_gateway"
		}
		if shared.ExpiresAt.After(now) {
			nextTransition = earliestProfileTime(nextTransition, shared.ExpiresAt)
		}
	}
	if profile.IdentityAt.IsZero() {
		profile.IdentityAt = lastObserved
	}
	if profile.IdentityExpiresAt.IsZero() {
		profile.IdentityExpiresAt = profile.IdentityAt
	}
	if profile.Brand != "" || profile.Model != "" {
		profile.DisplayName = strings.TrimSpace(strings.Join([]string{profile.Brand, profile.Model}, " "))
	}
	if profile.DisplayName == "" {
		profile.DisplayName = firstNonEmpty(profile.IP, profile.MAC)
	}
	account, err := s.latestSharedProfileAccount(ctx, profile.EndpointID, profile.MAC)
	if err != nil {
		return profile, keys, time.Time{}, false, err
	}
	profile.AuthBindings = []evidence.RouterAuthBinding{}
	if account.Binding.AccountID != "" {
		profile.AuthBindings = []evidence.RouterAuthBinding{account.Binding}
		profile.LatestAccountID, profile.LatestAccountAt, profile.LatestAccountActive = account.Binding.AccountID, &account.At, account.Active
		profile.LatestAccountMatchBasis, profile.AccountConflict = account.Binding.MatchBasis, account.Conflict
		lastObserved = latestProfileTime(lastObserved, account.At)
	}
	nextTransition = earliestProfileTime(nextTransition, account.NextTransition)
	if profile.EndpointID != "" {
		var leaseIP, action string
		var observed, validUntil time.Time
		err = s.pg.db.QueryRowContext(ctx, `SELECT host(ip),action,observed_at,valid_until FROM device_address_leases
WHERE sensor_id=$1 AND endpoint_id=$2 ORDER BY observed_at DESC,event_id DESC LIMIT 1`, sensor, profile.EndpointID).Scan(&leaseIP, &action, &observed, &validUntil)
		if err == nil {
			profile.IP = leaseIP
			profile.AddressState = "stale"
			if action == "ack" && validUntil.After(now) {
				profile.AddressState = "verified"
				nextTransition = earliestProfileTime(nextTransition, validUntil)
			}
			lastObserved = latestProfileTime(lastObserved, observed)
		} else if !errors.Is(err, sql.ErrNoRows) {
			return profile, keys, time.Time{}, false, err
		}
		if profile.IP != "" {
			var latestOwner string
			var latestAt time.Time
			leaseErr := s.pg.db.QueryRowContext(ctx, `SELECT endpoint_id,observed_at FROM device_address_leases
WHERE sensor_id=$1 AND ip=$2::inet ORDER BY observed_at DESC,event_id DESC LIMIT 1`, sensor, profile.IP).Scan(&latestOwner, &latestAt)
			if leaseErr == nil && latestOwner != profile.EndpointID {
				profile.AddressState = "reassigned"
				profile.CurrentShared = false
				lastObserved = latestProfileTime(lastObserved, latestAt)
			} else if leaseErr != nil && !errors.Is(leaseErr, sql.ErrNoRows) {
				return profile, keys, time.Time{}, false, leaseErr
			}
		}
	}
	profile.AddressOnly = profile.EndpointID == "" && profile.MAC == ""
	profile.Addresses = []string{}
	if profile.IP != "" {
		profile.Addresses = append(profile.Addresses, profile.IP)
	}
	profile.FirstSeen, profile.LastObservedAt = firstSeen, lastObserved
	keys = sharedProfileKeyValues(sensor, profile.CampusID, profile.EndpointID, profile.MAC, profile.IP, profile.VLAN)
	sort.Slice(keys, func(i, j int) bool { return keys[i][0]+keys[i][1] < keys[j][0]+keys[j][1] })
	return profile, keys, nextTransition, true, nil
}

func (s *DBStore) publishSharedDeviceProfile(ctx context.Context, job sharedDeviceProfileJob, profile SharedDeviceProfile, keys [][2]string, nextTransition time.Time) error {
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current bool
	if err = tx.QueryRowContext(ctx, `SELECT lease_owner=$2 AND lease_until>clock_timestamp() FROM shared_device_profile_jobs WHERE subject_key=$1 FOR UPDATE`, job.SubjectKey, job.LeaseOwner).Scan(&current); err != nil || !current {
		if err == nil {
			err = errRecognitionLeaseLost
		}
		return err
	}
	profile.IdentityConflict = profile.IdentityConflict || false
	for _, key := range keys {
		var owner string
		err = tx.QueryRowContext(ctx, `SELECT profile_id FROM shared_device_profile_keys WHERE sensor_id=$1 AND campus_id=$2 AND key_type=$3 AND key_value=$4`, profile.SensorID, profile.CampusID, key[0], key[1]).Scan(&owner)
		if err == nil && owner != profile.ProfileID {
			profile.IdentityConflict = true
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	raw, err := json.Marshal(profile)
	if err != nil {
		return err
	}
	var previous []byte
	err = tx.QueryRowContext(ctx, `SELECT list_item FROM shared_device_profiles WHERE profile_id=$1 FOR UPDATE`, profile.ProfileID).Scan(&previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO shared_device_profiles(
 profile_id,sensor_id,campus_id,endpoint_id,mac,primary_ip,vlan,display_name,role,brand,model,recognition_status,confidence,
 identity_conflict,latest_account_id,latest_account_at,latest_account_active,latest_account_match_basis,account_conflict,
 identity_current,identity_at,identity_expires_at,current_shared,shared_confidence,last_shared_at,last_observed_at,first_seen,
 source_rule_version,source_assessment_id,source_evidence_id,source_shared_observation_id,address_state,address_only,list_item,next_transition_at,materialized_at,updated_at)
VALUES($1,$2,$3,$4,$5,nullif($6,'')::inet,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,now(),now())
ON CONFLICT(profile_id) DO UPDATE SET sensor_id=EXCLUDED.sensor_id,campus_id=EXCLUDED.campus_id,endpoint_id=EXCLUDED.endpoint_id,
 mac=EXCLUDED.mac,primary_ip=EXCLUDED.primary_ip,vlan=EXCLUDED.vlan,display_name=EXCLUDED.display_name,role=EXCLUDED.role,
 brand=EXCLUDED.brand,model=EXCLUDED.model,recognition_status=EXCLUDED.recognition_status,confidence=EXCLUDED.confidence,
 identity_conflict=EXCLUDED.identity_conflict,latest_account_id=EXCLUDED.latest_account_id,latest_account_at=EXCLUDED.latest_account_at,
 latest_account_active=EXCLUDED.latest_account_active,latest_account_match_basis=EXCLUDED.latest_account_match_basis,
 account_conflict=EXCLUDED.account_conflict,identity_current=EXCLUDED.identity_current,identity_at=EXCLUDED.identity_at,
 identity_expires_at=EXCLUDED.identity_expires_at,current_shared=EXCLUDED.current_shared,shared_confidence=EXCLUDED.shared_confidence,
 last_shared_at=EXCLUDED.last_shared_at,last_observed_at=GREATEST(shared_device_profiles.last_observed_at,EXCLUDED.last_observed_at),
 first_seen=LEAST(shared_device_profiles.first_seen,EXCLUDED.first_seen),source_rule_version=EXCLUDED.source_rule_version,
 source_assessment_id=EXCLUDED.source_assessment_id,source_evidence_id=EXCLUDED.source_evidence_id,
 source_shared_observation_id=EXCLUDED.source_shared_observation_id,address_state=EXCLUDED.address_state,address_only=EXCLUDED.address_only,
 list_item=EXCLUDED.list_item,next_transition_at=EXCLUDED.next_transition_at,materialized_at=now(),updated_at=now()`,
		profile.ProfileID, profile.SensorID, profile.CampusID, profile.EndpointID, profile.MAC, profile.IP, profile.VLAN,
		profile.DisplayName, profile.Role, profile.Brand, profile.Model, profile.IdentityState, profile.Confidence, profile.IdentityConflict,
		profile.LatestAccountID, profile.LatestAccountAt, profile.LatestAccountActive, profile.LatestAccountMatchBasis, profile.AccountConflict,
		profile.IdentityCurrent, profile.IdentityAt, profile.IdentityExpiresAt, profile.CurrentShared, profile.SharedConfidence,
		profile.LastSharedAt, profile.LastObservedAt, profile.FirstSeen, profile.RuleVersion, profile.IdentityAssessmentID,
		profile.IdentityEvidenceID, profile.LastSharedObservationID, profile.AddressState, profile.AddressOnly, raw, nullTimeValue(sql.NullTime{Time: nextTransition, Valid: !nextTransition.IsZero()})); err != nil {
		return err
	}
	for _, key := range keys {
		reliable := key[0] != "address"
		_, err = tx.ExecContext(ctx, `INSERT INTO shared_device_profile_keys(sensor_id,campus_id,key_type,key_value,profile_id,reliable,first_seen,last_seen)
VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(sensor_id,campus_id,key_type,key_value) DO UPDATE SET
 reliable=shared_device_profile_keys.reliable OR EXCLUDED.reliable,last_seen=GREATEST(shared_device_profile_keys.last_seen,EXCLUDED.last_seen)
 WHERE shared_device_profile_keys.profile_id=EXCLUDED.profile_id`, profile.SensorID, profile.CampusID, key[0], key[1], profile.ProfileID, reliable, profile.FirstSeen, profile.LastObservedAt)
		if err != nil {
			return err
		}
	}
	if sharedProfileProjectionChanged(previous, profile) {
		if _, err = tx.ExecContext(ctx, `INSERT INTO shared_device_profile_history(profile_id,change_kind,observed_at,source_id,payload) VALUES($1,'projection',$2,$3,$4)`, profile.ProfileID, profile.LastObservedAt, job.SubjectKey, raw); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE shared_device_profile_jobs SET processed_generation=GREATEST(processed_generation,$2),attempts=0,
 lease_owner='',lease_until='-infinity',last_error='',next_run_at=$3,updated_at=now() WHERE subject_key=$1 AND lease_owner=$4`, job.SubjectKey, job.DirtyGeneration, nullTimeValue(sql.NullTime{Time: nextTransition, Valid: !nextTransition.IsZero()}), job.LeaseOwner)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE shared_device_profile_runtime SET last_success_at=now(),last_error='',processed_jobs=processed_jobs+1,updated_at=now() WHERE singleton`)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *DBStore) finishSharedDeviceProfileJob(ctx context.Context, job sharedDeviceProfileJob, runErr error) error {
	if runErr == nil {
		result, err := s.pg.db.ExecContext(ctx, `UPDATE shared_device_profile_jobs SET processed_generation=GREATEST(processed_generation,$2),attempts=0,
 lease_owner='',lease_until='-infinity',last_error='',updated_at=now() WHERE subject_key=$1 AND lease_owner=$3`, job.SubjectKey, job.DirtyGeneration, job.LeaseOwner)
		if err != nil {
			return err
		}
		changed, _ := result.RowsAffected()
		if changed != 1 {
			return errRecognitionLeaseLost
		}
		_, err = s.pg.db.ExecContext(ctx, `UPDATE shared_device_profile_runtime SET last_success_at=now(),last_error='',processed_jobs=processed_jobs+1,updated_at=now() WHERE singleton`)
		return nil
	}
	attempts := job.Attempts + 1
	delay := time.Second * time.Duration(1<<min(attempts, 8))
	if delay > 5*time.Minute {
		delay = 5 * time.Minute
	}
	_, err := s.pg.db.ExecContext(ctx, `UPDATE shared_device_profile_jobs SET attempts=$2,lease_owner='',lease_until='-infinity',last_error=$3,
 not_before=now()+$4::interval,updated_at=now() WHERE subject_key=$1 AND lease_owner=$5`, job.SubjectKey, attempts, runErr.Error(), delay.String(), job.LeaseOwner)
	if err == nil {
		_, _ = s.pg.db.ExecContext(ctx, `UPDATE shared_device_profile_runtime SET last_error=$1,updated_at=now() WHERE singleton`, runErr.Error())
	}
	return err
}

func (s *DBStore) processSharedDeviceProfileJob(ctx context.Context, worker string) (bool, error) {
	job, found, err := s.claimSharedDeviceProfileJob(ctx, worker)
	if err != nil || !found {
		return found, err
	}
	profile, keys, nextTransition, publish, runErr := s.buildSharedDeviceProfile(ctx, job)
	if runErr == nil && publish {
		runErr = s.publishSharedDeviceProfile(ctx, job, profile, keys, nextTransition)
		if runErr == nil {
			return true, nil
		}
	}
	finishErr := s.finishSharedDeviceProfileJob(ctx, job, runErr)
	if runErr != nil {
		return true, runErr
	}
	return true, finishErr
}

func (s *DBStore) runSharedDeviceProfileMaterializer(ctx context.Context) {
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for ctx.Err() == nil {
			work, cancel := context.WithTimeout(ctx, 20*time.Second)
			_, err := s.pg.pruneSharedDeviceProfileHistory(work, 1000)
			cancel()
			if err != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "shared device profile history retention:", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Hour):
			}
		}
	}()
	for index := 0; index < sharedDeviceProfileWorkerCount; index++ {
		workers.Add(1)
		go func(workerIndex int) {
			defer workers.Done()
			worker := fmt.Sprintf("shared-device-profile-%d-%d", os.Getpid(), workerIndex)
			for ctx.Err() == nil {
				work, cancel := context.WithTimeout(ctx, 20*time.Second)
				found, err := s.processSharedDeviceProfileJob(work, worker)
				if !found && err == nil {
					_, err = s.pg.db.ExecContext(work, `UPDATE shared_device_profile_runtime SET last_success_at=now(),updated_at=now() WHERE singleton AND updated_at<now()-interval '5 seconds'`)
				}
				cancel()
				if err != nil && ctx.Err() == nil {
					fmt.Fprintln(os.Stderr, "shared device profile materializer:", err)
				}
				delay := 100 * time.Millisecond
				if !found || err != nil {
					delay = time.Second
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(delay):
				}
			}
		}(index)
	}
	workers.Wait()
}

func (s *PostgresStore) pruneSharedDeviceProfileHistory(ctx context.Context, limit int) (int64, error) {
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	result, err := s.db.ExecContext(ctx, `WITH expired AS (SELECT history_id FROM shared_device_profile_history WHERE created_at<now()-interval '365 days' ORDER BY created_at LIMIT $1) DELETE FROM shared_device_profile_history h USING expired e WHERE h.history_id=e.history_id`, limit)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
