package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/sharedaccess"
)

// Profiles preserve passive identity evidence. They never participate in scoring
// or enforcement, and address activity cannot refresh identity or sharing proof.
type SharedDeviceProfile struct {
	ProfileID               string                       `json:"profile_id"`
	SensorID                string                       `json:"sensor_id,omitempty"`
	EndpointID              string                       `json:"endpoint_id,omitempty"`
	MAC                     string                       `json:"mac,omitempty"`
	IP                      string                       `json:"ip,omitempty"`
	Brand                   string                       `json:"brand,omitempty"`
	Model                   string                       `json:"model,omitempty"`
	Role                    string                       `json:"role,omitempty"`
	IdentityState           string                       `json:"identity_state"`
	IdentityCurrent         bool                         `json:"identity_current"`
	IdentityAt              time.Time                    `json:"identity_at"`
	IdentityExpiresAt       time.Time                    `json:"identity_expires_at"`
	IdentityEvidenceID      string                       `json:"identity_evidence_id"`
	IdentityAssessmentID    string                       `json:"identity_assessment_id"`
	IdentityBasis           string                       `json:"identity_basis"`
	AddressState            string                       `json:"address_state"`
	AddressLastActivityAt   *time.Time                   `json:"address_last_activity_at,omitempty"`
	LastSharedAt            *time.Time                   `json:"last_shared_at,omitempty"`
	LastSharedObservationID string                       `json:"last_shared_observation_id,omitempty"`
	CurrentShared           bool                         `json:"current_shared"`
	AddressOnly             bool                         `json:"address_only"`
	AuthBindings            []evidence.RouterAuthBinding `json:"auth_bindings,omitempty"`
}

type SharedDeviceProfileQuery struct {
	Keyword       string
	Limit, Cursor int
}
type SharedDeviceProfilePage struct {
	Items         []SharedDeviceProfile `json:"items"`
	Page          Page                  `json:"page"`
	ActivityState string                `json:"activity_state,omitempty"`
	CheckedAt     time.Time             `json:"checked_at"`
}
type SharedDeviceProfileReader interface {
	ListSharedDeviceProfiles(context.Context, SharedDeviceProfileQuery) (SharedDeviceProfilePage, error)
}

func independentDeviceRole(f evidence.RouterEvidence) bool {
	return (f.Role == "router" || f.Role == "ap") && !f.BrandReferenceOnly && !f.Conflict && !f.Exclusion && f.Score >= 30 && f.SourceFamily != "shared_gateway_behavior" && f.SourceFamily != "derived" && f.SourceFamily != "weak_stack" && f.Kind != "confirmed_router"
}
func buildSharedDeviceProfiles(facts []evidence.RouterEvidence, now time.Time) []SharedDeviceProfile {
	selected := map[string]evidence.RouterEvidence{}
	exclusions := map[string]time.Time{}
	keyFor := func(f evidence.RouterEvidence) string {
		identity := "address:" + f.IP + ":" + f.VLAN
		if f.MAC != "" {
			identity = "mac:" + strings.ToLower(f.MAC)
		} else if f.EndpointID != "" {
			identity = "endpoint:" + f.EndpointID
		}
		return f.SensorID + "|" + identity
	}
	for _, f := range facts {
		at, err := time.Parse(time.RFC3339Nano, f.LastSeen)
		if err != nil || at.After(now) {
			continue
		}
		key := keyFor(f)
		if f.Exclusion || f.Conflict {
			if at.After(exclusions[key]) {
				exclusions[key] = at
			}
			continue
		}
		if !independentDeviceRole(f) && !(f.BrandAttribution && f.BrandReferenceOnly && f.Brand != "" && f.SourceFamily != "shared_gateway_behavior") {
			continue
		}
		old, exists := selected[key]
		oldAt, _ := time.Parse(time.RFC3339Nano, old.LastSeen)
		if !exists || independentDeviceRole(f) && !independentDeviceRole(old) || independentDeviceRole(f) == independentDeviceRole(old) && (at.After(oldAt) || at.Equal(oldAt) && f.EvidenceID < old.EvidenceID) {
			selected[key] = f
		}
	}
	profiles := []SharedDeviceProfile{}
	for key, f := range selected {
		at, _ := time.Parse(time.RFC3339Nano, f.LastSeen)
		expires, _ := time.Parse(time.RFC3339Nano, f.ExpiresAt)
		role := ""
		state := "reference"
		current := independentDeviceRole(f) && expires.After(now) && exclusions[key].Before(at)
		if independentDeviceRole(f) {
			role = f.Role
			state = "historical"
			if current {
				state = "supported"
			}
		}
		profiles = append(profiles, SharedDeviceProfile{ProfileID: stableSharedBehaviorID("device-profile", key), SensorID: f.SensorID, EndpointID: f.EndpointID, MAC: f.MAC, IP: f.IP, Brand: f.Brand, Model: f.Model, Role: role, IdentityState: state, IdentityCurrent: current, IdentityAt: at, IdentityExpiresAt: expires, IdentityEvidenceID: f.EvidenceID, IdentityAssessmentID: f.AssessmentID, IdentityBasis: f.Explanation, AddressState: "unbound", AddressOnly: f.MAC == "" && f.EndpointID == ""})
	}
	// Do not merge unowned IP observations into a physical device. Suppress a
	// duplicate address reference only when its role/model matches a stable profile.
	result := []SharedDeviceProfile{}
	for _, p := range profiles {
		duplicate := false
		if p.AddressOnly {
			for _, known := range profiles {
				if !known.AddressOnly && p.SensorID == known.SensorID && p.IP == known.IP && p.Brand == known.Brand && p.Model == known.Model && p.Role == known.Role {
					duplicate = true
					break
				}
			}
		}
		if !duplicate {
			result = append(result, p)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if (result[i].Role != "") != (result[j].Role != "") {
			return result[i].Role != ""
		}
		if !result[i].IdentityAt.Equal(result[j].IdentityAt) {
			return result[i].IdentityAt.After(result[j].IdentityAt)
		}
		return result[i].ProfileID < result[j].ProfileID
	})
	return result
}

// Authentication can make a low-confidence router observation operationally useful
// without making the router role itself more certain. Keep these observations out of
// the durable identity archive unless a current session matches the same MAC or
// endpoint exactly; the caller performs that exact-session check before publishing.
func buildAuthBackedRouterCandidates(facts []evidence.RouterEvidence, now time.Time) []SharedDeviceProfile {
	selected := map[string]evidence.RouterEvidence{}
	for _, f := range facts {
		at, err := time.Parse(time.RFC3339Nano, f.LastSeen)
		if err != nil || at.After(now) || f.Role != "router" || independentDeviceRole(f) || f.BrandReferenceOnly || f.Conflict || f.Exclusion || f.Score <= 0 || f.SourceFamily == "shared_gateway_behavior" || f.SourceFamily == "derived" || f.SourceFamily == "weak_stack" {
			continue
		}
		identity := ""
		if f.MAC != "" {
			identity = "mac:" + strings.ToLower(f.MAC)
		} else if f.EndpointID != "" {
			identity = "endpoint:" + f.EndpointID
		}
		if identity == "" {
			continue
		}
		key := f.SensorID + "|" + identity
		old, exists := selected[key]
		oldAt, _ := time.Parse(time.RFC3339Nano, old.LastSeen)
		if !exists || at.After(oldAt) || at.Equal(oldAt) && f.EvidenceID < old.EvidenceID {
			selected[key] = f
		}
	}
	profiles := make([]SharedDeviceProfile, 0, len(selected))
	for key, f := range selected {
		at, _ := time.Parse(time.RFC3339Nano, f.LastSeen)
		expires, _ := time.Parse(time.RFC3339Nano, f.ExpiresAt)
		profiles = append(profiles, SharedDeviceProfile{
			ProfileID:            stableSharedBehaviorID("device-profile", key),
			SensorID:             f.SensorID,
			EndpointID:           f.EndpointID,
			MAC:                  f.MAC,
			IP:                   f.IP,
			Brand:                f.Brand,
			Model:                f.Model,
			Role:                 "router",
			IdentityState:        "reference",
			IdentityCurrent:      false,
			IdentityAt:           at,
			IdentityExpiresAt:    expires,
			IdentityEvidenceID:   f.EvidenceID,
			IdentityAssessmentID: f.AssessmentID,
			IdentityBasis:        f.Explanation,
			AddressState:         "unbound",
		})
	}
	return profiles
}

func sortSharedDeviceProfiles(profiles []SharedDeviceProfile) {
	sort.Slice(profiles, func(i, j int) bool {
		if (profiles[i].Role != "") != (profiles[j].Role != "") {
			return profiles[i].Role != ""
		}
		if !profiles[i].IdentityAt.Equal(profiles[j].IdentityAt) {
			return profiles[i].IdentityAt.After(profiles[j].IdentityAt)
		}
		return profiles[i].ProfileID < profiles[j].ProfileID
	})
}

func (s *PostgresStore) ListSharedDeviceProfiles(ctx context.Context, q SharedDeviceProfileQuery) (SharedDeviceProfilePage, error) {
	if q.Limit == 0 {
		q.Limit = 20
	}
	if q.Limit < 1 || q.Limit > 100 || q.Cursor < 0 {
		return SharedDeviceProfilePage{}, fmt.Errorf("invalid device profile pagination")
	}
	now := time.Now().UTC()
	rows, err := s.db.QueryContext(ctx, `SELECT data,host(ip),endpoint_id,mac,first_seen,last_seen,expires_at FROM router_evidence_facts
WHERE ip IS NOT NULL AND kind<>'confirmed_router' AND source_family NOT IN ('shared_gateway_behavior','derived','weak_stack')
 AND (data->>'role' IN ('router','ap') OR COALESCE(data->>'brand_attribution','false')='true' OR exclusion OR conflict)
 AND COALESCE(NULLIF(data->>'sensor_id',''),$1)=$1
ORDER BY last_seen DESC,evidence_id LIMIT 10001`, s.sensorID)
	if err != nil {
		return SharedDeviceProfilePage{}, err
	}
	facts := []evidence.RouterEvidence{}
	for rows.Next() {
		var raw []byte
		var f evidence.RouterEvidence
		var first, last, expires time.Time
		if err = rows.Scan(&raw, &f.IP, &f.EndpointID, &f.MAC, &first, &last, &expires); err != nil {
			rows.Close()
			return SharedDeviceProfilePage{}, err
		}
		ip, endpoint, mac := f.IP, f.EndpointID, f.MAC
		if err = json.Unmarshal(raw, &f); err != nil {
			rows.Close()
			return SharedDeviceProfilePage{}, err
		}
		f.IP, f.EndpointID, f.MAC = ip, endpoint, mac
		f.SensorID = s.sensorID // legacy facts predate the per-fact sensor field on this node
		f.FirstSeen, f.LastSeen, f.ExpiresAt = first.UTC().Format(time.RFC3339Nano), last.UTC().Format(time.RFC3339Nano), expires.UTC().Format(time.RFC3339Nano)
		facts = append(facts, f)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return SharedDeviceProfilePage{}, err
	}
	if len(facts) > 10000 {
		return SharedDeviceProfilePage{}, fmt.Errorf("device profile archive exceeded safety limit")
	}
	profiles := buildSharedDeviceProfiles(facts, now)
	existing := make(map[string]bool, len(profiles))
	for _, profile := range profiles {
		existing[profile.ProfileID] = true
	}
	authCandidates := buildAuthBackedRouterCandidates(facts, now)
	if err = s.attachSharedDeviceAuthBindings(ctx, authCandidates); err != nil {
		return SharedDeviceProfilePage{}, err
	}
	for _, candidate := range authCandidates {
		if !existing[candidate.ProfileID] && len(candidate.AuthBindings) > 0 {
			profiles = append(profiles, candidate)
			existing[candidate.ProfileID] = true
		}
	}
	sortSharedDeviceProfiles(profiles)
	filtered := []SharedDeviceProfile{}
	keyword := strings.ToLower(strings.TrimSpace(q.Keyword))
	for _, p := range profiles {
		if keyword == "" || strings.Contains(strings.ToLower(strings.Join([]string{p.IP, p.MAC, p.EndpointID, p.Brand, p.Model, p.Role}, " ")), keyword) {
			filtered = append(filtered, p)
		}
	}
	page := SharedDeviceProfilePage{Items: []SharedDeviceProfile{}, Page: Page{Limit: q.Limit, Total: len(filtered)}, CheckedAt: now}
	if q.Cursor >= len(filtered) {
		return page, nil
	}
	end := q.Cursor + q.Limit
	if end > len(filtered) {
		end = len(filtered)
	}
	page.Items = append(page.Items, filtered[q.Cursor:end]...)
	if end < len(filtered) {
		next := fmt.Sprint(end)
		page.Page.NextCursor = &next
	}
	for i := range page.Items {
		if err = s.enrichSharedDeviceProfile(ctx, &page.Items[i], now); err != nil {
			return page, err
		}
	}
	if err = s.attachSharedDeviceAuthBindings(ctx, page.Items); err != nil {
		return page, err
	}
	return page, nil
}

func (s *PostgresStore) attachSharedDeviceAuthBindings(ctx context.Context, items []SharedDeviceProfile) error {
	macs, endpoints := []string{}, []string{}
	seenMAC, seenEndpoint := map[string]bool{}, map[string]bool{}
	for _, item := range items {
		if mac := normalizedRouterAuthMAC(item.MAC); mac != "" && !seenMAC[mac] {
			seenMAC[mac], macs = true, append(macs, mac)
		}
		if endpoint := strings.TrimSpace(item.EndpointID); endpoint != "" && !seenEndpoint[endpoint] {
			seenEndpoint[endpoint], endpoints = true, append(endpoints, endpoint)
		}
	}
	if len(macs) == 0 && len(endpoints) == 0 {
		return nil
	}
	sessions, err := s.currentAuthSessionsForIdentities(ctx, macs, endpoints)
	if err != nil {
		return err
	}
	for i := range items {
		items[i].AuthBindings = routerBindingsForAssessment(evidence.RouterAssessment{MAC: items[i].MAC, EndpointID: items[i].EndpointID}, sessions)
	}
	return nil
}

func (s *PostgresStore) enrichSharedDeviceProfile(ctx context.Context, p *SharedDeviceProfile, now time.Time) error {
	// An IP is not a permanent device identity. The latest lease is checked before
	// attributing current address activity or sharing to the archived hardware.
	rows, err := s.db.QueryContext(ctx, `SELECT endpoint_id,action,valid_until,observed_at,campus_id FROM device_address_leases
WHERE sensor_id=$1 AND ip=$2::inet AND observed_at<=$3 ORDER BY observed_at DESC,event_id DESC LIMIT 2`, p.SensorID, p.IP, now)
	if err != nil {
		return err
	}
	type lease struct {
		endpoint, action string
		until, at        time.Time
		campus           string
	}
	leases := []lease{}
	for rows.Next() {
		var l lease
		if err = rows.Scan(&l.endpoint, &l.action, &l.until, &l.at, &l.campus); err != nil {
			rows.Close()
			return err
		}
		leases = append(leases, l)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	owner := p.EndpointID
	if owner == "" && p.MAC != "" {
		owner = "mac:" + strings.ToLower(p.MAC)
	}
	if len(leases) > 0 {
		l := leases[0]
		p.AddressState = "stale"
		if owner != "" && l.endpoint != owner {
			p.AddressState = "reassigned"
		}
		if owner != "" && l.endpoint == owner && l.action == "ack" && l.until.After(now) {
			p.AddressState = "verified"
			if len(leases) > 1 && leases[1].at.Equal(l.at) && (leases[1].endpoint != l.endpoint || leases[1].campus != l.campus) {
				p.AddressState = "unbound"
			}
			var moved bool
			if err = s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM device_address_leases WHERE sensor_id=$1 AND campus_id=$2 AND endpoint_id=$3 AND observed_at>$4 AND observed_at<=$5)`, p.SensorID, l.campus, owner, l.at, now).Scan(&moved); err != nil {
				return err
			}
			if moved {
				p.AddressState = "stale"
			}
		}
	}
	// Historical sharing is identity-scoped when an endpoint is known. Old rules
	// without a physical strong anchor remain in the separate historical view.
	var at time.Time
	var id string
	var current bool
	err = s.db.QueryRowContext(ctx, `SELECT last_seen,observation_id,
 current AND rule_version=$4 AND expires_at>$5 AND window_end>$5-interval '20 minutes' AND window_end<=$5
FROM shared_behavior_observations WHERE sensor_id=$1 AND status='confirmed' AND coverage_state='verified'
 AND COALESCE(observation->>'strong_anchor','') IN ('ieee1905_association','coexisting_device_models')
 AND COALESCE((observation->>'device_lower_bound')::int,0)>=2
 AND ((NULLIF($2,'') IS NOT NULL AND endpoint_id=$2) OR ($2='' AND ip=$3::inet AND router_assessment_id=$6))
ORDER BY last_seen DESC,observation_id DESC LIMIT 1`, p.SensorID, owner, p.IP, sharedaccess.BehaviorRuleVersion, now, p.IdentityAssessmentID).Scan(&at, &id, &current)
	if err == nil {
		p.LastSharedAt = &at
		p.LastSharedObservationID = id
		p.CurrentShared = current && p.AddressState == "verified"
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	return err
}

func (s *DBStore) ListSharedDeviceProfiles(ctx context.Context, q SharedDeviceProfileQuery) (SharedDeviceProfilePage, error) {
	page, err := s.pg.ListSharedDeviceProfiles(ctx, q)
	page.ActivityState = "available"
	if err != nil || len(page.Items) == 0 {
		return page, err
	}
	// Bounded standard-event read, outside ingest/risk hot paths. Activity is named
	// as address activity even where ownership cannot currently be verified.
	ips := map[string]bool{}
	quoted := []string{}
	for _, p := range page.Items {
		if p.IP != "" && !ips[p.IP] {
			ips[p.IP] = true
			quoted = append(quoted, chQuote(p.IP))
		}
	}
	if len(quoted) == 0 {
		return page, nil
	}
	raw, err := s.ch.query(ctx, fmt.Sprintf(`SELECT subject_ip AS ip,formatDateTime(max(timestamp),'%%Y-%%m-%%dT%%H:%%i:%%S.%%fZ','UTC') AS last_seen
FROM normalized_events PREWHERE sensor_id=%s AND subject_ip IN (%s) AND timestamp>=now()-INTERVAL 7 DAY
GROUP BY subject_ip SETTINGS max_threads=1,max_memory_usage=268435456,max_execution_time=10 FORMAT JSONEachRow`, chQuote(s.pg.sensorID), strings.Join(quoted, ",")))
	if err != nil {
		page.ActivityState = "unavailable"
		return page, nil
	}
	var activity []struct {
		IP       string `json:"ip"`
		LastSeen string `json:"last_seen"`
	}
	if err = decodeJSONEachRow(raw, &activity); err != nil {
		page.ActivityState = "unavailable"
		return page, nil
	}
	byIP := map[string]time.Time{}
	for _, a := range activity {
		if at, e := time.Parse(time.RFC3339Nano, normalizeClickHouseTimestamp(a.LastSeen)); e == nil {
			byIP[a.IP] = at
		}
	}
	for i := range page.Items {
		if at, ok := byIP[page.Items[i].IP]; ok {
			page.Items[i].AddressLastActivityAt = &at
		}
	}
	return page, nil
}
