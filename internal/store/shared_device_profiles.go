package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"proxy-sentinel/internal/evidence"
)

// Profiles preserve passive identity evidence. They never participate in scoring
// or enforcement, and address activity cannot refresh identity or sharing proof.
type SharedDeviceProfile struct {
	ProfileID               string                       `json:"profile_id"`
	SensorID                string                       `json:"sensor_id,omitempty"`
	CampusID                string                       `json:"campus_id,omitempty"`
	EndpointID              string                       `json:"endpoint_id,omitempty"`
	MAC                     string                       `json:"mac,omitempty"`
	IP                      string                       `json:"ip,omitempty"`
	VLAN                    string                       `json:"vlan,omitempty"`
	Addresses               []string                     `json:"addresses,omitempty"`
	DisplayName             string                       `json:"display_name,omitempty"`
	Brand                   string                       `json:"brand,omitempty"`
	Model                   string                       `json:"model,omitempty"`
	Role                    string                       `json:"role,omitempty"`
	RoleSource              string                       `json:"role_source,omitempty"`
	RouterStatus            string                       `json:"router_status,omitempty"`
	BrandReferenceOnly      bool                         `json:"brand_reference_only"`
	Confidence              int                          `json:"confidence"`
	IdentityConflict        bool                         `json:"identity_conflict"`
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
	SharedConfidence        int                          `json:"shared_confidence"`
	AddressOnly             bool                         `json:"address_only"`
	AuthBindings            []evidence.RouterAuthBinding `json:"auth_bindings,omitempty"`
	LatestAccountID         string                       `json:"latest_account_id,omitempty"`
	LatestAccountAt         *time.Time                   `json:"latest_account_at,omitempty"`
	LatestAccountActive     bool                         `json:"latest_account_active"`
	LatestAccountMatchBasis string                       `json:"latest_account_match_basis,omitempty"`
	AccountConflict         bool                         `json:"account_conflict"`
	FirstSeen               time.Time                    `json:"first_seen"`
	LastObservedAt          time.Time                    `json:"last_observed_at"`
	MaterializedAt          time.Time                    `json:"materialized_at"`
	RuleVersion             string                       `json:"rule_version,omitempty"`
}

type SharedDeviceProfileQuery struct {
	Keyword         string
	Role            string
	RouterStatus    string
	IdentityState   string
	CurrentShared   *bool
	AccountConflict *bool
	Limit, Cursor   int
}
type SharedDeviceProfilePage struct {
	Items             []SharedDeviceProfile `json:"items"`
	Page              Page                  `json:"page"`
	ActivityState     string                `json:"activity_state,omitempty"`
	CheckedAt         time.Time             `json:"checked_at"`
	AsOf              time.Time             `json:"as_of"`
	FreshnessState    string                `json:"freshness_state"`
	MaterializedAt    *time.Time            `json:"materialized_at,omitempty"`
	PendingJobs       int                   `json:"pending_jobs"`
	OldestPendingAt   *time.Time            `json:"oldest_pending_at,omitempty"`
	MaterializerError string                `json:"materializer_error,omitempty"`
}
type SharedDeviceProfileReader interface {
	ListSharedDeviceProfiles(context.Context, SharedDeviceProfileQuery) (SharedDeviceProfilePage, error)
}

type SharedDeviceProfileHistory struct {
	Kind       string          `json:"kind"`
	ObservedAt time.Time       `json:"observed_at"`
	SourceID   string          `json:"source_id,omitempty"`
	Snapshot   json.RawMessage `json:"snapshot"`
}

type SharedDeviceProfileDetail struct {
	Profile SharedDeviceProfile          `json:"profile"`
	History []SharedDeviceProfileHistory `json:"history"`
}

type SharedDeviceProfileDetailReader interface {
	GetSharedDeviceProfile(context.Context, string) (SharedDeviceProfileDetail, bool, error)
}

func (s *PostgresStore) ListSharedDeviceProfiles(ctx context.Context, q SharedDeviceProfileQuery) (SharedDeviceProfilePage, error) {
	if q.Limit == 0 {
		q.Limit = 20
	}
	if q.Limit < 1 || q.Limit > 100 || q.Cursor < 0 {
		return SharedDeviceProfilePage{}, fmt.Errorf("invalid device profile pagination")
	}
	now := time.Now().UTC()
	// Address-only discovery announcements carry no device identity; profiles
	// created from them before the qualification rule tightened stay stored but hidden.
	where := []string{"p.merged_into_profile_id IS NULL", "p.sensor_id=$1",
		"NOT (p.address_only AND coalesce(p.source_assessment_id,'')='' AND coalesce(p.source_shared_observation_id,'')='')"}
	args := []any{s.sensorID}
	add := func(clause string, value any) {
		args = append(args, value)
		where = append(where, strings.ReplaceAll(clause, "$N", fmt.Sprintf("$%d", len(args))))
	}
	if keyword := strings.ToLower(strings.TrimSpace(q.Keyword)); keyword != "" {
		add(`lower(concat_ws(' ',p.display_name,p.endpoint_id,p.mac,coalesce(host(p.primary_ip),''),p.brand,p.model,p.role,p.latest_account_id)) LIKE $N`, "%"+keyword+"%")
	}
	if q.Role != "" {
		add("p.role=$N", q.Role)
	}
	if q.RouterStatus != "" {
		add("p.list_item->>'router_status'=$N", q.RouterStatus)
	}
	if q.IdentityState != "" {
		add("p.recognition_status=$N", q.IdentityState)
	}
	if q.CurrentShared != nil {
		add("p.current_shared=$N", *q.CurrentShared)
	}
	if q.AccountConflict != nil {
		add("p.account_conflict=$N", *q.AccountConflict)
	}
	args = append(args, q.Limit, q.Cursor)
	limitArg, cursorArg := len(args)-1, len(args)
	query := `WITH runtime AS (
 SELECT r.last_success_at,r.last_error,r.updated_at,
  (SELECT count(*) FROM shared_device_profile_jobs j WHERE j.processed_generation<j.dirty_generation OR j.next_run_at<=now()) pending_jobs,
  (SELECT min(j.dirty_since) FROM shared_device_profile_jobs j WHERE j.processed_generation<j.dirty_generation) oldest_pending_at
 FROM shared_device_profile_runtime r WHERE singleton
), filtered AS NOT MATERIALIZED (
 SELECT p.profile_id,p.list_item,p.last_observed_at,p.materialized_at FROM shared_device_profiles p WHERE ` + strings.Join(where, " AND ") + `
), page AS (
 SELECT list_item,last_observed_at,profile_id,materialized_at FROM filtered
 ORDER BY last_observed_at DESC,profile_id LIMIT $` + fmt.Sprint(limitArg) + ` OFFSET $` + fmt.Sprint(cursorArg) + `
)
SELECT coalesce(jsonb_agg(page.list_item ORDER BY page.last_observed_at DESC,page.profile_id) FILTER(WHERE page.profile_id IS NOT NULL),'[]'::jsonb),
 (SELECT count(*) FROM filtered),runtime.last_success_at,runtime.last_error,coalesce(max(page.materialized_at),runtime.last_success_at),
 runtime.pending_jobs,runtime.oldest_pending_at,clock_timestamp()
FROM runtime LEFT JOIN page ON true GROUP BY runtime.last_success_at,runtime.last_error,runtime.pending_jobs,runtime.oldest_pending_at`
	var raw []byte
	var total int
	var lastSuccess, materialized sql.NullTime
	var lastError string
	var oldestPending sql.NullTime
	var pendingJobs int
	var checkedAt time.Time
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&raw, &total, &lastSuccess, &lastError, &materialized, &pendingJobs, &oldestPending, &checkedAt); err != nil {
		return SharedDeviceProfilePage{}, err
	}
	items := []SharedDeviceProfile{}
	if err := json.Unmarshal(raw, &items); err != nil {
		return SharedDeviceProfilePage{}, err
	}
	page := SharedDeviceProfilePage{Items: items, Page: Page{Limit: q.Limit, Total: total}, CheckedAt: checkedAt.UTC(), AsOf: checkedAt.UTC(), FreshnessState: "fresh", PendingJobs: pendingJobs, MaterializerError: lastError}
	if materialized.Valid {
		stamp := materialized.Time.UTC()
		page.MaterializedAt = &stamp
	}
	if oldestPending.Valid {
		stamp := oldestPending.Time.UTC()
		page.OldestPendingAt = &stamp
	}
	if !lastSuccess.Valid {
		page.FreshnessState = "initializing"
	} else if lastError != "" || now.Sub(lastSuccess.Time) > 45*time.Second || oldestPending.Valid && now.Sub(oldestPending.Time) > 45*time.Second {
		page.FreshnessState = "stale"
	}
	if q.Cursor+len(items) < total {
		next := fmt.Sprint(q.Cursor + len(items))
		page.Page.NextCursor = &next
	}
	return page, nil
}

func (s *DBStore) ListSharedDeviceProfiles(ctx context.Context, q SharedDeviceProfileQuery) (SharedDeviceProfilePage, error) {
	return s.pg.ListSharedDeviceProfiles(ctx, q)
}

func (s *PostgresStore) GetSharedDeviceProfile(ctx context.Context, id string) (SharedDeviceProfileDetail, bool, error) {
	var profileRaw, historyRaw []byte
	err := s.db.QueryRowContext(ctx, `SELECT p.list_item,coalesce((SELECT jsonb_agg(jsonb_build_object(
 'kind',h.change_kind,'observed_at',h.observed_at,'source_id',h.source_id,'snapshot',h.payload)
 ORDER BY h.observed_at DESC,h.history_id DESC) FROM shared_device_profile_history h WHERE h.profile_id=p.profile_id),'[]'::jsonb)
FROM shared_device_profiles p WHERE p.profile_id=$1 AND p.merged_into_profile_id IS NULL`, id).Scan(&profileRaw, &historyRaw)
	if err == sql.ErrNoRows {
		return SharedDeviceProfileDetail{}, false, nil
	}
	if err != nil {
		return SharedDeviceProfileDetail{}, false, err
	}
	detail := SharedDeviceProfileDetail{History: []SharedDeviceProfileHistory{}}
	if err = json.Unmarshal(profileRaw, &detail.Profile); err != nil {
		return SharedDeviceProfileDetail{}, false, err
	}
	if err = json.Unmarshal(historyRaw, &detail.History); err != nil {
		return SharedDeviceProfileDetail{}, false, err
	}
	return detail, true, nil
}

func (s *DBStore) GetSharedDeviceProfile(ctx context.Context, id string) (SharedDeviceProfileDetail, bool, error) {
	return s.pg.GetSharedDeviceProfile(ctx, id)
}
