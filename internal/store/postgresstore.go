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

	_ "github.com/jackc/pgx/v5/stdlib"

	"proxy-sentinel/internal/evidence"
	"proxy-sentinel/internal/ingest"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/risk"
)

const PostgresDDLPath = "migrations/postgres/001_production_schema.sql"

type PostgresOptions struct {
	DSN           string
	SensorID      string
	CollectorKind string
	CollectorVer  string
	InterfaceName string
}

type PostgresStore struct {
	db            *sql.DB
	dsn           string
	sensorID      string
	collectorKind string
	collectorVer  string
	interfaceName string
}

func NewPostgresStore(opts PostgresOptions) (*PostgresStore, error) {
	if err := dbRequired("postgres dsn", opts.DSN); err != nil {
		return nil, err
	}
	db, err := sql.Open("pgx", opts.DSN)
	if err != nil {
		return nil, err
	}
	sensorID := opts.SensorID
	if sensorID == "" {
		sensorID = "office-30"
	}
	collectorKind := opts.CollectorKind
	if collectorKind == "" {
		collectorKind = "suricata"
	}
	interfaceName := opts.InterfaceName
	if interfaceName == "" {
		interfaceName = "ens1f1"
	}
	return &PostgresStore{
		db:            db,
		dsn:           opts.DSN,
		sensorID:      sensorID,
		collectorKind: collectorKind,
		collectorVer:  opts.CollectorVer,
		interfaceName: interfaceName,
	}, nil
}

func (s *PostgresStore) DSN() string {
	return s.dsn
}

func (s *PostgresStore) Close() error {
	return s.db.Close()
}

func (s *PostgresStore) collector() ingest.Collector {
	return ingest.Collector{Kind: s.collectorKind, Version: s.collectorVer, Interface: s.interfaceName}
}

func (s *PostgresStore) Overview(ctx context.Context) (Overview, error) {
	runs, err := s.ListRuns(ctx, 1)
	if err != nil {
		return Overview{}, err
	}
	counts := map[string]int{"normal": 0, "suspicious": 0, "high": 0, "confirmed": 0}
	rows, err := s.db.QueryContext(ctx, `SELECT level, count(*) FROM risk_snapshots GROUP BY level`)
	if err != nil {
		return Overview{}, fmt.Errorf("query risk level counts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var level string
		var count int
		if err := rows.Scan(&level, &count); err != nil {
			return Overview{}, err
		}
		if _, ok := counts[level]; ok {
			counts[level] = count
		}
	}
	topEvidence, err := s.topEvidence(ctx)
	if err != nil {
		return Overview{}, err
	}
	risks, err := s.RiskSnapshotMap(ctx)
	if err != nil {
		return Overview{}, err
	}
	riskItems := make([]risk.Snapshot, 0, len(risks))
	for _, item := range risks {
		riskItems = append(riskItems, item)
	}
	reviewed := applyLatestReviewLabels(riskItems, latestLabelMap(s.allLabels(ctx, 0)))
	latest := Run{SensorID: s.sensorID, Normalized: NormalizedCounts{ByType: map[string]int{}}}
	if len(runs) > 0 {
		latest = runs[0]
	}
	return Overview{
		LevelCounts:    counts,
		PendingReviews: pendingReviewCount(reviewed),
		LatestRun:      latest,
		Throughput: map[string]int{
			"events":   latest.Normalized.Emitted,
			"evidence": latest.EvidenceCount,
			"risks":    latest.RiskCount,
		},
		TopEvidence: topEvidence,
	}, nil
}

func (s *PostgresStore) ListRisks(ctx context.Context, query Query) (RiskPage, error) {
	limit := query.Limit
	if limit == 0 {
		limit = 50
	}
	if query.SensorID != "" && query.SensorID != s.sensorID {
		return RiskPage{Items: []risk.Snapshot{}, Page: Page{Limit: limit}}, nil
	}
	if query.Level != "" {
		if _, ok := levelRank(query.Level); !ok {
			return RiskPage{}, fmt.Errorf("unknown level: %s", query.Level)
		}
	}
	baseQuery := query
	baseQuery.Level = ""
	baseQuery.Limit = 0
	baseQuery.Cursor = 0
	where, args, err := riskWhere(baseQuery)
	if err != nil {
		return RiskPage{}, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT host(ip), score, level, confidence, "window", evidence_ids, summary, recommended_action, updated_at
FROM risk_snapshots`+where+`
ORDER BY
  CASE level WHEN 'confirmed' THEN 3 WHEN 'high' THEN 2 WHEN 'suspicious' THEN 1 ELSE 0 END DESC,
  score DESC,
  ip ASC`, args...)
	if err != nil {
		return RiskPage{}, err
	}
	defer rows.Close()
	items, err := scanRiskRows(rows)
	if err != nil {
		return RiskPage{}, err
	}
	items = applyLatestReviewLabels(items, latestLabelMap(s.allLabels(ctx, 0)))
	items, err = filterRisks(items, query)
	if err != nil {
		return RiskPage{}, err
	}
	total := len(items)
	cursor := query.Cursor
	if cursor > total {
		cursor = total
	}
	end := cursor + limit
	if end > total {
		end = total
	}
	var next *string
	if end < total {
		value := fmt.Sprintf("%d", end)
		next = &value
	}
	return RiskPage{Items: items[cursor:end], Page: Page{Limit: limit, NextCursor: next, Total: total}}, nil
}

func (s *PostgresStore) GetIPRisk(ctx context.Context, ip string) (risk.Snapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT host(ip), score, level, confidence, "window", evidence_ids, summary, recommended_action, updated_at
FROM risk_snapshots WHERE ip = $1::inet`, ip)
	if err != nil {
		return risk.Snapshot{}, err
	}
	defer rows.Close()
	items, err := scanRiskRows(rows)
	if err != nil {
		return risk.Snapshot{}, err
	}
	if len(items) == 0 {
		return applyLatestReviewLabel(normalRisk(ip), latestLabelMap(s.allLabels(ctx, 0))), nil
	}
	return applyLatestReviewLabel(items[0], latestLabelMap(s.allLabels(ctx, 0))), nil
}

func (s *PostgresStore) RiskSnapshotMap(ctx context.Context) (map[string]risk.Snapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT host(ip), score, level, confidence, "window", evidence_ids, summary, recommended_action, updated_at
FROM risk_snapshots`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items, err := scanRiskRows(rows)
	if err != nil {
		return nil, err
	}
	return riskSnapshotMap(items), nil
}

func (s *PostgresStore) GetIPEvidence(ctx context.Context, ip string, limit int) ([]evidence.Evidence, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT evidence_id, host(ip), type, "window", score, confidence, severity, reason, samples, created_at
FROM evidence WHERE ip = $1::inet ORDER BY created_at DESC, evidence_id ASC LIMIT $2`, ip, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []evidence.Evidence{}
	for rows.Next() {
		var item evidence.Evidence
		var samples []byte
		var created time.Time
		if err := rows.Scan(&item.EvidenceID, &item.IP, &item.Type, &item.Window, &item.Score, &item.Confidence, &item.Severity, &item.Reason, &samples, &created); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(samples, &item.Samples)
		item.CreatedAt = created.Format(time.RFC3339Nano)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) GetAccountIdentity(ctx context.Context, accountID string, query Query) (AccountIdentityProfile, bool, error) {
	limit := identityLimit(query.Limit)
	state := IdentityState{
		Endpoints:      []EndpointEntity{},
		Infrastructure: []InfrastructureEntity{},
		Sessions:       []AccountSession{},
		IPMACHistory:   []IdentityIPMACHistory{},
		AccessHistory:  []IdentityAccessHistory{},
	}
	endpointIDs := map[string]struct{}{}
	sessions, err := s.queryAccountSessions(ctx, "account_id = $1", []any{accountID}, limit)
	if err != nil {
		return AccountIdentityProfile{}, false, err
	}
	state.Sessions = sessions
	for _, session := range sessions {
		if session.EndpointID != "" {
			endpointIDs[session.EndpointID] = struct{}{}
		}
	}
	ipHistory, err := s.queryIdentityIPMACHistory(ctx, "account_id = $1", []any{accountID}, limit)
	if err != nil {
		return AccountIdentityProfile{}, false, err
	}
	state.IPMACHistory = ipHistory
	for _, item := range ipHistory {
		if item.EndpointID != "" {
			endpointIDs[item.EndpointID] = struct{}{}
		}
	}
	accessHistory, err := s.queryIdentityAccessHistory(ctx, "account_id = $1", []any{accountID}, limit)
	if err != nil {
		return AccountIdentityProfile{}, false, err
	}
	state.AccessHistory = accessHistory
	for _, item := range accessHistory {
		if item.EndpointID != "" {
			endpointIDs[item.EndpointID] = struct{}{}
		}
	}
	for endpointID := range endpointIDs {
		endpoint, ok, err := s.getEndpointEntity(ctx, endpointID)
		if err != nil {
			return AccountIdentityProfile{}, false, err
		}
		if ok {
			state.Endpoints = append(state.Endpoints, endpoint)
		}
	}
	profile, ok := BuildAccountIdentityProfile(state, accountID)
	return profile, ok, nil
}

func (s *PostgresStore) GetEndpointIdentity(ctx context.Context, endpointID string, query Query) (EndpointIdentityProfile, bool, error) {
	limit := identityLimit(query.Limit)
	state := IdentityState{
		Endpoints:      []EndpointEntity{},
		Infrastructure: []InfrastructureEntity{},
		Sessions:       []AccountSession{},
		IPMACHistory:   []IdentityIPMACHistory{},
		AccessHistory:  []IdentityAccessHistory{},
	}
	if endpoint, ok, err := s.getEndpointEntity(ctx, endpointID); err != nil {
		return EndpointIdentityProfile{}, false, err
	} else if ok {
		state.Endpoints = append(state.Endpoints, endpoint)
	}
	sessions, err := s.queryAccountSessions(ctx, "endpoint_id = $1", []any{endpointID}, limit)
	if err != nil {
		return EndpointIdentityProfile{}, false, err
	}
	state.Sessions = sessions
	ipHistory, err := s.queryIdentityIPMACHistory(ctx, "endpoint_id = $1", []any{endpointID}, limit)
	if err != nil {
		return EndpointIdentityProfile{}, false, err
	}
	state.IPMACHistory = ipHistory
	accessHistory, err := s.queryIdentityAccessHistory(ctx, "endpoint_id = $1", []any{endpointID}, limit)
	if err != nil {
		return EndpointIdentityProfile{}, false, err
	}
	state.AccessHistory = accessHistory
	profile, ok := BuildEndpointIdentityProfile(state, endpointID)
	return profile, ok, nil
}

func (s *PostgresStore) ListEndpointDevices(ctx context.Context, query Query) (EndpointDevicePage, error) {
	limit := query.Limit
	if limit == 0 {
		limit = 50
	}
	where := []string{"entity_role = 'endpoint'"}
	args := []any{}
	if query.Q != "" {
		args = append(args, "%"+strings.ToLower(query.Q)+"%")
		placeholder := "$" + strconvArg(len(args))
		where = append(where, `(lower(endpoint_id) LIKE `+placeholder+` OR lower(coalesce(primary_mac, '')) LIKE `+placeholder+` OR lower(coalesce(registration_status, '')) LIKE `+placeholder+` OR lower(coalesce(owner_account, '')) LIKE `+placeholder+` OR lower(coalesce(owner_name, '')) LIKE `+placeholder+` OR lower(coalesce(owner_department, '')) LIKE `+placeholder+` OR lower(coalesce(asset_tag, '')) LIKE `+placeholder+`)`)
	}
	whereSQL := " WHERE " + strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM endpoint_entities"+whereSQL, args...).Scan(&total); err != nil {
		return EndpointDevicePage{}, err
	}
	if limit < 0 {
		limit = total
	}
	selectArgs := append(append([]any{}, args...), limit, query.Cursor)
	rows, err := s.db.QueryContext(ctx, `
SELECT endpoint_id
FROM endpoint_entities`+whereSQL+`
ORDER BY last_seen DESC NULLS LAST, registration_updated_at DESC NULLS LAST, endpoint_id ASC
LIMIT $`+strconvArg(len(selectArgs)-1)+` OFFSET $`+strconvArg(len(selectArgs)), selectArgs...)
	if err != nil {
		return EndpointDevicePage{}, err
	}
	defer rows.Close()
	endpointIDs := []string{}
	for rows.Next() {
		var endpointID string
		if err := rows.Scan(&endpointID); err != nil {
			return EndpointDevicePage{}, err
		}
		endpointIDs = append(endpointIDs, endpointID)
	}
	if err := rows.Err(); err != nil {
		return EndpointDevicePage{}, err
	}
	items := []EndpointDeviceInventory{}
	for _, endpointID := range endpointIDs {
		profile, ok, err := s.GetEndpointIdentity(ctx, endpointID, Query{Limit: 200})
		if err != nil {
			return EndpointDevicePage{}, err
		}
		if !ok {
			continue
		}
		item := BuildEndpointDeviceInventory(profile)
		if query.SrcIP == "" || item.CurrentIP == query.SrcIP || stringSliceContains(item.IPs, query.SrcIP) {
			items = append(items, item)
		}
	}
	var next *string
	if query.Cursor+len(endpointIDs) < total {
		value := fmt.Sprintf("%d", query.Cursor+len(endpointIDs))
		next = &value
	}
	return EndpointDevicePage{Items: items, Page: Page{Limit: query.Limit, NextCursor: next, Total: total}}, nil
}

func identityLimit(limit int) int {
	if limit == 0 {
		return 200
	}
	if limit < 0 {
		return 10000
	}
	return limit
}

func (s *PostgresStore) getEndpointEntity(ctx context.Context, endpointID string) (EndpointEntity, bool, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT endpoint_id, primary_mac, entity_role, first_seen, last_seen, identity_confidence, attributes,
       registration_status, owner_account, owner_name, owner_department, asset_tag,
       registered_by, registered_at, registration_note, merge_status,
       merged_into_endpoint_id, split_from_endpoint_id, registration_updated_by, registration_updated_at
FROM endpoint_entities WHERE endpoint_id = $1`, endpointID)
	if err != nil {
		return EndpointEntity{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return EndpointEntity{}, false, rows.Err()
	}
	endpoint, err := scanEndpointEntity(rows)
	if err != nil {
		return EndpointEntity{}, false, err
	}
	return endpoint, true, rows.Err()
}

func (s *PostgresStore) queryAccountSessions(ctx context.Context, where string, args []any, limit int) ([]AccountSession, error) {
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, `
SELECT session_id, account_id, endpoint_id, host(ip), mac, access_id, source, started_at, ended_at, identity_confidence, raw_ref
FROM account_sessions
WHERE `+where+`
ORDER BY started_at DESC, session_id ASC
LIMIT $`+strconvArg(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AccountSession{}
	for rows.Next() {
		item, err := scanAccountSession(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) queryIdentityIPMACHistory(ctx context.Context, where string, args []any, limit int) ([]IdentityIPMACHistory, error) {
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, `
SELECT event_id, endpoint_id, account_id, entity_role, host(ip), mac, source, first_seen, last_seen, identity_confidence, event_ids_sample
FROM identity_ip_mac_history
WHERE `+where+`
ORDER BY last_seen DESC, event_id ASC
LIMIT $`+strconvArg(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []IdentityIPMACHistory{}
	for rows.Next() {
		item, err := scanIdentityIPMACHistory(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) queryIdentityAccessHistory(ctx context.Context, where string, args []any, limit int) ([]IdentityAccessHistory, error) {
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, `
SELECT event_id, endpoint_id, account_id, entity_role, access_id, access_type, ap, switch_id, switch_port, vlan, source, first_seen, last_seen, identity_confidence, event_ids_sample
FROM identity_access_history
WHERE `+where+`
ORDER BY last_seen DESC, event_id ASC
LIMIT $`+strconvArg(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []IdentityAccessHistory{}
	for rows.Next() {
		item, err := scanIdentityAccessHistory(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func scanEndpointEntity(rows *sql.Rows) (EndpointEntity, error) {
	var item EndpointEntity
	var primaryMAC, ownerAccount, ownerName, ownerDepartment, assetTag, registeredBy, registrationNote, mergedInto, splitFrom, updatedBy sql.NullString
	var firstSeen, lastSeen, registeredAt, updatedAt sql.NullTime
	var attrs []byte
	if err := rows.Scan(
		&item.EndpointID, &primaryMAC, &item.EntityRole, &firstSeen, &lastSeen, &item.IdentityConfidence, &attrs,
		&item.RegistrationStatus, &ownerAccount, &ownerName, &ownerDepartment, &assetTag,
		&registeredBy, &registeredAt, &registrationNote, &item.MergeStatus,
		&mergedInto, &splitFrom, &updatedBy, &updatedAt,
	); err != nil {
		return EndpointEntity{}, err
	}
	item.PrimaryMAC = nullStringValue(primaryMAC)
	item.FirstSeen = nullTimeText(firstSeen)
	item.LastSeen = nullTimeText(lastSeen)
	item.Attributes = map[string]any{}
	_ = json.Unmarshal(attrs, &item.Attributes)
	item.OwnerAccount = nullStringValue(ownerAccount)
	item.OwnerName = nullStringValue(ownerName)
	item.OwnerDepartment = nullStringValue(ownerDepartment)
	item.AssetTag = nullStringValue(assetTag)
	item.RegisteredBy = nullStringValue(registeredBy)
	item.RegisteredAt = nullTimeText(registeredAt)
	item.RegistrationNote = nullStringValue(registrationNote)
	item.MergedIntoEndpointID = nullStringValue(mergedInto)
	item.SplitFromEndpointID = nullStringValue(splitFrom)
	item.RegistrationUpdateByID = nullStringValue(updatedBy)
	item.RegistrationUpdatedAt = nullTimeText(updatedAt)
	ensureEndpointRegistrationDefaults(&item)
	return item, nil
}

func scanAccountSession(rows *sql.Rows) (AccountSession, error) {
	var item AccountSession
	var endpointID, ip, mac, accessID sql.NullString
	var startedAt time.Time
	var endedAt sql.NullTime
	var rawRef []byte
	if err := rows.Scan(&item.SessionID, &item.AccountID, &endpointID, &ip, &mac, &accessID, &item.Source, &startedAt, &endedAt, &item.IdentityConfidence, &rawRef); err != nil {
		return AccountSession{}, err
	}
	item.EndpointID = nullStringValue(endpointID)
	item.IP = nullStringValue(ip)
	item.MAC = nullStringValue(mac)
	item.AccessID = nullStringValue(accessID)
	item.StartedAt = startedAt.Format(time.RFC3339Nano)
	item.EndedAt = nullTimeText(endedAt)
	item.RawRef = map[string]any{}
	_ = json.Unmarshal(rawRef, &item.RawRef)
	return item, nil
}

func scanIdentityIPMACHistory(rows *sql.Rows) (IdentityIPMACHistory, error) {
	var item IdentityIPMACHistory
	var endpointID, accountID, ip, mac sql.NullString
	var firstSeen, lastSeen time.Time
	var eventIDs []byte
	if err := rows.Scan(&item.EventID, &endpointID, &accountID, &item.EntityRole, &ip, &mac, &item.Source, &firstSeen, &lastSeen, &item.IdentityConfidence, &eventIDs); err != nil {
		return IdentityIPMACHistory{}, err
	}
	item.EndpointID = nullStringValue(endpointID)
	item.AccountID = nullStringValue(accountID)
	item.IP = nullStringValue(ip)
	item.MAC = nullStringValue(mac)
	item.FirstSeen = firstSeen.Format(time.RFC3339Nano)
	item.LastSeen = lastSeen.Format(time.RFC3339Nano)
	_ = json.Unmarshal(eventIDs, &item.EventIDsSample)
	return item, nil
}

func scanIdentityAccessHistory(rows *sql.Rows) (IdentityAccessHistory, error) {
	var item IdentityAccessHistory
	var endpointID, accountID, accessType, ap, switchID, switchPort, vlan sql.NullString
	var firstSeen, lastSeen time.Time
	var eventIDs []byte
	if err := rows.Scan(&item.EventID, &endpointID, &accountID, &item.EntityRole, &item.AccessID, &accessType, &ap, &switchID, &switchPort, &vlan, &item.Source, &firstSeen, &lastSeen, &item.IdentityConfidence, &eventIDs); err != nil {
		return IdentityAccessHistory{}, err
	}
	item.EndpointID = nullStringValue(endpointID)
	item.AccountID = nullStringValue(accountID)
	item.AccessType = nullStringValue(accessType)
	item.AP = nullStringValue(ap)
	item.SwitchID = nullStringValue(switchID)
	item.SwitchPort = nullStringValue(switchPort)
	item.VLAN = nullStringValue(vlan)
	item.FirstSeen = firstSeen.Format(time.RFC3339Nano)
	item.LastSeen = lastSeen.Format(time.RFC3339Nano)
	_ = json.Unmarshal(eventIDs, &item.EventIDsSample)
	return item, nil
}

func nullStringValue(value sql.NullString) string {
	if value.Valid {
		return value.String
	}
	return ""
}

func nullEmptyString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func nullTimeText(value sql.NullTime) string {
	if value.Valid {
		return value.Time.Format(time.RFC3339Nano)
	}
	return ""
}

func (s *PostgresStore) ListRuns(ctx context.Context, limit int) ([]Run, error) {
	if limit == 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT run_id, sensor_id, started_at, finished_at, previous_offset, new_offset, truncated,
       normalized_read, normalized_emitted, normalized_skipped, normalized_malformed,
       evidence_count, risk_count, risk_list_count, summary
FROM collector_runs
ORDER BY started_at DESC, run_id DESC
LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	runs := []Run{}
	for rows.Next() {
		var run Run
		var started, finished time.Time
		var summaryJSON []byte
		if err := rows.Scan(&run.RunID, &run.SensorID, &started, &finished, &run.PreviousOffset, &run.NewOffset, &run.Truncated, &run.Normalized.Read, &run.Normalized.Emitted, &run.Normalized.Skipped, &run.Normalized.Malformed, &run.EvidenceCount, &run.RiskCount, &run.RiskListCount, &summaryJSON); err != nil {
			return nil, err
		}
		run.StartedAt = started.Format(time.RFC3339Nano)
		run.FinishedAt = finished.Format(time.RFC3339Nano)
		run.Normalized.ByType = map[string]int{}
		if len(summaryJSON) > 0 {
			var stored storedRunSummary
			if err := json.Unmarshal(summaryJSON, &stored); err == nil {
				if stored.ZeekStatus == "" && stored.ZeekNormalized.Emitted == 0 {
					stored = legacyStoredRunSummary(summaryJSON, stored)
				}
				if stored.Normalized.ByType != nil {
					run.Normalized.ByType = stored.Normalized.ByType
				}
				run.ZeekNormalized = stored.ZeekNormalized
				run.ZeekStatus = stored.ZeekStatus
				run.ZeekReason = stored.ZeekReason
				run.ZeekPrevOffset = stored.ZeekPrevOffset
				run.ZeekNewOffset = stored.ZeekNewOffset
				run.ZeekTruncated = stored.ZeekTruncated
				run.ZeekSoftwarePrevOffset = stored.ZeekSoftwarePrevOffset
				run.ZeekSoftwareNewOffset = stored.ZeekSoftwareNewOffset
				run.ZeekSoftwareTruncated = stored.ZeekSoftwareTruncated
				if stored.RawRef != nil {
					run.RawRef = stored.RawRef
				}
			}
		}
		runs = append(runs, run)
	}
	return runs, rows.Err()
}

type storedRunSummary struct {
	Normalized             NormalizedCounts `json:"normalized"`
	ZeekNormalized         NormalizedCounts `json:"zeek_normalized"`
	ZeekStatus             string           `json:"zeek_status"`
	ZeekReason             string           `json:"zeek_reason"`
	ZeekPrevOffset         int64            `json:"zeek_previous_offset"`
	ZeekNewOffset          int64            `json:"zeek_new_offset"`
	ZeekTruncated          bool             `json:"zeek_truncated"`
	ZeekSoftwarePrevOffset int64            `json:"zeek_software_previous_offset"`
	ZeekSoftwareNewOffset  int64            `json:"zeek_software_new_offset"`
	ZeekSoftwareTruncated  bool             `json:"zeek_software_truncated"`
	RawRef                 map[string]any   `json:"raw_ref"`
}

func legacyStoredRunSummary(summaryJSON []byte, stored storedRunSummary) storedRunSummary {
	var legacy struct {
		Normalized             NormalizedCounts
		ZeekNormalized         NormalizedCounts
		ZeekStatus             string
		ZeekReason             string
		ZeekPrevOffset         int64
		ZeekNewOffset          int64
		ZeekTruncated          bool
		ZeekSoftwarePrevOffset int64
		ZeekSoftwareNewOffset  int64
		ZeekSoftwareTruncated  bool
		RawRef                 map[string]any
	}
	if err := json.Unmarshal(summaryJSON, &legacy); err != nil {
		return stored
	}
	if legacy.Normalized.ByType != nil {
		stored.Normalized = legacy.Normalized
	}
	stored.ZeekNormalized = legacy.ZeekNormalized
	stored.ZeekStatus = legacy.ZeekStatus
	stored.ZeekReason = legacy.ZeekReason
	stored.ZeekPrevOffset = legacy.ZeekPrevOffset
	stored.ZeekNewOffset = legacy.ZeekNewOffset
	stored.ZeekTruncated = legacy.ZeekTruncated
	stored.ZeekSoftwarePrevOffset = legacy.ZeekSoftwarePrevOffset
	stored.ZeekSoftwareNewOffset = legacy.ZeekSoftwareNewOffset
	stored.ZeekSoftwareTruncated = legacy.ZeekSoftwareTruncated
	stored.RawRef = legacy.RawRef
	return stored
}

func (s *PostgresStore) ListAuditLogs(ctx context.Context, limit int) ([]AuditLog, error) {
	if limit == 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT audit_id, actor, action, target, outcome, created_at
FROM audit_logs ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	logs := []AuditLog{}
	for rows.Next() {
		var log AuditLog
		var created time.Time
		if err := rows.Scan(&log.AuditID, &log.Actor, &log.Action, &log.Target, &log.Outcome, &created); err != nil {
			return nil, err
		}
		log.CreatedAt = created.Format(time.RFC3339Nano)
		logs = append(logs, log)
	}
	return logs, rows.Err()
}

func (s *PostgresStore) CreateLabel(ctx context.Context, label Label) (Label, error) {
	if label.CreatedAt == "" {
		label.CreatedAt = NowRFC3339()
	}
	if label.CreatedBy == "" {
		label.CreatedBy = "shadow-operator"
	}
	if label.LabelID == "" {
		label.LabelID = "label-" + shortHash(label.TargetType+"|"+label.TargetID+"|"+label.Label+"|"+label.CreatedAt)
	}
	evidenceIDs, _ := json.Marshal(label.EvidenceIDs)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Label{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO labels(label_id, target_type, target_id, label, reason, evidence_ids, created_by, created_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT(label_id) DO UPDATE SET label = EXCLUDED.label, reason = EXCLUDED.reason, evidence_ids = EXCLUDED.evidence_ids`,
		label.LabelID, label.TargetType, label.TargetID, label.Label, label.Reason, evidenceIDs, label.CreatedBy, label.CreatedAt); err != nil {
		return Label{}, err
	}
	auditID := "audit-" + label.LabelID
	if _, err := tx.ExecContext(ctx, `
INSERT INTO audit_logs(audit_id, actor, action, target, outcome, created_at)
VALUES($1, $2, 'labels.create', $3, $4, $5)
ON CONFLICT(audit_id) DO UPDATE SET outcome = EXCLUDED.outcome`,
		auditID, label.CreatedBy, label.TargetType+":"+label.TargetID, label.Label, label.CreatedAt); err != nil {
		return Label{}, err
	}
	if err := tx.Commit(); err != nil {
		return Label{}, err
	}
	return label, nil
}

func (s *PostgresStore) ListLabels(ctx context.Context, limit int) ([]Label, error) {
	query := `
SELECT label_id, target_type, target_id, label, reason, evidence_ids, created_by, created_at
FROM labels
ORDER BY created_at DESC, label_id DESC`
	args := []any{}
	if limit > 0 {
		query += " LIMIT $1"
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	labels := []Label{}
	for rows.Next() {
		var label Label
		var evidenceIDs []byte
		var created time.Time
		if err := rows.Scan(&label.LabelID, &label.TargetType, &label.TargetID, &label.Label, &label.Reason, &evidenceIDs, &label.CreatedBy, &created); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(evidenceIDs, &label.EvidenceIDs)
		label.CreatedAt = created.Format(time.RFC3339Nano)
		labels = append(labels, label)
	}
	return labels, rows.Err()
}

func (s *PostgresStore) allLabels(ctx context.Context, limit int) []Label {
	labels, err := s.ListLabels(ctx, limit)
	if err != nil {
		return []Label{}
	}
	return labels
}

func (s *PostgresStore) UpdateEndpointRegistration(ctx context.Context, update EndpointRegistrationUpdate) (EndpointEntity, error) {
	if update.RegistrationUpdatedAt == "" {
		update.RegistrationUpdatedAt = NowRFC3339()
	}
	if update.RegistrationUpdatedBy == "" {
		update.RegistrationUpdatedBy = "shadow-operator"
	}
	if update.RegistrationStatus == "" {
		update.RegistrationStatus = "unregistered"
	}
	if update.MergeStatus == "" {
		update.MergeStatus = "active"
	}
	updatedAt := nullableTime(update.RegistrationUpdatedAt)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return EndpointEntity{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO endpoint_entities(
  endpoint_id, entity_role, identity_confidence, attributes,
  registration_status, owner_account, owner_name, owner_department, asset_tag,
  registered_by, registered_at, registration_note, merge_status,
  merged_into_endpoint_id, split_from_endpoint_id, registration_updated_by, registration_updated_at, updated_at
)
VALUES($1, 'endpoint', 0, '{}'::jsonb, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, now())
ON CONFLICT(endpoint_id) DO UPDATE SET
  registration_status = EXCLUDED.registration_status,
  owner_account = EXCLUDED.owner_account,
  owner_name = EXCLUDED.owner_name,
  owner_department = EXCLUDED.owner_department,
  asset_tag = EXCLUDED.asset_tag,
  registered_by = COALESCE(endpoint_entities.registered_by, EXCLUDED.registered_by),
  registered_at = COALESCE(endpoint_entities.registered_at, EXCLUDED.registered_at),
  registration_note = EXCLUDED.registration_note,
  merge_status = EXCLUDED.merge_status,
  merged_into_endpoint_id = EXCLUDED.merged_into_endpoint_id,
  split_from_endpoint_id = EXCLUDED.split_from_endpoint_id,
  registration_updated_by = EXCLUDED.registration_updated_by,
  registration_updated_at = EXCLUDED.registration_updated_at,
  updated_at = now()`,
		update.EndpointID,
		update.RegistrationStatus,
		nullEmptyString(update.OwnerAccount),
		nullEmptyString(update.OwnerName),
		nullEmptyString(update.OwnerDepartment),
		nullEmptyString(update.AssetTag),
		nullEmptyString(update.RegistrationUpdatedBy),
		nullTimeValue(updatedAt),
		nullEmptyString(update.RegistrationNote),
		update.MergeStatus,
		nullEmptyString(update.MergedIntoEndpointID),
		nullEmptyString(update.SplitFromEndpointID),
		update.RegistrationUpdatedBy,
		nullTimeValue(updatedAt),
	); err != nil {
		return EndpointEntity{}, err
	}
	auditID := "audit-endpoint-registration-" + shortHash(update.EndpointID+"|"+update.RegistrationUpdatedAt)
	if _, err := tx.ExecContext(ctx, `
INSERT INTO audit_logs(audit_id, actor, action, target, outcome, created_at)
VALUES($1, $2, 'endpoints.registration.update', $3, $4, $5)
ON CONFLICT(audit_id) DO UPDATE SET outcome = EXCLUDED.outcome`,
		auditID, update.RegistrationUpdatedBy, "endpoint:"+update.EndpointID, update.RegistrationStatus, nullTimeValue(updatedAt)); err != nil {
		return EndpointEntity{}, err
	}
	if err := tx.Commit(); err != nil {
		return EndpointEntity{}, err
	}
	endpoint, ok, err := s.getEndpointEntity(ctx, update.EndpointID)
	if err != nil {
		return EndpointEntity{}, err
	}
	if !ok {
		return EndpointEntity{}, fmt.Errorf("endpoint registration was written but endpoint was not found: %s", update.EndpointID)
	}
	return endpoint, nil
}

func (s *PostgresStore) WriteCollectorRun(ctx context.Context, run Run) error {
	if run.SensorID == "" {
		run.SensorID = s.sensorID
	}
	summary, _ := json.Marshal(run)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO sensors(sensor_id, display_name, collector_kind, collector_version, interface_name)
VALUES($1, $1, $2, $3, $4)
ON CONFLICT(sensor_id) DO UPDATE SET collector_kind = EXCLUDED.collector_kind, collector_version = EXCLUDED.collector_version, interface_name = EXCLUDED.interface_name, updated_at = now()`,
		run.SensorID, s.collectorKind, s.collectorVer, s.interfaceName); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO collector_runs(run_id, sensor_id, started_at, finished_at, previous_offset, new_offset, truncated, normalized_read, normalized_emitted, normalized_skipped, normalized_malformed, evidence_count, risk_count, risk_list_count, summary)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
ON CONFLICT(run_id) DO UPDATE SET
  finished_at = EXCLUDED.finished_at,
  new_offset = EXCLUDED.new_offset,
  truncated = EXCLUDED.truncated,
  normalized_read = EXCLUDED.normalized_read,
  normalized_emitted = EXCLUDED.normalized_emitted,
  normalized_skipped = EXCLUDED.normalized_skipped,
  normalized_malformed = EXCLUDED.normalized_malformed,
  evidence_count = EXCLUDED.evidence_count,
  risk_count = EXCLUDED.risk_count,
  risk_list_count = EXCLUDED.risk_list_count,
  summary = EXCLUDED.summary`,
		run.RunID, run.SensorID, run.StartedAt, run.FinishedAt, run.PreviousOffset, run.NewOffset, run.Truncated, run.Normalized.Read, run.Normalized.Emitted, run.Normalized.Skipped, run.Normalized.Malformed, run.EvidenceCount, run.RiskCount, run.RiskListCount, summary); err != nil {
		return err
	}
	auditID := "audit-collector-" + run.RunID
	if _, err := tx.ExecContext(ctx, `
INSERT INTO audit_logs(audit_id, actor, action, target, outcome, created_at)
VALUES($1, 'system', 'collector.run', $2, $3, $4)
ON CONFLICT(audit_id) DO UPDATE SET outcome = EXCLUDED.outcome`,
		auditID, run.RunID, fmt.Sprintf("risk_list_count=%d", run.RiskListCount), run.FinishedAt); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresStore) WriteEvidence(ctx context.Context, items []evidence.Evidence) error {
	if len(items) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, item := range items {
		samples, _ := json.Marshal(item.Samples)
		if item.SubjectType != "" && item.SubjectType != "ip" {
			if _, err := tx.ExecContext(ctx, `
INSERT INTO subject_evidence(evidence_id, subject_type, subject_id, account_id, endpoint_id, ip, type, "window", score, confidence, severity, reason, samples, created_at)
VALUES($1,$2,$3,$4,$5,NULLIF($6, '')::inet,$7,$8,$9,$10,$11,$12,$13,$14)
ON CONFLICT(evidence_id) DO UPDATE SET score = EXCLUDED.score, confidence = EXCLUDED.confidence, severity = EXCLUDED.severity, reason = EXCLUDED.reason, samples = EXCLUDED.samples`,
				item.EvidenceID, item.SubjectType, item.SubjectID, item.AccountID, item.EndpointID, item.IP, item.Type, item.Window, item.Score, item.Confidence, item.Severity, item.Reason, samples, item.CreatedAt); err != nil {
				return err
			}
			continue
		}
		if item.IP == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO evidence(evidence_id, ip, type, "window", score, confidence, severity, reason, samples, created_at)
VALUES($1,$2::inet,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT(evidence_id) DO UPDATE SET score = EXCLUDED.score, confidence = EXCLUDED.confidence, severity = EXCLUDED.severity, reason = EXCLUDED.reason, samples = EXCLUDED.samples`,
			item.EvidenceID, item.IP, item.Type, item.Window, item.Score, item.Confidence, item.Severity, item.Reason, samples, item.CreatedAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresStore) WriteRiskSnapshots(ctx context.Context, snapshots []risk.Snapshot) error {
	if len(snapshots) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, snapshot := range snapshots {
		evidenceIDs, _ := json.Marshal(snapshot.EvidenceIDs)
		payload, _ := json.Marshal(snapshot)
		if snapshot.SubjectType != "" && snapshot.SubjectType != "ip" {
			if _, err := tx.ExecContext(ctx, `
INSERT INTO subject_risk_snapshots(subject_type, subject_id, account_id, endpoint_id, ip, score, level, confidence, "window", evidence_ids, summary, recommended_action, updated_at)
VALUES($1,$2,$3,$4,NULLIF($5, '')::inet,$6,$7,$8,$9,$10,$11,$12,$13)
ON CONFLICT(subject_type, subject_id) DO UPDATE SET account_id = EXCLUDED.account_id, endpoint_id = EXCLUDED.endpoint_id, ip = EXCLUDED.ip, score = EXCLUDED.score, level = EXCLUDED.level, confidence = EXCLUDED.confidence, "window" = EXCLUDED."window", evidence_ids = EXCLUDED.evidence_ids, summary = EXCLUDED.summary, recommended_action = EXCLUDED.recommended_action, updated_at = EXCLUDED.updated_at`,
				snapshot.SubjectType, snapshot.SubjectID, snapshot.AccountID, snapshot.EndpointID, snapshot.IP, snapshot.Score, snapshot.Level, snapshot.Confidence, snapshot.Window, evidenceIDs, snapshot.Summary, snapshot.RecommendedAction, snapshot.UpdatedAt); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
INSERT INTO subject_risk_snapshot_history(subject_type, subject_id, snapshot)
VALUES($1, $2, $3)`, snapshot.SubjectType, snapshot.SubjectID, payload); err != nil {
				return err
			}
			continue
		}
		if snapshot.IP == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO risk_snapshots(ip, score, level, confidence, "window", evidence_ids, summary, recommended_action, updated_at)
VALUES($1::inet,$2,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT(ip) DO UPDATE SET score = EXCLUDED.score, level = EXCLUDED.level, confidence = EXCLUDED.confidence, "window" = EXCLUDED."window", evidence_ids = EXCLUDED.evidence_ids, summary = EXCLUDED.summary, recommended_action = EXCLUDED.recommended_action, updated_at = EXCLUDED.updated_at`,
			snapshot.IP, snapshot.Score, snapshot.Level, snapshot.Confidence, snapshot.Window, evidenceIDs, snapshot.Summary, snapshot.RecommendedAction, snapshot.UpdatedAt); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO risk_snapshot_history(ip, snapshot) VALUES($1::inet, $2)`, snapshot.IP, payload); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresStore) WriteDeviceState(ctx context.Context, run Run, events []normalized.Event, snapshots []risk.Snapshot) error {
	if run.SensorID == "" {
		run.SensorID = s.sensorID
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO sensors(sensor_id, display_name, collector_kind, collector_version, interface_name)
VALUES($1, $1, $2, $3, $4)
ON CONFLICT(sensor_id) DO UPDATE SET collector_kind = EXCLUDED.collector_kind, collector_version = EXCLUDED.collector_version, interface_name = EXCLUDED.interface_name, updated_at = now()`,
		run.SensorID, s.collectorKind, s.collectorVer, s.interfaceName); err != nil {
		return err
	}
	if err := writeIdentityState(ctx, tx, BuildIdentityState(events)); err != nil {
		return err
	}
	riskMap := riskSnapshotMap(snapshots)
	for _, inventory := range BuildDeviceInventories("latest-run", events, riskMap) {
		for _, signal := range inventory.Signals {
			if err := upsertDeviceSignalFact(ctx, tx, run.SensorID, signal); err != nil {
				return err
			}
		}
	}
	for _, window := range []string{"10m", "1h", "24h"} {
		inventories, err := s.buildDeviceInventoriesFromFacts(ctx, tx, run.SensorID, run.FinishedAt, window, riskMap)
		if err != nil {
			return err
		}
		for _, inventory := range inventories {
			if err := insertDeviceInventorySnapshot(ctx, tx, run, window, inventory); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func writeIdentityState(ctx context.Context, tx *sql.Tx, state IdentityState) error {
	for _, entity := range state.Endpoints {
		if err := upsertEndpointEntity(ctx, tx, entity); err != nil {
			return err
		}
	}
	for _, entity := range state.Infrastructure {
		if err := upsertInfrastructureEntity(ctx, tx, entity); err != nil {
			return err
		}
	}
	for _, session := range state.Sessions {
		if err := upsertAccountSession(ctx, tx, session); err != nil {
			return err
		}
	}
	for _, item := range state.IPMACHistory {
		if err := upsertIdentityIPMACHistory(ctx, tx, item); err != nil {
			return err
		}
	}
	for _, item := range state.AccessHistory {
		if err := upsertIdentityAccessHistory(ctx, tx, item); err != nil {
			return err
		}
	}
	return nil
}

func upsertEndpointEntity(ctx context.Context, tx *sql.Tx, entity EndpointEntity) error {
	if entity.EndpointID == "" {
		return nil
	}
	attrs, _ := json.Marshal(entity.Attributes)
	firstSeen := identitySQLTime(entity.FirstSeen)
	lastSeen := identitySQLTime(entity.LastSeen)
	_, err := tx.ExecContext(ctx, `
INSERT INTO endpoint_entities(endpoint_id, primary_mac, entity_role, first_seen, last_seen, identity_confidence, attributes)
VALUES($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT(endpoint_id) DO UPDATE SET
  primary_mac = COALESCE(endpoint_entities.primary_mac, EXCLUDED.primary_mac),
  entity_role = EXCLUDED.entity_role,
  first_seen = LEAST(endpoint_entities.first_seen, EXCLUDED.first_seen),
  last_seen = GREATEST(endpoint_entities.last_seen, EXCLUDED.last_seen),
  identity_confidence = GREATEST(endpoint_entities.identity_confidence, EXCLUDED.identity_confidence),
  attributes = endpoint_entities.attributes || EXCLUDED.attributes,
  updated_at = now()`,
		entity.EndpointID, entity.PrimaryMAC, entity.EntityRole, firstSeen, lastSeen, entity.IdentityConfidence, attrs)
	return err
}

func upsertInfrastructureEntity(ctx context.Context, tx *sql.Tx, entity InfrastructureEntity) error {
	if entity.EntityID == "" {
		return nil
	}
	attrs, _ := json.Marshal(entity.Attributes)
	firstSeen := identitySQLTime(entity.FirstSeen)
	lastSeen := identitySQLTime(entity.LastSeen)
	_, err := tx.ExecContext(ctx, `
INSERT INTO infrastructure_entities(entity_id, ip, mac, entity_role, name, source, first_seen, last_seen, attributes)
VALUES($1,NULLIF($2, '')::inet,$3,$4,$5,$6,$7,$8,$9)
ON CONFLICT(entity_id) DO UPDATE SET
  ip = COALESCE(EXCLUDED.ip, infrastructure_entities.ip),
  mac = COALESCE(EXCLUDED.mac, infrastructure_entities.mac),
  entity_role = EXCLUDED.entity_role,
  name = COALESCE(EXCLUDED.name, infrastructure_entities.name),
  first_seen = LEAST(infrastructure_entities.first_seen, EXCLUDED.first_seen),
  last_seen = GREATEST(infrastructure_entities.last_seen, EXCLUDED.last_seen),
  attributes = infrastructure_entities.attributes || EXCLUDED.attributes,
  updated_at = now()`,
		entity.EntityID, entity.IP, entity.MAC, entity.EntityRole, entity.Name, entity.Source, firstSeen, lastSeen, attrs)
	return err
}

func upsertAccountSession(ctx context.Context, tx *sql.Tx, session AccountSession) error {
	if session.SessionID == "" || session.AccountID == "" {
		return nil
	}
	rawRef, _ := json.Marshal(session.RawRef)
	startedAt := identitySQLTime(session.StartedAt)
	endedAt := nullTimeValue(nullableTime(session.EndedAt))
	_, err := tx.ExecContext(ctx, `
INSERT INTO account_sessions(session_id, account_id, endpoint_id, ip, mac, access_id, source, started_at, ended_at, identity_confidence, raw_ref)
VALUES($1,$2,$3,NULLIF($4, '')::inet,$5,$6,$7,$8,$9,$10,$11)
ON CONFLICT(session_id) DO UPDATE SET
  account_id = EXCLUDED.account_id,
  endpoint_id = EXCLUDED.endpoint_id,
  ip = EXCLUDED.ip,
  mac = EXCLUDED.mac,
  access_id = EXCLUDED.access_id,
  source = EXCLUDED.source,
  started_at = LEAST(account_sessions.started_at, EXCLUDED.started_at),
  ended_at = COALESCE(EXCLUDED.ended_at, account_sessions.ended_at),
  identity_confidence = GREATEST(account_sessions.identity_confidence, EXCLUDED.identity_confidence),
  raw_ref = account_sessions.raw_ref || EXCLUDED.raw_ref,
  updated_at = now()`,
		session.SessionID, session.AccountID, session.EndpointID, session.IP, session.MAC, session.AccessID, session.Source, startedAt, endedAt, session.IdentityConfidence, rawRef)
	return err
}

func upsertIdentityIPMACHistory(ctx context.Context, tx *sql.Tx, item IdentityIPMACHistory) error {
	if item.EventID == "" {
		return nil
	}
	eventIDs, _ := json.Marshal(item.EventIDsSample)
	firstSeen := identitySQLTime(item.FirstSeen)
	lastSeen := identitySQLTime(item.LastSeen)
	_, err := tx.ExecContext(ctx, `
INSERT INTO identity_ip_mac_history(event_id, endpoint_id, account_id, entity_role, ip, mac, source, first_seen, last_seen, identity_confidence, event_ids_sample)
VALUES($1,$2,$3,$4,NULLIF($5, '')::inet,$6,$7,$8,$9,$10,$11)
ON CONFLICT(event_id) DO UPDATE SET
  endpoint_id = EXCLUDED.endpoint_id,
  account_id = EXCLUDED.account_id,
  entity_role = EXCLUDED.entity_role,
  ip = EXCLUDED.ip,
  mac = EXCLUDED.mac,
  source = EXCLUDED.source,
  last_seen = GREATEST(identity_ip_mac_history.last_seen, EXCLUDED.last_seen),
  identity_confidence = GREATEST(identity_ip_mac_history.identity_confidence, EXCLUDED.identity_confidence),
  event_ids_sample = EXCLUDED.event_ids_sample`,
		item.EventID, item.EndpointID, item.AccountID, item.EntityRole, item.IP, item.MAC, item.Source, firstSeen, lastSeen, item.IdentityConfidence, eventIDs)
	return err
}

func upsertIdentityAccessHistory(ctx context.Context, tx *sql.Tx, item IdentityAccessHistory) error {
	if item.EventID == "" || item.AccessID == "" {
		return nil
	}
	eventIDs, _ := json.Marshal(item.EventIDsSample)
	firstSeen := identitySQLTime(item.FirstSeen)
	lastSeen := identitySQLTime(item.LastSeen)
	_, err := tx.ExecContext(ctx, `
INSERT INTO identity_access_history(event_id, endpoint_id, account_id, entity_role, access_id, access_type, ap, switch_id, switch_port, vlan, source, first_seen, last_seen, identity_confidence, event_ids_sample)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
ON CONFLICT(event_id) DO UPDATE SET
  endpoint_id = EXCLUDED.endpoint_id,
  account_id = EXCLUDED.account_id,
  entity_role = EXCLUDED.entity_role,
  access_id = EXCLUDED.access_id,
  access_type = EXCLUDED.access_type,
  ap = EXCLUDED.ap,
  switch_id = EXCLUDED.switch_id,
  switch_port = EXCLUDED.switch_port,
  vlan = EXCLUDED.vlan,
  source = EXCLUDED.source,
  last_seen = GREATEST(identity_access_history.last_seen, EXCLUDED.last_seen),
  identity_confidence = GREATEST(identity_access_history.identity_confidence, EXCLUDED.identity_confidence),
  event_ids_sample = EXCLUDED.event_ids_sample`,
		item.EventID, item.EndpointID, item.AccountID, item.EntityRole, item.AccessID, item.AccessType, item.AP, item.SwitchID, item.SwitchPort, item.VLAN, item.Source, firstSeen, lastSeen, item.IdentityConfidence, eventIDs)
	return err
}

func identitySQLTime(raw string) time.Time {
	if parsed, ok := parseTime(raw); ok {
		return parsed
	}
	return time.Now()
}

func upsertDeviceSignalFact(ctx context.Context, tx *sql.Tx, sensorID string, signal DeviceSignal) error {
	firstSeen := nullableTime(signal.FirstSeen)
	lastSeen := nullableTime(signal.LastSeen)
	if !firstSeen.Valid && lastSeen.Valid {
		firstSeen = lastSeen
	}
	if !lastSeen.Valid && firstSeen.Valid {
		lastSeen = firstSeen
	}
	if !firstSeen.Valid || !lastSeen.Valid {
		now := time.Now()
		firstSeen = sql.NullTime{Time: now, Valid: true}
		lastSeen = sql.NullTime{Time: now, Valid: true}
	}
	sample, _ := json.Marshal(signalEventIDs(signal))
	if _, err := tx.ExecContext(ctx, `
INSERT INTO device_signal_facts(sensor_id, signal_id, ip, source, kind, value, normalized_value, strength, confidence, weight, first_seen, last_seen, seen_count, event_ids_sample)
VALUES($1,$2,$3::inet,$4,$5,$6,$7,$8,$9,$10,$11,$12,0,$13)
ON CONFLICT(sensor_id, signal_id) DO UPDATE SET
  value = EXCLUDED.value,
  confidence = GREATEST(device_signal_facts.confidence, EXCLUDED.confidence),
  weight = GREATEST(device_signal_facts.weight, EXCLUDED.weight),
  first_seen = LEAST(device_signal_facts.first_seen, EXCLUDED.first_seen),
  last_seen = GREATEST(device_signal_facts.last_seen, EXCLUDED.last_seen),
  updated_at = now()`,
		sensorID, signal.SignalID, signal.IP, signal.Source, signal.Kind, signal.Value, signal.NormalizedValue, signal.Strength, signal.Confidence, signal.Weight, firstSeen.Time, lastSeen.Time, sample); err != nil {
		return err
	}
	for _, eventID := range signalEventIDs(signal) {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO device_signal_events(sensor_id, signal_id, event_id, first_seen)
VALUES($1,$2,$3,$4)
ON CONFLICT(sensor_id, signal_id, event_id) DO NOTHING`,
			sensorID, signal.SignalID, eventID, firstSeen.Time); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, `
UPDATE device_signal_facts
SET seen_count = counted.seen_count,
    event_ids_sample = COALESCE(counted.event_ids_sample, '[]'::jsonb),
    updated_at = now()
FROM (
  SELECT count(*) AS seen_count, jsonb_agg(event_id ORDER BY first_seen DESC, event_id) FILTER (WHERE event_rank <= 20) AS event_ids_sample
  FROM (
    SELECT event_id, first_seen, row_number() OVER (ORDER BY first_seen DESC, event_id) AS event_rank
    FROM device_signal_events
    WHERE sensor_id = $1 AND signal_id = $2
  ) ranked
) counted
WHERE device_signal_facts.sensor_id = $1 AND device_signal_facts.signal_id = $2`, sensorID, signal.SignalID)
	return err
}

func signalEventIDs(signal DeviceSignal) []string {
	ids := signal.EventIDsSample
	if len(ids) == 0 {
		ids = signal.EventIDs
	}
	if len(ids) == 0 {
		return []string{}
	}
	seen := map[string]struct{}{}
	result := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	return result
}

func (s *PostgresStore) buildDeviceInventoriesFromFacts(ctx context.Context, tx *sql.Tx, sensorID, finishedAt, window string, risks map[string]risk.Snapshot) ([]IPDeviceInventory, error) {
	_, duration, err := NormalizeActivityWindow(window)
	if err != nil {
		return nil, err
	}
	end := time.Now()
	if parsed, ok := parseTime(finishedAt); ok {
		end = parsed
	}
	cutoff := end.Add(-duration)
	rows, err := tx.QueryContext(ctx, `
SELECT signal_id, host(ip), source, kind, value, normalized_value, strength, confidence, weight, first_seen, last_seen, seen_count, event_ids_sample
FROM device_signal_facts
WHERE sensor_id = $1 AND last_seen >= $2
ORDER BY ip ASC, last_seen DESC, signal_id ASC`, sensorID, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byIP := map[string][]DeviceSignal{}
	for rows.Next() {
		signal, err := scanDeviceSignal(rows)
		if err != nil {
			return nil, err
		}
		byIP[signal.IP] = append(byIP[signal.IP], signal)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	ips := make([]string, 0, len(byIP))
	for ip := range byIP {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	items := make([]IPDeviceInventory, 0, len(ips))
	for _, ip := range ips {
		items = append(items, BuildDeviceInventoryFromSignals(ip, window, byIP[ip], risks[ip]))
	}
	sortDeviceInventories(items)
	return items, nil
}

func insertDeviceInventorySnapshot(ctx context.Context, tx *sql.Tx, run Run, window string, inventory IPDeviceInventory) error {
	payload, _ := json.Marshal(inventory)
	firstSeen := nullableTime(inventory.FirstSeen)
	lastSeen := nullableTime(inventory.LastSeen)
	strong, medium, weak := inventorySignalCounts(inventory)
	_, err := tx.ExecContext(ctx, `
INSERT INTO device_inventory_snapshots(run_id, sensor_id, "window", ip, suspected_device_count, confidence, status, summary, strong_signal_count, medium_signal_count, weak_signal_count, conflict_count, first_seen, last_seen, inventory)
VALUES($1,$2,$3,$4::inet,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
ON CONFLICT(run_id, "window", ip) DO UPDATE SET
  suspected_device_count = EXCLUDED.suspected_device_count,
  confidence = EXCLUDED.confidence,
  status = EXCLUDED.status,
  summary = EXCLUDED.summary,
  strong_signal_count = EXCLUDED.strong_signal_count,
  medium_signal_count = EXCLUDED.medium_signal_count,
  weak_signal_count = EXCLUDED.weak_signal_count,
  conflict_count = EXCLUDED.conflict_count,
  first_seen = EXCLUDED.first_seen,
  last_seen = EXCLUDED.last_seen,
  inventory = EXCLUDED.inventory,
  created_at = now()`,
		run.RunID, run.SensorID, window, inventory.IP, inventory.SuspectedDeviceCount, inventory.Confidence, inventory.Status, inventory.Summary, strong, medium, weak, len(inventory.Conflicts), nullTimeValue(firstSeen), nullTimeValue(lastSeen), payload)
	return err
}

func inventorySignalCounts(inventory IPDeviceInventory) (int, int, int) {
	strong, medium, weak := 0, 0, 0
	for _, signal := range inventory.Signals {
		switch signal.Strength {
		case "strong":
			strong++
		case "medium":
			medium++
		default:
			weak++
		}
	}
	return strong, medium, weak
}

func nullableTime(raw string) sql.NullTime {
	if parsed, ok := parseTime(raw); ok {
		return sql.NullTime{Time: parsed, Valid: true}
	}
	return sql.NullTime{}
}

func nullTimeValue(value sql.NullTime) any {
	if !value.Valid {
		return nil
	}
	return value.Time
}

func (s *PostgresStore) ListDeviceInventories(ctx context.Context, query Query) (DevicePage, error) {
	limit := query.Limit
	if limit == 0 {
		limit = 50
	}
	window := query.Window
	if window == "" {
		window = "1h"
	}
	sensorID := query.SensorID
	if sensorID == "" {
		sensorID = s.sensorID
	}
	where := []string{`sensor_id = $1`, `"window" = $2`, `run_id = (
  SELECT run_id FROM device_inventory_snapshots
  WHERE sensor_id = $1 AND "window" = $2
  ORDER BY created_at DESC, run_id DESC
  LIMIT 1
)`}
	args := []any{sensorID, window}
	if query.SrcIP != "" {
		args = append(args, query.SrcIP)
		where = append(where, "ip = $"+strconvArg(len(args))+"::inet")
	}
	if query.Q != "" {
		args = append(args, "%"+strings.ToLower(query.Q)+"%")
		where = append(where, "(lower(host(ip)) LIKE $"+strconvArg(len(args))+" OR lower(summary) LIKE $"+strconvArg(len(args))+" OR lower(inventory::text) LIKE $"+strconvArg(len(args))+")")
	}
	if !query.IncludeWeak {
		where = append(where, "confidence >= 0.80 AND status <> 'weak_signals_only'")
	}
	whereSQL := " WHERE " + strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM device_inventory_snapshots"+whereSQL, args...).Scan(&total); err != nil {
		return DevicePage{}, err
	}
	if limit < 0 {
		limit = total
	}
	selectArgs := append(append([]any{}, args...), limit, query.Cursor)
	rows, err := s.db.QueryContext(ctx, `
SELECT inventory
FROM device_inventory_snapshots`+whereSQL+`
ORDER BY suspected_device_count DESC, conflict_count DESC, strong_signal_count DESC, confidence DESC, last_seen DESC NULLS LAST, ip ASC
LIMIT $`+strconvArg(len(selectArgs)-1)+` OFFSET $`+strconvArg(len(selectArgs)), selectArgs...)
	if err != nil {
		return DevicePage{}, err
	}
	defer rows.Close()
	items, err := scanDeviceInventoryRows(rows)
	if err != nil {
		return DevicePage{}, err
	}
	var next *string
	if query.Cursor+len(items) < total {
		value := fmt.Sprintf("%d", query.Cursor+len(items))
		next = &value
	}
	return DevicePage{Items: items, Page: Page{Limit: query.Limit, NextCursor: next, Total: total}}, nil
}

func (s *PostgresStore) GetIPDeviceInventory(ctx context.Context, ip string, query ActivityQuery) (IPDeviceInventory, error) {
	window := query.Window
	if window == "" {
		window = "1h"
	}
	sensorID := query.SensorID
	if sensorID == "" {
		sensorID = s.sensorID
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT inventory
FROM device_inventory_snapshots
WHERE sensor_id = $1 AND "window" = $2 AND ip = $3::inet
ORDER BY created_at DESC, run_id DESC
LIMIT 1`, sensorID, window, ip)
	if err != nil {
		return IPDeviceInventory{}, err
	}
	defer rows.Close()
	items, err := scanDeviceInventoryRows(rows)
	if err != nil {
		return IPDeviceInventory{}, err
	}
	if len(items) == 0 {
		return IPDeviceInventory{
			IP:        ip,
			Window:    window,
			Status:    "insufficient_signal",
			Summary:   "当前设备库存快照中没有足够设备识别信号",
			Devices:   []ObservedDevice{},
			Signals:   []DeviceSignal{},
			Conflicts: []DeviceConflict{},
		}, nil
	}
	return items[0], nil
}

func (s *PostgresStore) GetDevice(ctx context.Context, deviceID string, query Query) (ObservedDevice, bool, error) {
	page, err := s.ListDeviceInventories(ctx, Query{SensorID: query.SensorID, Window: query.Window, IncludeWeak: true, Limit: -1})
	if err != nil {
		return ObservedDevice{}, false, err
	}
	for _, inventory := range page.Items {
		for _, device := range inventory.Devices {
			if device.DeviceID == deviceID {
				return device, true, nil
			}
		}
	}
	return ObservedDevice{}, false, nil
}

func (s *PostgresStore) ListDeviceSignals(ctx context.Context, query Query) ([]DeviceSignal, error) {
	window := query.Window
	if window == "" {
		window = "1h"
	}
	sensorID := query.SensorID
	if sensorID == "" {
		sensorID = s.sensorID
	}
	_, duration, err := NormalizeActivityWindow(window)
	if err != nil {
		return nil, err
	}
	cutoff := time.Now().Add(-duration)
	where := []string{"sensor_id = $1", "last_seen >= $2"}
	args := []any{sensorID, cutoff}
	if query.SrcIP != "" {
		args = append(args, query.SrcIP)
		where = append(where, "ip = $"+strconvArg(len(args))+"::inet")
	}
	if query.Q != "" {
		args = append(args, "%"+strings.ToLower(query.Q)+"%")
		where = append(where, "(lower(host(ip)) LIKE $"+strconvArg(len(args))+" OR lower(source) LIKE $"+strconvArg(len(args))+" OR lower(kind) LIKE $"+strconvArg(len(args))+" OR lower(value) LIKE $"+strconvArg(len(args))+")")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT signal_id, host(ip), source, kind, value, normalized_value, strength, confidence, weight, first_seen, last_seen, seen_count, event_ids_sample
FROM device_signal_facts
WHERE `+strings.Join(where, " AND ")+`
ORDER BY last_seen DESC, signal_id ASC
LIMIT 1000`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []DeviceSignal{}
	for rows.Next() {
		signal, err := scanDeviceSignal(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, signal)
	}
	return items, rows.Err()
}

func (s *PostgresStore) ListDeviceFingerprintConflicts(ctx context.Context, query Query) ([]DeviceConflict, error) {
	page, err := s.ListDeviceInventories(ctx, Query{SensorID: query.SensorID, Window: query.Window, SrcIP: query.SrcIP, Q: query.Q, IncludeWeak: true, Limit: -1})
	if err != nil {
		return nil, err
	}
	conflicts := []DeviceConflict{}
	for _, inventory := range page.Items {
		conflicts = append(conflicts, inventory.Conflicts...)
	}
	return conflicts, nil
}

func scanDeviceInventoryRows(rows *sql.Rows) ([]IPDeviceInventory, error) {
	items := []IPDeviceInventory{}
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var inventory IPDeviceInventory
		if err := json.Unmarshal(payload, &inventory); err != nil {
			return nil, err
		}
		items = append(items, inventory)
	}
	return items, rows.Err()
}

type deviceSignalScanner interface {
	Scan(dest ...any) error
}

func scanDeviceSignal(scanner deviceSignalScanner) (DeviceSignal, error) {
	var signal DeviceSignal
	var firstSeen, lastSeen time.Time
	var sample []byte
	var seenCount int64
	if err := scanner.Scan(&signal.SignalID, &signal.IP, &signal.Source, &signal.Kind, &signal.Value, &signal.NormalizedValue, &signal.Strength, &signal.Confidence, &signal.Weight, &firstSeen, &lastSeen, &seenCount, &sample); err != nil {
		return DeviceSignal{}, err
	}
	_ = json.Unmarshal(sample, &signal.EventIDsSample)
	signal.EventIDs = append([]string{}, signal.EventIDsSample...)
	signal.SeenCount = int(seenCount)
	signal.FirstSeen = firstSeen.Format(time.RFC3339Nano)
	signal.LastSeen = lastSeen.Format(time.RFC3339Nano)
	return signal, nil
}

func (s *PostgresStore) topEvidence(ctx context.Context) ([]ingest.EventTypeCount, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT type, count(*) FROM evidence GROUP BY type ORDER BY count(*) DESC, type ASC LIMIT 20`)
	if errors.Is(err, sql.ErrNoRows) {
		return []ingest.EventTypeCount{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ingest.EventTypeCount{}
	for rows.Next() {
		var item ingest.EventTypeCount
		if err := rows.Scan(&item.Type, &item.Count); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func riskWhere(query Query) (string, []any, error) {
	clauses := []string{}
	args := []any{}
	if query.Level != "" {
		args = append(args, query.Level)
		clauses = append(clauses, "level = $"+strconvArg(len(args)))
	}
	if query.Q != "" {
		args = append(args, "%"+strings.ToLower(query.Q)+"%")
		clauses = append(clauses, "(lower(host(ip)) LIKE $"+strconvArg(len(args))+" OR lower(summary) LIKE $"+strconvArg(len(args))+")")
	}
	if query.From != "" {
		if _, err := optionalTime(query.From); err != nil {
			return "", nil, fmt.Errorf("bad from: %w", err)
		}
		args = append(args, query.From)
		clauses = append(clauses, "updated_at >= $"+strconvArg(len(args))+"::timestamptz")
	}
	if query.To != "" {
		if _, err := optionalTime(query.To); err != nil {
			return "", nil, fmt.Errorf("bad to: %w", err)
		}
		args = append(args, query.To)
		clauses = append(clauses, "updated_at <= $"+strconvArg(len(args))+"::timestamptz")
	}
	if len(clauses) == 0 {
		return "", args, nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args, nil
}

func scanRiskRows(rows *sql.Rows) ([]risk.Snapshot, error) {
	items := []risk.Snapshot{}
	for rows.Next() {
		var item risk.Snapshot
		var evidenceIDs []byte
		var updated time.Time
		if err := rows.Scan(&item.IP, &item.Score, &item.Level, &item.Confidence, &item.Window, &evidenceIDs, &item.Summary, &item.RecommendedAction, &updated); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(evidenceIDs, &item.EvidenceIDs)
		item.UpdatedAt = updated.Format(time.RFC3339Nano)
		items = append(items, item)
	}
	return items, rows.Err()
}

func strconvArg(value int) string {
	return fmt.Sprintf("%d", value)
}
