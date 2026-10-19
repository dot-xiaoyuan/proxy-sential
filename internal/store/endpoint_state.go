package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Endpoint state updater.
//
// The terminal list reads one prepared row per endpoint (endpoint_inventory_lookup plus
// endpoint_inventory_accounts). The previous producer kept that row current through
// per-row triggers on eight source tables, a delta queue and a per-origin contribution
// ledger; on 184 that queue reached 5M inserts in 13.5 hours and a single gateway MAC
// held 558k pending deltas. This updater keeps the same read model with a much smaller
// write path:
//
//   - each round reads the endpoints whose source rows changed since a keyset watermark
//     (endpoint_entities, recognition summary, account_sessions, snapshot projection, DHCP
//     leases, name notes);
//   - a round-robin sweep re-derives a slice of every endpoint, so time-based expiry of
//     sessions is reflected without a timer table;
//   - affected endpoints are recomputed set-wise in one statement per chunk and written
//     back with one upsert, skipping rows whose content did not change.
const (
	endpointStateInterval    = 15 * time.Second
	endpointStateChunk       = 300
	endpointStateSourceLimit = 5000
	endpointStateSweep       = 1000
	// endpointSessionFreshness matches the router binding rule: a session counts as
	// current only while it is open and was refreshed within three reconcile intervals.
	endpointSessionFreshness = 90 * time.Minute
)

type endpointStateKey struct {
	At string `json:"at"`
	ID string `json:"id"`
}

type endpointStateSource struct {
	name  string
	query string
}

// Each source returns (endpoint_id, change time) after a (time, endpoint_id) keyset.
var endpointStateSources = []endpointStateSource{
	{"entities", `SELECT endpoint_id,updated_at FROM endpoint_entities WHERE (updated_at,endpoint_id)>($1,$2) ORDER BY updated_at,endpoint_id LIMIT $3`},
	{"recognition", `SELECT endpoint_id,updated_at FROM endpoint_recognition_summary WHERE (updated_at,endpoint_id)>($1,$2) ORDER BY updated_at,endpoint_id LIMIT $3`},
	{"sessions", `SELECT endpoint_id,updated_at FROM account_sessions WHERE endpoint_id IS NOT NULL AND endpoint_id<>'' AND (updated_at,endpoint_id)>($1,$2) ORDER BY updated_at,endpoint_id LIMIT $3`},
	// Snapshot membership changes only: unchanged members are not rewritten (projectionUpsertSQL), and
	// their confirmation follows the scope snapshot, which the sweep picks up.
	{"projection", `SELECT document->>'endpoint_id',confirmed_at FROM account_identity_session_projection WHERE (confirmed_at,document->>'endpoint_id')>($1,$2) ORDER BY confirmed_at,document->>'endpoint_id' LIMIT $3`},
	{"leases", `SELECT endpoint_id,observed_at FROM device_address_leases WHERE (observed_at,endpoint_id)>($1,$2) ORDER BY observed_at,endpoint_id LIMIT $3`},
	{"notes", `SELECT endpoint_id,updated_at FROM device_name_notes WHERE (updated_at,endpoint_id)>($1,$2) ORDER BY updated_at,endpoint_id LIMIT $3`},
}

func (s *DBStore) RunEndpointStateUpdater(ctx context.Context) {
	for ctx.Err() == nil {
		work, cancel := context.WithTimeout(ctx, 4*time.Minute)
		refreshed, err := s.pg.endpointStateRound(work)
		cancel()
		report, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "endpoint state round failed: %v\n", err)
			_, _ = s.pg.db.ExecContext(report, `UPDATE endpoint_state_watermark SET last_error=$1,updated_at=now() WHERE singleton`, err.Error())
		} else if err == nil {
			_, _ = s.pg.db.ExecContext(report, `UPDATE endpoint_state_watermark SET last_error='',last_success_at=now(),refreshed_endpoints=refreshed_endpoints+$1,updated_at=now() WHERE singleton`, refreshed)
		}
		stop()
		select {
		case <-ctx.Done():
			return
		case <-time.After(endpointStateInterval):
		}
	}
}

// endpointStateRound runs one bootstrap step, the change-set pass and one sweep slice.
func (s *PostgresStore) endpointStateRound(ctx context.Context) (int, error) {
	var raw []byte
	var bootstrapCursor string
	var bootstrapComplete bool
	if err := s.db.QueryRowContext(ctx, `SELECT cursors,bootstrap_cursor,bootstrap_complete FROM endpoint_state_watermark WHERE singleton`).Scan(&raw, &bootstrapCursor, &bootstrapComplete); err != nil {
		return 0, err
	}
	cursors := map[string]endpointStateKey{}
	if err := json.Unmarshal(raw, &cursors); err != nil {
		return 0, err
	}
	refreshed := 0
	if !bootstrapComplete {
		ids, err := s.endpointIDsAfter(ctx, bootstrapCursor, endpointStateSweep)
		if err != nil {
			return refreshed, err
		}
		if err = s.refreshEndpointStates(ctx, ids); err != nil {
			return refreshed, err
		}
		refreshed += len(ids)
		next := bootstrapCursor
		if len(ids) > 0 {
			next = ids[len(ids)-1]
		}
		if _, err = s.db.ExecContext(ctx, `UPDATE endpoint_state_watermark SET bootstrap_cursor=$1,bootstrap_complete=$2,updated_at=now() WHERE singleton`, next, len(ids) < endpointStateSweep); err != nil {
			return refreshed, err
		}
	}
	changed := map[string]bool{}
	sessionChanged := map[string]bool{}
	for _, source := range endpointStateSources {
		position := cursors[source.name]
		if position.At == "" {
			// Bootstrap covers everything older than the updater's first round.
			position.At = time.Now().UTC().Add(-endpointStateInterval).Format(time.RFC3339Nano)
		}
		at, err := time.Parse(time.RFC3339Nano, position.At)
		if err != nil {
			return refreshed, fmt.Errorf("endpoint state %s cursor: %w", source.name, err)
		}
		rows, err := s.db.QueryContext(ctx, source.query, at, position.ID, endpointStateSourceLimit)
		if err != nil {
			return refreshed, fmt.Errorf("endpoint state %s: %w", source.name, err)
		}
		for rows.Next() {
			var id string
			var stamp time.Time
			if err = rows.Scan(&id, &stamp); err != nil {
				rows.Close()
				return refreshed, err
			}
			changed[id] = true
			if source.name == "sessions" {
				sessionChanged[id] = true
			}
			position = endpointStateKey{At: stamp.UTC().Format(time.RFC3339Nano), ID: id}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return refreshed, err
		}
		cursors[source.name] = position
	}
	// Round-robin sweep: every endpoint is re-derived about every 20 minutes, which ends
	// sessions that went stale without a source update.
	sweep, err := s.endpointIDsAfter(ctx, cursors["sweep"].ID, endpointStateSweep)
	if err != nil {
		return refreshed, err
	}
	for _, id := range sweep {
		changed[id] = true
	}
	sweepCursor := ""
	if len(sweep) == endpointStateSweep {
		sweepCursor = sweep[len(sweep)-1]
	}
	cursors["sweep"] = endpointStateKey{ID: sweepCursor}
	ids := make([]string, 0, len(changed))
	for id := range changed {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if err = s.refreshEndpointStates(ctx, ids); err != nil {
		return refreshed, err
	}
	if err = s.markRecognitionForSessions(ctx, sessionChanged); err != nil {
		return refreshed, err
	}
	refreshed += len(ids)
	encoded, _ := json.Marshal(cursors)
	_, err = s.db.ExecContext(ctx, `UPDATE endpoint_state_watermark SET cursors=$1,updated_at=now() WHERE singleton`, encoded)
	return refreshed, err
}

func (s *PostgresStore) endpointIDsAfter(ctx context.Context, after string, limit int) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT endpoint_id FROM endpoint_entities WHERE endpoint_id>$1 ORDER BY endpoint_id LIMIT $2`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

type endpointStateSession struct {
	Account    string            `json:"account"`
	Access     string            `json:"access"`
	IP         string            `json:"ip"`
	At         time.Time         `json:"at"`
	Dimensions map[string]string `json:"dims"`
}

type endpointStateRow struct {
	ID         string          `json:"endpoint_id"`
	Item       json.RawMessage `json:"list_item"`
	LastSeen   *time.Time      `json:"last_seen"`
	Name       string          `json:"device_name"`
	MACKey     string          `json:"mac_key"`
	CurrentIP  string          `json:"current_ip"`
	SearchText string          `json:"search_text"`
	Dimensions json.RawMessage `json:"dimensions"`
	Accounts   []string        `json:"accounts"`
	AccountAt  *time.Time      `json:"account_at"`
}

// projectionCurrentSQL keeps a snapshot member current while its scope's latest projected snapshot is
// within three reconcile intervals, the same rule the router bindings use.
const projectionCurrentSQL = "src.observed_at>=now()-make_interval(secs=>GREATEST(60,LEAST(86400,COALESCE(NULLIF(p.document->>'reconcile_interval_seconds','')::int,1800)))*3)"

// endpointStateSQL derives every input of one endpoint row in a single set-wise read:
// entity, recognition item, manual name, latest DHCP lease and current sessions. Current
// sessions come from account_sessions (events) and from open members of the snapshot
// projection: a device online since before the event stream existed has no event session.
const endpointStateSQL = `WITH ids AS (SELECT DISTINCT unnest($1::text[]) AS id)
SELECT e.endpoint_id,coalesce(r.list_item,'{}'::jsonb),coalesce(e.primary_mac,''),coalesce(nullif(n.value,''),r.device_name,''),coalesce(n.value,'')<>'',
 coalesce(e.owner_account,''),coalesce(e.owner_name,''),concat_ws(' ',e.owner_account,e.owner_name,e.owner_department,e.asset_tag),e.last_seen,
 coalesce(l.ip,''),l.observed_at,
 coalesce((SELECT jsonb_agg(jsonb_build_object('account',s.account_id,'access',coalesce(s.access_id,''),'ip',coalesce(host(s.ip),''),
   'at',greatest(s.started_at,coalesce(nullif(s.policy_metadata->>'last_confirmed_at','')::timestamptz,s.started_at)),
   'dims',jsonb_strip_nulls(jsonb_build_object('campus_id',nullif(s.campus_id::text,''),'department',nullif(s.department::text,''),'person_type',nullif(s.person_type::text,''),
     'ssid',nullif(s.ssid::text,''),'vlan',nullif(s.vlan::text,''),'ap',nullif(s.ap::text,''),'nas_ip',host(s.nas_ip)))))
  FROM account_sessions s WHERE s.endpoint_id=e.endpoint_id AND s.ended_at IS NULL AND s.updated_at>now()-$2::interval),'[]'::jsonb)
 ||coalesce((SELECT jsonb_agg(jsonb_build_object('account',p.account_id,'access',coalesce(p.document->>'access_id',''),'ip',p.ip,
   'at',` + projectionConfirmedSQL + `,
   'dims',jsonb_strip_nulls(jsonb_build_object('campus_id',nullif(p.document->>'campus_id',''),'department',nullif(p.document->>'department',''),'person_type',nullif(p.document->>'person_type',''),
     'ssid',nullif(p.document->>'ssid',''),'vlan',nullif(p.document->>'vlan',''),'ap',nullif(p.document->>'ap',''),'nas_ip',nullif(p.document->>'nas_ip','')))))
  FROM account_identity_session_projection p JOIN account_identity_projection_sources src USING(source,sensor_id,campus_id,access_domain)
  WHERE p.document->>'endpoint_id'=e.endpoint_id AND COALESCE(p.document->>'ended_at','')='' AND ` + projectionCurrentSQL + `),'[]'::jsonb)
FROM ids JOIN endpoint_entities e ON e.endpoint_id=ids.id
LEFT JOIN endpoint_recognition_summary r ON r.endpoint_id=e.endpoint_id
LEFT JOIN device_name_notes n ON n.endpoint_id=e.endpoint_id
LEFT JOIN LATERAL (SELECT host(d.ip) AS ip,d.observed_at FROM device_address_leases d WHERE d.endpoint_id=e.endpoint_id AND d.action='ack' ORDER BY d.observed_at DESC LIMIT 1) l ON true`

func (s *PostgresStore) refreshEndpointStates(ctx context.Context, ids []string) error {
	for start := 0; start < len(ids); start += endpointStateChunk {
		if err := s.refreshEndpointStateChunk(ctx, ids[start:min(start+endpointStateChunk, len(ids))]); err != nil {
			return err
		}
	}
	return nil
}

func (s *PostgresStore) refreshEndpointStateChunk(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	rows, err := s.db.QueryContext(ctx, endpointStateSQL, ids, fmt.Sprintf("%d seconds", int(endpointSessionFreshness.Seconds())))
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	states := make([]endpointStateRow, 0, len(ids))
	found := map[string]bool{}
	for rows.Next() {
		var in endpointStateInput
		var leaseAt, seen sql.NullTime
		var sessions []byte
		if err = rows.Scan(&in.ID, &in.Item, &in.MAC, &in.Name, &in.Manual, &in.OwnerAccount, &in.OwnerName, &in.Owner, &seen, &in.LeaseIP, &leaseAt, &sessions); err != nil {
			rows.Close()
			return err
		}
		in.Seen = seen
		in.LeaseAt = leaseAt
		if err = json.Unmarshal(sessions, &in.Sessions); err != nil {
			rows.Close()
			return err
		}
		state, buildErr := buildEndpointState(in, now)
		if buildErr != nil {
			rows.Close()
			return buildErr
		}
		states = append(states, state)
		found[in.ID] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	missing := []string{}
	for _, id := range ids {
		if !found[id] {
			missing = append(missing, id)
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// The read model is rebuilt from durable sources on every sweep; a lost commit only
	// delays one refresh, so this write does not wait for a WAL fsync.
	if _, err = tx.ExecContext(ctx, `SET LOCAL synchronous_commit = off`); err != nil {
		return err
	}
	if len(missing) > 0 {
		for _, table := range []string{"endpoint_inventory_lookup", "endpoint_inventory_accounts"} {
			if _, err = tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE endpoint_id=ANY($1::text[])`, missing); err != nil {
				return err
			}
		}
	}
	if len(states) > 0 {
		body, marshalErr := json.Marshal(states)
		if marshalErr != nil {
			return marshalErr
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_lookup(endpoint_id,list_item,last_seen,device_name,mac_key,current_ip,search_text,dimensions)
 SELECT r.endpoint_id,r.list_item,r.last_seen,r.device_name,r.mac_key,nullif(r.current_ip,'')::inet,r.search_text,coalesce(r.dimensions,'{}'::jsonb)
 FROM jsonb_to_recordset($1::jsonb) r(endpoint_id text,list_item jsonb,last_seen timestamptz,device_name text,mac_key text,current_ip text,search_text text,dimensions jsonb)
 ORDER BY r.endpoint_id
 ON CONFLICT(endpoint_id) DO UPDATE SET list_item=EXCLUDED.list_item,last_seen=EXCLUDED.last_seen,device_name=EXCLUDED.device_name,mac_key=EXCLUDED.mac_key,current_ip=EXCLUDED.current_ip,search_text=EXCLUDED.search_text,dimensions=EXCLUDED.dimensions,updated_at=now()
 WHERE (endpoint_inventory_lookup.list_item,endpoint_inventory_lookup.last_seen,endpoint_inventory_lookup.device_name,endpoint_inventory_lookup.mac_key,endpoint_inventory_lookup.current_ip,endpoint_inventory_lookup.search_text,endpoint_inventory_lookup.dimensions)
   IS DISTINCT FROM (EXCLUDED.list_item,EXCLUDED.last_seen,EXCLUDED.device_name,EXCLUDED.mac_key,EXCLUDED.current_ip,EXCLUDED.search_text,EXCLUDED.dimensions)`, body); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM endpoint_inventory_accounts a USING jsonb_to_recordset($1::jsonb) r(endpoint_id text,accounts text[])
 WHERE a.endpoint_id=r.endpoint_id AND NOT (a.account_id=ANY(coalesce(r.accounts,ARRAY[]::text[])))`, body); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_accounts(endpoint_id,account_id,observed_at)
 SELECT r.endpoint_id,a.account_id,r.account_at FROM jsonb_to_recordset($1::jsonb) r(endpoint_id text,accounts text[],account_at timestamptz) CROSS JOIN LATERAL unnest(r.accounts) a(account_id)
 ORDER BY 1,2
 ON CONFLICT(endpoint_id,account_id) DO UPDATE SET observed_at=EXCLUDED.observed_at WHERE endpoint_inventory_accounts.observed_at IS DISTINCT FROM EXCLUDED.observed_at`, body); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type endpointStateInput struct {
	ID, MAC, Name, OwnerAccount, OwnerName, Owner, LeaseIP string
	Item                                                   []byte
	Manual                                                 bool
	Seen, LeaseAt                                          sql.NullTime
	Sessions                                               []endpointStateSession
}

// buildEndpointState composes the list row exactly as the previous projection did:
// recognition item, entity ownership, manual name, then the latest account/access/IP.
func buildEndpointState(in endpointStateInput, now time.Time) (endpointStateRow, error) {
	var item EndpointDeviceInventory
	if err := json.Unmarshal(in.Item, &item); err != nil {
		return endpointStateRow{}, err
	}
	item.EndpointID, item.PrimaryMAC, item.OwnerAccount, item.OwnerName = in.ID, in.MAC, in.OwnerAccount, in.OwnerName
	if in.Name == "" {
		item.DeviceName = nil
	} else {
		if item.DeviceName == nil {
			item.DeviceName = &DeviceName{}
		}
		item.DeviceName.Value = in.Name
		if in.Manual {
			item.DeviceName.Manual = true
			item.DeviceName.Source = "manual_note"
			item.DeviceName.Status = "current"
		}
	}
	profile := EndpointIdentityProfile{}
	dimensions := map[string]string{}
	var dimensionsAt time.Time
	for _, session := range in.Sessions {
		if session.At.After(now) {
			continue
		}
		stamp := session.At.UTC().Format(time.RFC3339Nano)
		profile.IPHistory = append(profile.IPHistory, IdentityIPMACHistory{AccountID: session.Account, LastSeen: stamp})
		if session.IP != "" {
			profile.IPHistory = append(profile.IPHistory, IdentityIPMACHistory{IP: session.IP, LastSeen: stamp})
		}
		if session.Access != "" {
			profile.AccessHistory = append(profile.AccessHistory, IdentityAccessHistory{AccessID: session.Access, LastSeen: stamp})
		}
		if session.At.After(dimensionsAt) {
			dimensions, dimensionsAt = session.Dimensions, session.At
		}
	}
	if in.LeaseIP != "" && in.LeaseAt.Valid && !in.LeaseAt.Time.After(now) {
		profile.IPHistory = append(profile.IPHistory, IdentityIPMACHistory{IP: in.LeaseIP, LastSeen: in.LeaseAt.Time.UTC().Format(time.RFC3339Nano)})
	}
	applyLatestInventoryAssociations(&item, profile, now)
	latest := latestInventoryAssociations(profile, now)
	seen := in.Seen
	if seen.Valid && seen.Time.After(now) {
		seen = sql.NullTime{}
	}
	for _, at := range []time.Time{latest.AccountAt, latest.IPAt, latest.AccessAt} {
		if !at.IsZero() && (!seen.Valid || at.After(seen.Time)) {
			seen = sql.NullTime{Time: at, Valid: true}
		}
	}
	row := endpointStateRow{ID: in.ID, Name: in.Name, CurrentIP: item.CurrentIP, Accounts: append([]string{}, item.CurrentAccountCandidates...)}
	item.LastSeen = ""
	if seen.Valid {
		// Minute precision keeps a busy endpoint from rewriting its row on every event batch.
		at := seen.Time.UTC().Truncate(time.Minute)
		row.LastSeen = &at
		item.LastSeen = at.Format(time.RFC3339Nano)
	}
	if !latest.AccountAt.IsZero() {
		at := latest.AccountAt.UTC()
		row.AccountAt = &at
	}
	row.MACKey = strings.ToLower(strings.NewReplacer(":", "", "-", "", ".", "").Replace(in.MAC))
	row.SearchText = strings.ToLower(strings.Join([]string{in.ID, in.MAC, row.MACKey, item.CurrentIP, in.Name, strings.Join(item.CurrentAccountCandidates, " "), item.CurrentAccessID, in.Owner, item.Brand, item.Model, item.OSFamily, item.DeviceType}, " "))
	compact, err := json.Marshal(ProjectDeviceInventoryListItem(item))
	if err != nil {
		return endpointStateRow{}, err
	}
	row.Item = compact
	if dimensions == nil {
		dimensions = map[string]string{}
	}
	row.Dimensions, _ = json.Marshal(dimensions)
	return row, nil
}

// endpointStateProjection reports the updater's progress in the shape the list and
// detail responses already expose.
func endpointStateProjection(ctx context.Context, db inventoryRowQueryer) (InventoryProjectionState, error) {
	var s InventoryProjectionState
	var updated time.Time
	var success sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT bootstrap_complete,last_error,last_success_at,updated_at FROM endpoint_state_watermark WHERE singleton`).Scan(&s.Complete, &s.Error, &success, &updated)
	if err == sql.ErrNoRows {
		return InventoryProjectionState{Status: "backfilling"}, nil
	}
	if err != nil {
		return s, err
	}
	// Rows written by the previous projection stay readable while the updater refills them.
	s.Available = true
	s.Updating = !s.Complete
	s.AsOf = updated.UTC().Format(time.RFC3339Nano)
	if success.Valid {
		s.AsOf = success.Time.UTC().Format(time.RFC3339Nano)
		s.ProcessingLagSeconds = max(0, time.Since(success.Time).Seconds())
	}
	s.ResultVersion = s.AsOf
	switch {
	case s.Error != "":
		s.Status = "failed"
	case !s.Complete:
		s.Status = "backfilling"
	case s.ProcessingLagSeconds > 2*endpointStateInterval.Seconds()+60:
		s.Status = "processing"
		s.Updating = true
	default:
		s.Status = "ready"
	}
	return s, nil
}

// markRecognitionForSessions replaces the per-row recognition trigger on account_sessions
// (dropped in migration 140). That trigger took recognition job row locks inside the
// authentication lane's long session insert and blocked every other writer of the same
// endpoints; here the change set is marked once per round, sorted, in a short transaction.
func (s *PostgresStore) markRecognitionForSessions(ctx context.Context, changed map[string]bool) error {
	if len(changed) == 0 {
		return nil
	}
	ids := make([]string, 0, len(changed))
	for id := range changed {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	_, err := s.db.ExecContext(ctx, `SELECT mark_endpoint_recognition_dirty(id) FROM unnest($1::text[]) AS t(id) ORDER BY id`, ids)
	return err
}
