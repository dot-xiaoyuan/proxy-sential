package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

var ErrInventoryProjectionRepairRequired = errors.New("inventory projection repair required")

type inventoryOrigin [3]string

func (o inventoryOrigin) json() string { b, _ := json.Marshal(o); return string(b) }

type inventoryRelation struct{ Kind, Value, Source string }
type inventoryContribution struct {
	inventoryRelation
	First, Last time.Time
	Confidence  float64
	Event       string
	Session     bool
}
type inventoryDeltaBatch struct {
	IDs    []int64
	Cursor int64
}

// Only the selected delta IDs are acknowledged. The generation fence belongs
// to the outer transaction; no source notification row is locked during work.
func (s *PostgresStore) materializeInventoryDeltaTx(ctx context.Context, tx *sql.Tx, id string) (inventoryDeltaBatch, error) {
	batch := inventoryDeltaBatch{}
	rows, err := tx.QueryContext(ctx, `SELECT delta_id,source_table,payload,old_payload FROM endpoint_inventory_projection_deltas WHERE endpoint_id=$1 ORDER BY delta_id LIMIT 500`, id)
	if err != nil {
		return batch, err
	}
	origins := map[inventoryOrigin]bool{}
	for rows.Next() {
		var delta int64
		var table string
		var current, previous []byte
		if err = rows.Scan(&delta, &table, &current, &previous); err != nil {
			rows.Close()
			return batch, err
		}
		batch.IDs = append(batch.IDs, delta)
		batch.Cursor = delta
		for _, raw := range [][]byte{current, previous} {
			if len(raw) == 0 {
				continue
			}
			var v struct {
				Source  string `json:"source"`
				Event   string `json:"event_id"`
				Session string `json:"session_id"`
			}
			if err = json.Unmarshal(raw, &v); err != nil {
				rows.Close()
				return batch, err
			}
			switch table {
			case "identity_ip_mac_history", "identity_access_history", "endpoint_inventory_snapshot_facts":
				origins[inventoryOrigin{"observation", v.Source, v.Event}] = true
			case "account_sessions", "account_identity_session_projection":
				origins[inventoryOrigin{"session", v.Source, v.Session}] = true
			case "endpoint_entities", "endpoint_recognition_summary", "device_name_notes": // Current scalar fields are read once below.
			default:
				rows.Close()
				return batch, fmt.Errorf("%w: unsupported source %s", ErrInventoryProjectionRepairRequired, table)
			}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return batch, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT origin_key FROM endpoint_inventory_projection_timers WHERE endpoint_id=$1 AND due_at<=now() ORDER BY due_at,origin_key LIMIT 500`, id)
	if err != nil {
		return batch, err
	}
	for rows.Next() {
		var raw []byte
		var key inventoryOrigin
		if err = rows.Scan(&raw); err == nil {
			err = json.Unmarshal(raw, &key)
		}
		if err != nil {
			rows.Close()
			return batch, err
		}
		origins[key] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return batch, err
	}
	keys := make([]inventoryOrigin, 0, len(origins))
	for key := range origins {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].json() < keys[j].json() })
	// Counts are adjusted by replaced contributions; extrema use ordered indexes.
	// No ordinary event reads an endpoint's complete historical evidence.
	changes := map[inventoryRelation][2]int64{}
	now := time.Now().UTC()
	for _, key := range keys {
		facts, due, e := loadInventoryOrigin(ctx, tx, id, key, now)
		if e != nil {
			return batch, e
		}
		if e = replaceInventoryContributions(ctx, tx, id, key, facts, changes); e != nil {
			return batch, e
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM endpoint_inventory_projection_timers WHERE endpoint_id=$1 AND origin_key=$2::jsonb`, id, key.json()); e != nil {
			return batch, e
		}
		if !due.IsZero() {
			if _, e = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_projection_timers VALUES($1,$2::jsonb,$3)`, id, key.json(), due); e != nil {
				return batch, e
			}
		}
	}
	for key, delta := range changes {
		if err = refreshInventoryRelation(ctx, tx, id, key, delta); err != nil {
			return batch, err
		}
	}
	return batch, refreshInventoryLookupFromCompact(ctx, tx, id)
}

func loadInventoryOrigin(ctx context.Context, tx *sql.Tx, id string, key inventoryOrigin, now time.Time) ([]inventoryContribution, time.Time, error) {
	facts := []inventoryContribution{}
	var due time.Time
	next := func(at time.Time) {
		if at.After(now) && (due.IsZero() || at.Before(due)) {
			due = at
		}
	}
	if key[0] == "observation" {
		rows, err := tx.QueryContext(ctx, `SELECT kind,value,source,first_seen,observed_at,confidence,event_id FROM endpoint_inventory_observation_facts WHERE endpoint_id=$1 AND source=$2 AND event_id=$3`, id, key[1], key[2])
		if err != nil {
			return nil, due, err
		}
		defer rows.Close()
		latest := map[inventoryRelation]inventoryContribution{}
		for rows.Next() {
			var f inventoryContribution
			if err = rows.Scan(&f.Kind, &f.Value, &f.Source, &f.First, &f.Last, &f.Confidence, &f.Event); err != nil {
				return nil, due, err
			}
			if f.Last.After(now) {
				next(f.Last)
				continue
			}
			old, ok := latest[f.inventoryRelation]
			if !ok || f.Last.After(old.Last) || (f.Last.Equal(old.Last) && f.Confidence > old.Confidence) {
				latest[f.inventoryRelation] = f
			}
		}
		if err = rows.Err(); err != nil {
			return nil, due, err
		}
		for _, f := range latest {
			facts = append(facts, f)
		}
		return facts, due, nil
	}
	if key[0] != "session" {
		return nil, due, fmt.Errorf("unknown inventory origin")
	}
	// Reconcile the business session key, including removal and IP corrections.
	if _, err := tx.ExecContext(ctx, `DELETE FROM endpoint_inventory_sessions WHERE endpoint_id=$1 AND source=$2 AND session_id=$3`, id, key[1], key[2]); err != nil {
		return nil, due, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT jsonb_build_object('session_id',session_id,'source',source,'account_id',account_id,'ip',host(ip),'access_id',coalesce(access_id,''),'started_at',started_at,'ended_at',ended_at,'last_confirmed_at',policy_metadata->>'last_confirmed_at','identity_confidence',identity_confidence,'campus_id',campus_id,'department',department,'person_type',person_type,'ssid',ssid,'vlan',vlan,'ap',ap,'nas_ip',nas_ip),started_at,true FROM account_sessions WHERE endpoint_id=$1 AND source=$2 AND session_id=$3
 UNION ALL SELECT document,confirmed_at,false FROM account_identity_session_projection WHERE document->>'endpoint_id'=$1 AND source=$2 AND session_id=$3`, id, key[1], key[2])
	if err != nil {
		return nil, due, err
	}
	type sessionRow struct {
		v        AccountSession
		at       time.Time
		explicit bool
	}
	sessions := []sessionRow{}
	for rows.Next() {
		var raw []byte
		var r sessionRow
		if err = rows.Scan(&raw, &r.at, &r.explicit); err == nil {
			err = json.Unmarshal(raw, &r.v)
		}
		if err != nil {
			rows.Close()
			return nil, due, err
		}
		sessions = append(sessions, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, due, err
	}
	for _, r := range sessions {
		v := r.v
		ip := net.ParseIP(v.IP)
		if ip == nil || ip.IsUnspecified() {
			continue
		}
		start, e := time.Parse(time.RFC3339Nano, v.StartedAt)
		if e != nil {
			return nil, due, fmt.Errorf("invalid inventory session start: %w", e)
		}
		next(start)
		ended, _ := time.Parse(time.RFC3339Nano, v.EndedAt)
		next(ended)
		confirmed, _ := time.Parse(time.RFC3339Nano, v.LastConfirmedAt)
		next(confirmed)
		if start.After(now) {
			continue
		}
		if v.LastConfirmedAt == "" && !r.explicit {
			v.LastConfirmedAt = r.at.UTC().Format(time.RFC3339Nano)
			next(r.at)
		}
		// Snapshot disappearance is not a fresh confirmation of the old occupant.
		if !r.explicit {
			v.EndedAt = ""
		}
		stamp := associationSessionTime(v, now)
		if stamp == "" {
			continue
		}
		last, _ := time.Parse(time.RFC3339Nano, stamp)
		dimensions, _ := json.Marshal(map[string]string{"campus_id": v.CampusID, "department": v.Department, "person_type": v.PersonType, "ssid": v.SSID, "vlan": v.VLAN, "ap": v.AP, "nas_ip": v.NASIP})
		var end any
		if !ended.IsZero() {
			end = ended
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_sessions(endpoint_id,source,session_id,ip,account_id,started_at,ended_at,confirmed_at,access_id,dimensions,confidence,interval_explicit) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
 ON CONFLICT(endpoint_id,source,session_id,ip) DO UPDATE SET account_id=EXCLUDED.account_id,started_at=EXCLUDED.started_at,ended_at=EXCLUDED.ended_at,confirmed_at=EXCLUDED.confirmed_at,access_id=EXCLUDED.access_id,dimensions=EXCLUDED.dimensions,confidence=EXCLUDED.confidence,interval_explicit=EXCLUDED.interval_explicit WHERE EXCLUDED.interval_explicit OR NOT endpoint_inventory_sessions.interval_explicit`, id, key[1], key[2], ip.String(), v.AccountID, start, end, last, v.AccessID, dimensions, v.IdentityConfidence, r.explicit)
		if err != nil {
			return nil, due, err
		}
	}
	rows, err = tx.QueryContext(ctx, `SELECT kind,value,source,min(CASE WHEN interval_explicit THEN started_at ELSE confirmed_at END),max(confirmed_at),max(confidence) FROM endpoint_inventory_sessions CROSS JOIN LATERAL(VALUES('account',account_id),('ip',host(ip)),('access',access_id)) v(kind,value) WHERE endpoint_id=$1 AND source=$2 AND session_id=$3 AND value<>'' GROUP BY kind,value,source`, id, key[1], key[2])
	if err != nil {
		return nil, due, err
	}
	defer rows.Close()
	for rows.Next() {
		f := inventoryContribution{Session: true}
		if err = rows.Scan(&f.Kind, &f.Value, &f.Source, &f.First, &f.Last, &f.Confidence); err != nil {
			return nil, due, err
		}
		facts = append(facts, f)
	}
	return facts, due, rows.Err()
}

func replaceInventoryContributions(ctx context.Context, tx *sql.Tx, id string, key inventoryOrigin, facts []inventoryContribution, changes map[inventoryRelation][2]int64) error {
	rows, err := tx.QueryContext(ctx, `SELECT kind,value,source,first_seen,last_seen,confidence,event_id,is_session FROM endpoint_inventory_contributions WHERE endpoint_id=$1 AND origin_key=$2::jsonb`, id, key.json())
	if err != nil {
		return err
	}
	old := map[inventoryRelation]inventoryContribution{}
	for rows.Next() {
		var f inventoryContribution
		if err = rows.Scan(&f.Kind, &f.Value, &f.Source, &f.First, &f.Last, &f.Confidence, &f.Event, &f.Session); err != nil {
			rows.Close()
			return err
		}
		old[f.inventoryRelation] = f
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	incoming := map[inventoryRelation]inventoryContribution{}
	for _, f := range facts {
		incoming[f.inventoryRelation] = f
	}
	unchanged := len(old) == len(incoming)
	for relation, next := range incoming {
		previous, exists := old[relation]
		if !exists || !previous.First.Equal(next.First) || !previous.Last.Equal(next.Last) || previous.Confidence != next.Confidence || previous.Event != next.Event || previous.Session != next.Session {
			unchanged = false
			break
		}
	}
	if unchanged {
		return nil
	}
	for _, f := range old {
		d := changes[f.inventoryRelation]
		if f.Session {
			d[1]--
		} else {
			d[0]--
		}
		changes[f.inventoryRelation] = d
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM endpoint_inventory_contributions WHERE endpoint_id=$1 AND origin_key=$2::jsonb`, id, key.json()); err != nil {
		return err
	}
	for _, f := range facts {
		_, err = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_contributions VALUES($1,$2::jsonb,$3,$4,$5,$6,$7,$8,$9,$10)`, id, key.json(), f.Kind, f.Value, f.Source, f.First, f.Last, f.Confidence, f.Event, f.Session)
		if err != nil {
			return err
		}
		d := changes[f.inventoryRelation]
		if f.Session {
			d[1]++
		} else {
			d[0]++
		}
		changes[f.inventoryRelation] = d
	}
	return nil
}

func refreshInventoryRelation(ctx context.Context, tx *sql.Tx, id string, key inventoryRelation, delta [2]int64) error {
	args := []any{id, key.Kind, key.Value, key.Source}
	var first, last time.Time
	var confidence float64
	var event string
	err := tx.QueryRowContext(ctx, `SELECT newest.last_seen,newest.event_id,stats.first_seen,stats.confidence
 FROM (SELECT last_seen,event_id FROM endpoint_inventory_contributions WHERE endpoint_id=$1 AND kind=$2 AND value=$3 AND source=$4 ORDER BY last_seen DESC,event_id DESC LIMIT 1) newest
 CROSS JOIN (SELECT min(first_seen) first_seen,max(confidence) confidence FROM endpoint_inventory_contributions WHERE endpoint_id=$1 AND kind=$2 AND value=$3 AND source=$4) stats`, args[0], args[1], args[2], args[3], args[0], args[1], args[2], args[3]).Scan(&last, &event, &first, &confidence)
	if err == sql.ErrNoRows {
		_, err = tx.ExecContext(ctx, `DELETE FROM endpoint_inventory_associations WHERE endpoint_id=$1 AND kind=$2 AND value=$3 AND source=$4`, args...)
	} else if err == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_associations(endpoint_id,kind,value,source,first_seen,last_seen,observation_count,session_count,confidence,event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(endpoint_id,kind,value,source) DO UPDATE SET first_seen=EXCLUDED.first_seen,last_seen=EXCLUDED.last_seen,observation_count=endpoint_inventory_associations.observation_count+EXCLUDED.observation_count,session_count=endpoint_inventory_associations.session_count+EXCLUDED.session_count,confidence=EXCLUDED.confidence,event_id=EXCLUDED.event_id,updated_at=now()`, id, key.Kind, key.Value, key.Source, first, last, delta[0], delta[1], confidence, event)
	}
	if err != nil {
		return err
	}
	if key.Kind == "ip" {
		if _, err = tx.ExecContext(ctx, `DELETE FROM endpoint_inventory_ip_points WHERE endpoint_id=$1 AND ip=$2::inet AND source=$3`, id, key.Value, key.Source); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_ip_points SELECT endpoint_id,value::inet,last_seen,source FROM endpoint_inventory_contributions WHERE endpoint_id=$1 AND kind='ip' AND value=$2 AND source=$3 AND NOT is_session ORDER BY last_seen DESC LIMIT 1`, id, key.Value, key.Source)
	}
	return err
}

func seedInventoryContributionsTx(ctx context.Context, tx *sql.Tx, id string) error {
	// This is initial backfill only; normal deltas never invoke this path.
	for _, table := range []string{"endpoint_inventory_contributions", "endpoint_inventory_projection_timers"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE endpoint_id=$1`, id); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_contributions
 SELECT DISTINCT ON(kind,value,source,event_id) $1,jsonb_build_array('observation',source,event_id),kind,value,source,first_seen,observed_at,confidence,event_id,false
 FROM endpoint_inventory_observation_facts WHERE endpoint_id=$1 AND observed_at<=now() ORDER BY kind,value,source,event_id,observed_at DESC,confidence DESC`, id)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_contributions
 SELECT $1,jsonb_build_array('session',source,session_id),kind,value,source,min(CASE WHEN interval_explicit THEN started_at ELSE confirmed_at END),max(confirmed_at),max(confidence),'',true
 FROM endpoint_inventory_sessions CROSS JOIN LATERAL(VALUES('account',account_id),('ip',host(ip)),('access',access_id)) v(kind,value) WHERE endpoint_id=$1 AND value<>'' AND confirmed_at<=now() GROUP BY source,session_id,kind,value`, id)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_projection_timers
 SELECT $1,origin_key,min(at) FROM (
 SELECT jsonb_build_array('observation',source,event_id) origin_key,observed_at at FROM endpoint_inventory_observation_facts WHERE endpoint_id=$1
 UNION ALL SELECT jsonb_build_array('session',source,session_id),v.at FROM account_sessions CROSS JOIN LATERAL(VALUES(started_at),(ended_at),(nullif(policy_metadata->>'last_confirmed_at','')::timestamptz)) v(at) WHERE endpoint_id=$1
 UNION ALL SELECT jsonb_build_array('session',source,session_id),v.at FROM account_identity_session_projection CROSS JOIN LATERAL(VALUES(nullif(document->>'started_at','')::timestamptz),(nullif(document->>'ended_at','')::timestamptz),(coalesce(nullif(document->>'last_confirmed_at','')::timestamptz,confirmed_at))) v(at) WHERE document->>'endpoint_id'=$1
 ) f WHERE at>now() GROUP BY origin_key`, id)
	return err
}

func refreshInventoryLookupFromCompact(ctx context.Context, tx *sql.Tx, id string) error {
	var raw []byte
	var mac, name, ownerAccount, ownerName, owner string
	var seen sql.NullTime
	var manual bool
	err := tx.QueryRowContext(ctx, `SELECT coalesce(r.list_item,'{}'),coalesce(e.primary_mac,''),coalesce(nullif(n.value,''),r.device_name,''),coalesce(e.owner_account,''),coalesce(e.owner_name,''),concat_ws(' ',e.owner_account,e.owner_name,e.owner_department,e.asset_tag),e.last_seen,coalesce(n.value,'')<>'' FROM endpoint_entities e LEFT JOIN endpoint_recognition_summary r USING(endpoint_id) LEFT JOIN device_name_notes n USING(endpoint_id) WHERE e.endpoint_id=$1`, id).Scan(&raw, &mac, &name, &ownerAccount, &ownerName, &owner, &seen, &manual)
	if err == sql.ErrNoRows {
		for _, table := range []string{"endpoint_inventory_lookup", "endpoint_inventory_accounts", "endpoint_inventory_associations", "endpoint_inventory_ip_points", "endpoint_inventory_sessions", "endpoint_inventory_contributions", "endpoint_inventory_projection_timers"} {
			if _, e := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE endpoint_id=$1`, id); e != nil {
				return e
			}
		}
		return nil
	}
	if err != nil {
		return err
	}
	var item EndpointDeviceInventory
	if err = json.Unmarshal(raw, &item); err != nil {
		return err
	}
	item.EndpointID, item.PrimaryMAC, item.OwnerAccount, item.OwnerName = id, mac, ownerAccount, ownerName
	if name == "" {
		item.DeviceName = nil
	} else {
		if item.DeviceName == nil {
			item.DeviceName = &DeviceName{}
		}
		item.DeviceName.Value = name
		if manual {
			item.DeviceName.Manual = true
			item.DeviceName.Source = "manual_note"
			item.DeviceName.Status = "current"
		}
	}
	profile := EndpointIdentityProfile{}
	// Only tied latest candidates are needed, not all historical relationships.
	rows, err := tx.QueryContext(ctx, `SELECT a.kind,a.value,a.last_seen FROM (VALUES('account'),('access'),('ip')) k(kind) CROSS JOIN LATERAL(SELECT max(last_seen) at FROM endpoint_inventory_associations WHERE endpoint_id=$1 AND kind=k.kind) m JOIN endpoint_inventory_associations a ON a.endpoint_id=$1 AND a.kind=k.kind AND a.last_seen=m.at`, id)
	if err != nil {
		return err
	}
	for rows.Next() {
		var kind, value string
		var at time.Time
		if err = rows.Scan(&kind, &value, &at); err != nil {
			rows.Close()
			return err
		}
		stamp := at.UTC().Format(time.RFC3339Nano)
		switch kind {
		case "account":
			profile.IPHistory = append(profile.IPHistory, IdentityIPMACHistory{AccountID: value, LastSeen: stamp})
		case "ip":
			profile.IPHistory = append(profile.IPHistory, IdentityIPMACHistory{IP: value, LastSeen: stamp})
		case "access":
			profile.AccessHistory = append(profile.AccessHistory, IdentityAccessHistory{AccessID: value, LastSeen: stamp})
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	applyLatestInventoryAssociations(&item, profile, now)
	latest := latestInventoryAssociations(profile, now)
	if seen.Valid && seen.Time.After(now) {
		seen = sql.NullTime{}
	}
	for _, at := range []time.Time{latest.AccountAt, latest.IPAt, latest.AccessAt} {
		if !at.IsZero() && (!seen.Valid || at.After(seen.Time)) {
			seen = sql.NullTime{Time: at, Valid: true}
		}
	}
	item.LastSeen = ""
	if seen.Valid {
		item.LastSeen = seen.Time.UTC().Format(time.RFC3339Nano)
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM endpoint_inventory_accounts WHERE endpoint_id=$1 AND NOT(account_id=ANY($2::text[]))`, id, item.CurrentAccountCandidates); err != nil {
		return err
	}
	for _, account := range item.CurrentAccountCandidates {
		if _, err = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_accounts VALUES($1,$2,$3) ON CONFLICT(endpoint_id,account_id) DO UPDATE SET observed_at=EXCLUDED.observed_at WHERE endpoint_inventory_accounts.observed_at IS DISTINCT FROM EXCLUDED.observed_at`, id, account, item.CurrentAccountObservedAt); err != nil {
			return err
		}
	}
	key := strings.ToLower(strings.NewReplacer(":", "", "-", "", ".", "").Replace(mac))
	text := strings.ToLower(strings.Join([]string{id, mac, key, item.CurrentIP, name, strings.Join(item.CurrentAccountCandidates, " "), item.CurrentAccessID, owner, item.Brand, item.Model, item.OSFamily, item.DeviceType}, " "))
	compact, err := json.Marshal(ProjectDeviceInventoryListItem(item))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_lookup(endpoint_id,list_item,last_seen,device_name,mac_key,current_ip,search_text) VALUES($1,$2,$3,$4,$5,NULLIF($6,'')::inet,$7) ON CONFLICT(endpoint_id) DO UPDATE SET list_item=EXCLUDED.list_item,last_seen=EXCLUDED.last_seen,device_name=EXCLUDED.device_name,mac_key=EXCLUDED.mac_key,current_ip=EXCLUDED.current_ip,search_text=EXCLUDED.search_text,updated_at=now() WHERE (endpoint_inventory_lookup.list_item,endpoint_inventory_lookup.last_seen,endpoint_inventory_lookup.device_name,endpoint_inventory_lookup.mac_key,endpoint_inventory_lookup.current_ip,endpoint_inventory_lookup.search_text) IS DISTINCT FROM (EXCLUDED.list_item,EXCLUDED.last_seen,EXCLUDED.device_name,EXCLUDED.mac_key,EXCLUDED.current_ip,EXCLUDED.search_text)`, id, compact, inventoryNullTimeValue(seen), name, key, item.CurrentIP, text)
	return err
}
func inventoryNullTimeValue(value sql.NullTime) any {
	if !value.Valid {
		return nil
	}
	return value.Time
}

// Initialization may overlap live source changes. Keep aggregate counts and
// extrema aligned with the contribution records that subsequent deltas replace.
func reconcileInitialInventoryContributions(ctx context.Context, tx *sql.Tx, id string) error {
	for _, table := range []string{"endpoint_inventory_associations", "endpoint_inventory_ip_points"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE endpoint_id=$1`, id); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_associations(endpoint_id,kind,value,source,first_seen,last_seen,observation_count,session_count,confidence,event_id)
 SELECT endpoint_id,kind,value,source,min(first_seen),max(last_seen),count(*) FILTER(WHERE NOT is_session),count(*) FILTER(WHERE is_session),max(confidence),(array_agg(event_id ORDER BY last_seen DESC,event_id DESC))[1]
 FROM endpoint_inventory_contributions WHERE endpoint_id=$1 GROUP BY endpoint_id,kind,value,source`, id)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_ip_points SELECT endpoint_id,value::inet,max(last_seen),source FROM endpoint_inventory_contributions WHERE endpoint_id=$1 AND kind='ip' AND NOT is_session GROUP BY endpoint_id,value,source`, id)
	if err != nil {
		return err
	}
	return refreshInventoryLookupFromCompact(ctx, tx, id)
}

func inventoryInitialDeltaBatch(ctx context.Context, tx *sql.Tx, id string) (inventoryDeltaBatch, error) {
	batch := inventoryDeltaBatch{}
	rows, err := tx.QueryContext(ctx, `SELECT delta_id FROM endpoint_inventory_projection_deltas WHERE endpoint_id=$1 ORDER BY delta_id LIMIT 500`, id)
	if err != nil {
		return batch, err
	}
	defer rows.Close()
	for rows.Next() {
		var v int64
		if err = rows.Scan(&v); err != nil {
			return batch, err
		}
		batch.IDs = append(batch.IDs, v)
		batch.Cursor = v
	}
	return batch, rows.Err()
}
