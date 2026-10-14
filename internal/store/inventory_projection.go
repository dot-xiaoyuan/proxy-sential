package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// One background worker. No list request performs backfill or falls back to facts.
// RunDeviceInventoryProjection runs a separately quota-controlled worker lane.
func (s *DBStore) RunDeviceInventoryProjection(ctx context.Context, backfill bool) {
	lane := "realtime"
	if backfill {
		lane = "backfill"
	}
	// Each concurrent endpoint may hold a claim connection and a transaction connection.
	poolSize := 2*inventoryRealtimeWorkers() + 2
	if backfill {
		poolSize = 12
	}
	s.pg.db.SetMaxOpenConns(poolSize)
	s.pg.db.SetMaxIdleConns(poolSize)
	for ctx.Err() == nil {
		conn, err := s.pg.db.Conn(ctx)
		if err == nil {
			var acquired bool
			err = conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,7137103))`, "endpoint-inventory-"+lane).Scan(&acquired)
			if err == nil && acquired {
				s.runDeviceInventoryProjectionWork(ctx, conn, backfill)
				release, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
				_, err = conn.ExecContext(release, `SELECT pg_advisory_unlock(hashtextextended($1,7137103))`, "endpoint-inventory-"+lane)
				cancel()
				if err != nil {
					_ = conn.Raw(func(any) error { return driver.ErrBadConn })
				}
			}
			conn.Close()
		}
		if ctx.Err() != nil {
			return
		}
		timer := time.NewTimer(3 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (s *DBStore) runDeviceInventoryProjectionWork(ctx context.Context, guard *sql.Conn, backfill bool) {
	ctx, stop := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { stop(); workers.Wait() }()
	if backfill {
		for n := 0; n < inventoryBackfillWorkers(); n++ {
			workers.Add(1)
			go func() { defer workers.Done(); s.runInventoryBackfillEndpoints(ctx) }()
		}
	}
	for ctx.Err() == nil {
		work, cancel := context.WithTimeout(ctx, 30*time.Second)
		if err := guard.PingContext(work); err != nil {
			cancel()
			return
		}
		var err error
		if backfill {
			err = s.pg.bootstrapInventorySummaries(work, 2000)
			if err == nil {
				var available bool
				err = s.pg.db.QueryRowContext(work, `SELECT summary_complete FROM endpoint_inventory_projection_state WHERE singleton`).Scan(&available)
				if err == nil && !available {
					cancel()
					continue
				}
			}
			if err == nil {
				_, err = s.pg.backfillInventoryBatch(work, 2000)
			}
			if err == nil {
				err = s.pg.backfillInventorySnapshots(work)
			}
		} else {
			_, err = s.enqueueExpiredInventoryJobs(work, 1000)
		}
		cancel()
		// Each endpoint has its own budget. A contended snapshot or seed batch
		// must not consume every endpoint's processing time or starve that lane.
		//
		// The realtime lane used to run these sequentially, so one endpoint at a time set
		// the ceiling: the field measured ~0.67 jobs/s while roughly 133 real changes/min
		// arrived, and the backlog grew even though no single statement took 300 ms — the
		// cost is spread over many small statements. Endpoints are independent and the
		// claim uses FOR UPDATE SKIP LOCKED, so the work parallelises across workers.
		// PROXY_SENTINEL_INVENTORY_REALTIME_WORKERS=1 restores the sequential shape.
		if !backfill {
			workers := inventoryRealtimeWorkers()
			var running sync.WaitGroup
			var firstErr error
			var errMu sync.Mutex
			for w := 0; w < workers; w++ {
				running.Add(1)
				go func() {
					defer running.Done()
					for n := 0; n < 25; n++ {
						item, stop := context.WithTimeout(ctx, 30*time.Second)
						done, itemErr := s.pg.materializeNextInventoryLane(item, "realtime")
						stop()
						if itemErr != nil {
							errMu.Lock()
							if firstErr == nil {
								firstErr = itemErr
							}
							errMu.Unlock()
							return
						}
						if !done {
							return
						}
					}
				}()
			}
			running.Wait()
			if firstErr != nil {
				err = firstErr
			}
		}
		work, cancel = context.WithTimeout(ctx, 30*time.Second)
		if backfill {
			if _, snapshotErr := s.pg.projectInventorySnapshotBatch(work); snapshotErr != nil {
				err = snapshotErr
			}
		}
		if err == nil {
			_, err = s.pg.db.ExecContext(work, `UPDATE endpoint_inventory_projection_state SET ready=true,updated_at=now() WHERE backfill_complete AND snapshot_backfill_complete AND NOT ready AND NOT EXISTS(SELECT 1 FROM endpoint_inventory_projection_jobs WHERE NOT contributions_ready LIMIT 1) AND NOT EXISTS(SELECT 1 FROM endpoint_inventory_snapshot_jobs WHERE NOT processed LIMIT 1)`)
		}
		if err == nil {
			_, err = s.pg.db.ExecContext(work, `UPDATE endpoint_inventory_projection_state SET last_error='' WHERE last_error<>'' AND NOT EXISTS(SELECT 1 FROM endpoint_inventory_projection_jobs WHERE processed_generation<dirty_generation AND last_error<>'') AND NOT EXISTS(SELECT 1 FROM endpoint_inventory_snapshot_jobs WHERE NOT processed)`)
		}
		cancel()
		if err != nil && ctx.Err() == nil {
			// Never log the account/query, raw payload or endpoint ID.
			fmt.Fprintf(os.Stderr, "inventory projection batch failed lane=%s cause=%s\n", map[bool]string{true: "backfill", false: "realtime"}[backfill], inventoryProjectionErrorCode(err))
			status, cancel := context.WithTimeout(ctx, 2*time.Second)
			stateError := "projection_failed"
			if errors.Is(err, ErrInventoryProjectionRepairRequired) {
				stateError = "projection_repair_required"
			}
			_, _ = s.pg.db.ExecContext(status, `UPDATE endpoint_inventory_projection_state SET last_error=$1,updated_at=now()`, stateError)
			cancel()
		}
		delay := 100 * time.Millisecond
		if backfill {
			delay = inventoryBackfillDelay()
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// Bound initial endpoint work separately from snapshot parsing and realtime.
func (s *DBStore) runInventoryBackfillEndpoints(ctx context.Context) {
	for ctx.Err() == nil {
		work, cancel := context.WithTimeout(ctx, 90*time.Second)
		done, err := s.pg.materializeNextInventoryLane(work, "backfill")
		cancel()
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "inventory endpoint backfill failed cause=%s\n", inventoryProjectionErrorCode(err))
		}
		delay := inventoryBackfillDelay()
		if !done || err != nil || delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}
}

// Error codes identify database contention without exposing fact payloads or IDs.
func inventoryProjectionErrorCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return "sqlstate:" + pgErr.Code
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, ErrInventoryProjectionRepairRequired) {
		return "repair_required"
	}
	return "processing_error"
}

// enqueueExpiredInventoryJobs gives time based session expiry its own bounded
// wake-up path. It advances a per-endpoint watermark so an already handled
// expiry cannot cause an unbounded stream of duplicate projection jobs.
func (s *DBStore) enqueueExpiredInventoryJobs(ctx context.Context, limit int) (int64, error) {
	if limit < 1 || limit > 5000 {
		limit = 1000
	}
	result, err := s.pg.db.ExecContext(ctx, `WITH due AS (
 SELECT t.endpoint_id,min(t.due_at) at FROM endpoint_inventory_projection_timers t
 JOIN endpoint_inventory_projection_jobs j USING(endpoint_id)
 WHERE t.due_at<=now() AND j.processed_generation=j.dirty_generation
 GROUP BY t.endpoint_id ORDER BY min(t.due_at),t.endpoint_id LIMIT $1
 ) UPDATE endpoint_inventory_projection_jobs j
 SET dirty_generation=j.dirty_generation+1,not_before=now(),pending_since=coalesce(j.pending_since,due.at),updated_at=now()
 FROM due WHERE j.endpoint_id=due.endpoint_id`, limit)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *PostgresStore) backfillInventoryBatch(ctx context.Context, limit int) (bool, error) {
	if limit < 1 || limit > 2000 {
		limit = 2000
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var cursor string
	var complete bool
	if err = tx.QueryRowContext(ctx, `SELECT cursor,backfill_complete FROM endpoint_inventory_projection_state WHERE singleton FOR UPDATE`).Scan(&cursor, &complete); err != nil {
		return false, err
	}
	if complete {
		return false, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT endpoint_id FROM endpoint_entities WHERE endpoint_id>$1 ORDER BY endpoint_id LIMIT $2`, cursor, limit)
	if err != nil {
		return false, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return false, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return false, err
	}
	if len(ids) > 0 {
		if _, err = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_projection_jobs(endpoint_id,pending_since) SELECT id,clock_timestamp() FROM unnest($1::text[]) ids(id) WHERE NOT EXISTS(SELECT 1 FROM endpoint_inventory_projection_jobs j WHERE j.endpoint_id=ids.id) ON CONFLICT DO NOTHING`, ids); err != nil {
			return false, err
		}
		cursor = ids[len(ids)-1]
	}
	if _, err = tx.ExecContext(ctx, `UPDATE endpoint_inventory_projection_state SET cursor=$1,backfill_complete=$2,updated_at=now() WHERE singleton`, cursor, len(ids) < limit); err != nil {
		return false, err
	}
	return len(ids) > 0, tx.Commit()
}

// Heavy projection work does not hold the source notification row lock. A lease
// and generation fence make facts and consumed progress commit consistently.
func (s *PostgresStore) materializeNextInventory(ctx context.Context) (bool, error) {
	return s.materializeNextInventoryLane(ctx, "all")
}

func (s *PostgresStore) materializeNextInventoryLane(ctx context.Context, lane string) (bool, error) {
	var id string
	var generation, processedGeneration int64
	var contributionsReady bool
	owner := appToken()
	err := s.db.QueryRowContext(ctx, `WITH picked AS(SELECT endpoint_id FROM endpoint_inventory_projection_jobs WHERE processed_generation<dirty_generation AND not_before<=now() AND lease_until<now()
 AND ($2='all' OR ($2='backfill' AND NOT contributions_ready) OR ($2='realtime' AND (contributions_ready OR (SELECT ready FROM endpoint_inventory_projection_state WHERE singleton)))) ORDER BY (last_error<>''),(processed_generation>0) DESC,coalesce(pending_since,updated_at),endpoint_id FOR UPDATE SKIP LOCKED LIMIT 1)
		UPDATE endpoint_inventory_projection_jobs j SET lease_owner=$1,lease_until=now()+CASE WHEN $2='backfill' THEN interval '2 minutes' ELSE interval '1 minute' END FROM picked p WHERE j.endpoint_id=p.endpoint_id RETURNING j.endpoint_id,j.dirty_generation,j.processed_generation,j.contributions_ready`, owner, lane).Scan(&id, &generation, &processedGeneration, &contributionsReady)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() {
		tx.Rollback()
		release, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_, _ = s.db.ExecContext(release, `UPDATE endpoint_inventory_projection_jobs SET lease_owner='',lease_until='epoch' WHERE endpoint_id=$1 AND lease_owner=$2`, id, owner)
	}()
	var batch inventoryDeltaBatch
	initial := !contributionsReady
	if !initial {
		batch, err = s.materializeInventoryDeltaTx(ctx, tx, id)
	} else {
		// Capture exact committed notifications before reading facts. Notifications
		// arriving during initialization stay pending, including sequence gaps.
		batch, err = inventoryInitialDeltaBatch(ctx, tx, id)
		if err == nil {
			err = initializeInventorySessions(ctx, tx, id)
		}
		if err == nil {
			err = seedInventoryContributionsTx(ctx, tx, id)
		}
		if err == nil {
			err = reconcileInitialInventoryContributions(ctx, tx, id)
		}
	}
	if err != nil {
		tx.Rollback()
		failure, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		repair := errors.Is(err, ErrInventoryProjectionRepairRequired)
		errState, retryAfter := "projection_failed", "30 seconds"
		if repair {
			errState, retryAfter = "projection_repair_required", "5 minutes"
		}
		_, _ = s.db.ExecContext(failure, `UPDATE endpoint_inventory_projection_jobs SET last_error=$3,not_before=now()+$4::interval WHERE endpoint_id=$1 AND lease_owner=$2`, id, owner, errState, retryAfter)
		stateErr := errState
		_, _ = s.db.ExecContext(failure, `UPDATE endpoint_inventory_projection_state SET last_error=$1,updated_at=now() WHERE singleton`, stateErr)
		return false, err
	}
	// Lock notifications only while publishing. Initial facts can publish even
	// if new work arrived: derived rows match the stored contributions and only
	// captured delta IDs are acknowledged. New changes remain pending, so a hot
	// endpoint does not have to restart its entire history on every observation.
	result, err := tx.ExecContext(ctx, `UPDATE endpoint_inventory_projection_jobs SET last_error='' WHERE endpoint_id=$1 AND ($4 OR dirty_generation=$2) AND lease_owner=$3 AND lease_until>clock_timestamp()`, id, generation, owner, initial)
	if err != nil {
		return false, err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return true, nil
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM endpoint_inventory_projection_deltas WHERE endpoint_id=$1 AND delta_id=ANY($2::bigint[])`, id, batch.IDs)
	if err != nil {
		return false, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE endpoint_inventory_projection_jobs SET
 processed_generation=CASE WHEN EXISTS(SELECT 1 FROM endpoint_inventory_projection_deltas WHERE endpoint_id=$1) OR EXISTS(SELECT 1 FROM endpoint_inventory_projection_timers WHERE endpoint_id=$1 AND due_at<=now()) THEN processed_generation ELSE $2 END,
 pending_since=CASE WHEN EXISTS(SELECT 1 FROM endpoint_inventory_projection_deltas WHERE endpoint_id=$1) OR EXISTS(SELECT 1 FROM endpoint_inventory_projection_timers WHERE endpoint_id=$1 AND due_at<=now()) THEN pending_since ELSE NULL END,
 delta_cursor=greatest(delta_cursor,$3),contributions_ready=true,updated_at=now() WHERE endpoint_id=$1`, id, generation, batch.Cursor)
	if err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	// 单例状态行只承载派生的 last_error 与读取侧 AsOf（inventory_read_state 用它做结果版本），
	// 而任务事实此时已经提交。该更新原先写在任务事务内，行锁必须一直持有到任务提交时的 WAL fsync，
	// 8 路实时加上回填 worker 排队后，实测这条语句耗时 2.2 秒，而其内部的 EXISTS 只要 0.075 毫秒。
	// 改为提交后的独立短事务并关闭同步提交，行锁只持有毫秒级。
	stateCtx, cancelState := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	stateErr := s.writeAdvisoryState(stateCtx, `UPDATE endpoint_inventory_projection_state SET last_error=CASE WHEN EXISTS(SELECT 1 FROM endpoint_inventory_projection_jobs WHERE last_error<>'' AND processed_generation<dirty_generation) THEN 'projection_failed' ELSE '' END,updated_at=now() WHERE singleton`)
	cancelState()
	if stateErr != nil {
		// 任务结果已提交，这里失败只影响派生展示状态，下一个成功任务会立刻重写该行。
		fmt.Fprintf(os.Stderr, "inventory projection state refresh failed cause=%s\n", inventoryProjectionErrorCode(stateErr))
	}
	return true, nil
}

func (s *PostgresStore) materializeInventoryTx(ctx context.Context, tx *sql.Tx, id string) error {
	now := time.Now().UTC()
	// Only list_item, not recognition summary with its complete evidence/history.
	var raw []byte
	var mac, name, owner, ownerAccount, ownerName string
	var manual bool
	var seen sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT coalesce(r.list_item,'{}'),coalesce(e.primary_mac,''),coalesce(nullif(n.value,''),r.device_name,''),concat_ws(' ',e.owner_account,e.owner_name,e.owner_department,e.asset_tag),e.last_seen,coalesce(e.owner_account,''),coalesce(e.owner_name,''),coalesce(n.value,'')<>''
 FROM endpoint_entities e LEFT JOIN endpoint_recognition_summary r USING(endpoint_id) LEFT JOIN device_name_notes n USING(endpoint_id) WHERE e.endpoint_id=$1`, id).Scan(&raw, &mac, &name, &owner, &seen, &ownerAccount, &ownerName, &manual)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	for _, table := range []string{"endpoint_inventory_lookup", "endpoint_inventory_accounts", "endpoint_inventory_associations", "endpoint_inventory_ip_points", "endpoint_inventory_sessions"} {
		if _, e := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE endpoint_id=$1`, id); e != nil {
			return e
		}
	}
	if err == sql.ErrNoRows {
		return nil
	}
	var item EndpointDeviceInventory
	if err = json.Unmarshal(raw, &item); err != nil {
		return err
	}
	item.EndpointID = id
	item.PrimaryMAC = mac
	if seen.Valid && seen.Time.After(now) {
		seen = sql.NullTime{}
	}
	item.LastSeen = ""
	item.OwnerAccount = ownerAccount
	item.OwnerName = ownerName
	if seen.Valid {
		item.LastSeen = seen.Time.UTC().Format(time.RFC3339Nano)
	}
	if name != "" {
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
	if name == "" {
		item.DeviceName = nil
	}
	// DISTINCT event keys deduplicate the same account observation carried by
	// both IP and access facts. Corrections replace aggregates, not increment them.
	_, err = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_associations(endpoint_id,kind,value,source,first_seen,last_seen,observation_count,confidence,event_id)
 SELECT $1,kind,value,source,min(first_seen),max(observed_at),count(*),max(confidence),(array_agg(event_id ORDER BY observed_at DESC,event_id DESC))[1]
 FROM (SELECT DISTINCT ON(kind,value,source,event_id) kind,value,source,first_seen,observed_at,confidence,event_id FROM endpoint_inventory_observation_facts WHERE endpoint_id=$1 AND observed_at<=$2 ORDER BY kind,value,source,event_id,observed_at DESC) f GROUP BY kind,value,source`, id, now)
	if err != nil {
		return err
	}
	// The list only accepts relative windows ending at now: the latest actual
	// past observation per endpoint/IP/source is sufficient, and never fills gaps.
	// Every individual timestamp remains available in endpoint-scoped trace facts.
	_, err = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_ip_points SELECT endpoint_id,ip,max(observed_at),source FROM (
	SELECT endpoint_id,ip,last_seen observed_at,source FROM identity_ip_mac_history WHERE endpoint_id=$1 AND ip IS NOT NULL AND last_seen<=$2
	UNION ALL SELECT endpoint_id,ip,observed_at,source FROM endpoint_inventory_snapshot_facts WHERE endpoint_id=$1 AND ip IS NOT NULL AND observed_at<=$2) f GROUP BY endpoint_id,ip,source`, id, now)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_sessions(endpoint_id,source,session_id,ip,account_id,started_at,ended_at,confirmed_at,access_id,dimensions,confidence)
 SELECT endpoint_id,source,session_id,ip,account_id,started_at,ended_at,greatest(started_at,CASE WHEN ended_at<=$2 THEN ended_at END,CASE WHEN nullif(policy_metadata->>'last_confirmed_at','')::timestamptz<=$2 THEN nullif(policy_metadata->>'last_confirmed_at','')::timestamptz END),coalesce(access_id,''),jsonb_strip_nulls(jsonb_build_object('campus_id',campus_id,'department',department,'person_type',person_type,'ssid',ssid,'vlan',vlan,'ap',ap,'nas_ip',nas_ip))
 ,identity_confidence FROM account_sessions WHERE endpoint_id=$1 AND ip IS NOT NULL AND started_at<=$2`, id, now)
	if err != nil {
		return err
	}
	// Snapshot rows are confirmations, not newly invented historical events.
	rows, err := tx.QueryContext(ctx, `SELECT document,confirmed_at FROM account_identity_session_projection WHERE document->>'endpoint_id'=$1 AND confirmed_at<=$2`, id, now)
	if err != nil {
		return err
	}
	snapshots := []AccountSession{}
	for rows.Next() {
		var doc []byte
		var at time.Time
		if err = rows.Scan(&doc, &at); err != nil {
			rows.Close()
			return err
		}
		var v AccountSession
		if err = json.Unmarshal(doc, &v); err != nil {
			rows.Close()
			return err
		}
		// The projection's confirmed_at may mark disappearance from a complete
		// snapshot. The document retains the actual last observed confirmation.
		if v.LastConfirmedAt == "" {
			v.LastConfirmedAt = at.UTC().Format(time.RFC3339Nano)
		}
		if ended, e := time.Parse(time.RFC3339Nano, v.EndedAt); e == nil && ended.IsZero() {
			v.EndedAt = ""
		}
		snapshots = append(snapshots, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, v := range snapshots {
		ip := net.ParseIP(v.IP)
		if ip == nil {
			continue
		}
		start, err := time.Parse(time.RFC3339Nano, v.StartedAt)
		if err != nil || start.After(now) {
			continue
		}
		dimensions, _ := json.Marshal(map[string]string{"campus_id": v.CampusID, "department": v.Department, "person_type": v.PersonType, "ssid": v.SSID, "vlan": v.VLAN, "ap": v.AP, "nas_ip": v.NASIP})
		_, err = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_sessions VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,false)
		ON CONFLICT(endpoint_id,source,session_id,ip) DO UPDATE SET confirmed_at=greatest(endpoint_inventory_sessions.confirmed_at,EXCLUDED.confirmed_at),dimensions=EXCLUDED.dimensions`, id, v.Source, v.SessionID, ip.String(), v.AccountID, start, recognitionTimestamp(v.EndedAt), v.LastConfirmedAt, v.AccessID, dimensions, v.IdentityConfidence)
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_associations(endpoint_id,kind,value,source,first_seen,last_seen,observation_count,session_count,confidence,event_id)
	SELECT $1,kind,value,source,min(CASE WHEN interval_explicit THEN started_at ELSE confirmed_at END),max(confirmed_at),0,count(DISTINCT session_id),max(confidence),''
	FROM endpoint_inventory_sessions CROSS JOIN LATERAL(VALUES('account',account_id),('ip',host(ip)),('access',access_id)) v(kind,value)
	WHERE endpoint_id=$1 AND value<>'' AND confirmed_at<=$2 GROUP BY kind,value,source
	ON CONFLICT(endpoint_id,kind,value,source) DO UPDATE SET first_seen=least(endpoint_inventory_associations.first_seen,EXCLUDED.first_seen),last_seen=greatest(endpoint_inventory_associations.last_seen,EXCLUDED.last_seen),session_count=EXCLUDED.session_count,confidence=greatest(endpoint_inventory_associations.confidence,EXCLUDED.confidence)`, id, now)
	if err != nil {
		return err
	}
	latestSnapshots := append([]AccountSession{}, snapshots...)
	for i := range latestSnapshots {
		latestSnapshots[i].EndedAt = ""
	}
	profile := EndpointIdentityProfile{Sessions: latestSnapshots}
	rows, err = tx.QueryContext(ctx, `SELECT kind,value,last_seen FROM endpoint_inventory_associations WHERE endpoint_id=$1 UNION ALL
 SELECT 'account',account_id,confirmed_at FROM endpoint_inventory_sessions WHERE endpoint_id=$1 UNION ALL
 SELECT 'access',access_id,confirmed_at FROM endpoint_inventory_sessions WHERE endpoint_id=$1 UNION ALL
 SELECT 'ip',host(ip),confirmed_at FROM endpoint_inventory_sessions WHERE endpoint_id=$1`, id)
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
	item.CurrentIP = ""
	applyLatestInventoryAssociations(&item, profile, now)
	latest := latestInventoryAssociations(profile, now)
	for _, stamp := range []time.Time{latest.AccountAt, latest.IPAt, latest.AccessAt} {
		if !stamp.IsZero() && (!seen.Valid || stamp.After(seen.Time)) {
			seen = sql.NullTime{Time: stamp, Valid: true}
		}
	}
	if seen.Valid {
		item.LastSeen = seen.Time.UTC().Format(time.RFC3339Nano)
	}
	for _, account := range item.CurrentAccountCandidates {
		if _, err = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_accounts VALUES($1,$2,$3)`, id, account, item.CurrentAccountObservedAt); err != nil {
			return err
		}
	}
	key := strings.ToLower(strings.NewReplacer(":", "", "-", "", ".", "").Replace(mac))
	text := strings.ToLower(strings.Join([]string{id, mac, key, item.CurrentIP, name, strings.Join(item.CurrentAccountCandidates, " "), item.CurrentAccessID, owner, item.Brand, item.Model, item.OSFamily, item.DeviceType}, " "))
	raw, err = json.Marshal(ProjectDeviceInventoryListItem(item))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_lookup(endpoint_id,list_item,last_seen,device_name,mac_key,current_ip,search_text) VALUES($1,$2,$3,$4,$5,nullif($6,'')::inet,$7)`, id, raw, seen, name, key, item.CurrentIP, text)
	return err
}

// Initial preparation reads each observation fact set once into contributions.
// Sessions use bounded endpoint lookups; summaries derive only from those
// contributions, so initialization does not aggregate raw history twice.
func initializeInventorySessions(ctx context.Context, tx *sql.Tx, id string) error {
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `DELETE FROM endpoint_inventory_sessions WHERE endpoint_id=$1`, id); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_sessions(endpoint_id,source,session_id,ip,account_id,started_at,ended_at,confirmed_at,access_id,dimensions,confidence)
 SELECT endpoint_id,source,session_id,ip,account_id,started_at,ended_at,greatest(started_at,CASE WHEN ended_at<=$2 THEN ended_at END,CASE WHEN nullif(policy_metadata->>'last_confirmed_at','')::timestamptz<=$2 THEN nullif(policy_metadata->>'last_confirmed_at','')::timestamptz END),coalesce(access_id,''),jsonb_strip_nulls(jsonb_build_object('campus_id',campus_id,'department',department,'person_type',person_type,'ssid',ssid,'vlan',vlan,'ap',ap,'nas_ip',nas_ip))
 ,identity_confidence FROM account_sessions WHERE endpoint_id=$1 AND ip IS NOT NULL AND started_at<=$2`, id, now)
	if err != nil {
		return err
	}
	// Snapshot rows are confirmations, not newly invented historical events.
	rows, err := tx.QueryContext(ctx, `SELECT document,confirmed_at FROM account_identity_session_projection WHERE document->>'endpoint_id'=$1 AND confirmed_at<=$2`, id, now)
	if err != nil {
		return err
	}
	snapshots := []AccountSession{}
	for rows.Next() {
		var doc []byte
		var at time.Time
		if err = rows.Scan(&doc, &at); err != nil {
			rows.Close()
			return err
		}
		var v AccountSession
		if err = json.Unmarshal(doc, &v); err != nil {
			rows.Close()
			return err
		}
		// The projection's confirmed_at may mark disappearance from a complete
		// snapshot. The document retains the actual last observed confirmation.
		if v.LastConfirmedAt == "" {
			v.LastConfirmedAt = at.UTC().Format(time.RFC3339Nano)
		}
		if ended, e := time.Parse(time.RFC3339Nano, v.EndedAt); e == nil && ended.IsZero() {
			v.EndedAt = ""
		}
		snapshots = append(snapshots, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, v := range snapshots {
		ip := net.ParseIP(v.IP)
		if ip == nil {
			continue
		}
		start, err := time.Parse(time.RFC3339Nano, v.StartedAt)
		if err != nil || start.After(now) {
			continue
		}
		dimensions, _ := json.Marshal(map[string]string{"campus_id": v.CampusID, "department": v.Department, "person_type": v.PersonType, "ssid": v.SSID, "vlan": v.VLAN, "ap": v.AP, "nas_ip": v.NASIP})
		_, err = tx.ExecContext(ctx, `INSERT INTO endpoint_inventory_sessions VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,false)
		ON CONFLICT(endpoint_id,source,session_id,ip) DO UPDATE SET confirmed_at=greatest(endpoint_inventory_sessions.confirmed_at,EXCLUDED.confirmed_at),dimensions=EXCLUDED.dimensions`, id, v.Source, v.SessionID, ip.String(), v.AccountID, start, recognitionTimestamp(v.EndedAt), v.LastConfirmedAt, v.AccessID, dimensions, v.IdentityConfidence)
		if err != nil {
			return err
		}
	}
	return nil
}

// Limit database work in the producer; service CPU/I/O weights cannot throttle
// SQL executed inside the separate PostgreSQL container.
// inventoryRealtimeWorkers bounds how many endpoints the realtime lane projects at once.
// Endpoint projections are independent and claimed with FOR UPDATE SKIP LOCKED; the knob
// exists so the field can be measured without a redeploy (1 restores sequential behaviour).
func inventoryRealtimeWorkers() int {
	n, err := strconv.Atoi(os.Getenv("PROXY_SENTINEL_INVENTORY_REALTIME_WORKERS"))
	if err != nil || n < 1 || n > 8 {
		return 2
	}
	return n
}

func inventoryBackfillWorkers() int {
	n, err := strconv.Atoi(os.Getenv("PROXY_SENTINEL_INVENTORY_BACKFILL_WORKERS"))
	if err != nil || n < 1 || n > 4 {
		return 4
	}
	return n
}
func inventoryBackfillDelay() time.Duration {
	n, err := strconv.Atoi(os.Getenv("PROXY_SENTINEL_INVENTORY_BACKFILL_DELAY_MS"))
	if err != nil || n < 100 || n > 60000 {
		return 100 * time.Millisecond
	}
	return time.Duration(n) * time.Millisecond
}
