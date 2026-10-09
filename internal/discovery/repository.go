package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"proxy-sentinel/internal/normalized"
	"time"
)

type Repository struct {
	DB      *sql.DB
	Archive func(context.Context, []normalized.Event) error
}
type Task struct {
	ID              string          `json:"id"`
	SourceID        string          `json:"source_id"`
	Node            string          `json:"node"`
	Kind            string          `json:"kind"`
	Status          string          `json:"status"`
	Version         int             `json:"config_version"`
	Config          json.RawMessage `json:"config"`
	EncryptedSecret string          `json:"-"`
	CreatedAt       time.Time       `json:"created_at"`
	Result          json.RawMessage `json:"result,omitempty"`
	Error           string          `json:"error,omitempty"`
	CancelRequested bool            `json:"cancel_requested"`
}

func (r Repository) SaveSnapshot(ctx context.Context, s Snapshot) error {
	for _, e := range s.Events {
		if _, err := FromEvent(e); err != nil {
			return err
		}
	}
	if r.Archive != nil && len(s.Events) > 0 {
		if err := r.Archive(ctx, s.Events); err != nil {
			return err
		}
	}

	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	raw, _ := json.Marshal(s)
	if _, err = tx.ExecContext(ctx, `INSERT INTO discovery_snapshots(id,source_id,config_version,observed_at,data) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, s.ID, s.SourceID, s.ConfigVersion, s.At, raw); err != nil {
		return err
	}
	for _, e := range s.Events {
		o, err := FromEvent(e)
		if err != nil {
			return err
		}
		if o.Withdrawn && o.Origin == "ssdp" {
			if _, err = tx.ExecContext(ctx, `UPDATE discovery_observations SET valid_until=least(valid_until,$1) WHERE source_id=$2 AND origin='ssdp' AND observed_at<=$1 AND data->>'ip'=$3 AND data->'evidence'->'payload'->>'service_type'=$4 AND data->'evidence'->'payload'->>'usn'=$5 AND coalesce(data->>'site','')=$6 AND coalesce(data->>'domain','')=$7 AND coalesce(data->>'vlan','')=$8`, o.ObservedAt, o.SourceID, o.IP, str(o.Evidence.Payload, "service_type"), str(o.Evidence.Payload, "usn"), o.Site, o.Domain, o.VLAN); err != nil {
				return err
			}
		}
		if o.Withdrawn && o.Origin == "dns_sd" {
			if _, err = tx.ExecContext(ctx, `UPDATE discovery_observations SET valid_until=least(valid_until,$1) WHERE source_id=$2 AND origin='dns_sd' AND observed_at<=$1 AND data->'evidence'->'payload'->>'service_target'=$3 AND data->'evidence'->'payload'->>'service_instance'=$4 AND coalesce(data->>'site','')=$5 AND coalesce(data->>'domain','')=$6 AND coalesce(data->>'vlan','')=$7`, o.ObservedAt, o.SourceID, str(o.Evidence.Payload, "service_target"), str(o.Evidence.Payload, "service_instance"), o.Site, o.Domain, o.VLAN); err != nil {
				return err
			}
		}
		if o.Origin == "neighbor" && o.IP != "" && o.MAC != "" {
			if _, err = tx.ExecContext(ctx, `UPDATE discovery_observations SET valid_until=least(valid_until,$1) WHERE origin='neighbor' AND observed_at<$1 AND source_id=$2 AND data->>'ip'=$3 AND data->>'mac'<>$4 AND coalesce(data->>'site','')=$5 AND coalesce(data->>'domain','')=$6 AND coalesce(data->>'vlan','')=$7 AND coalesce(data->>'vrf','')=$8`, o.ObservedAt, o.SourceID, o.IP, o.MAC, o.Site, o.Domain, o.VLAN, o.VRF); err != nil {
				return err
			}
		}
		b, _ := json.Marshal(o)
		if _, err = tx.ExecContext(ctx, `INSERT INTO discovery_observations(id,device_key,source_id,origin,observed_at,valid_until,withdrawn,data) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`, o.ID, o.Key(), o.SourceID, o.Origin, o.ObservedAt, o.ValidUntil, o.Withdrawn, b); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (r Repository) EnqueuePoll(ctx context.Context, id, source string) error {
	result, err := r.DB.ExecContext(ctx, `INSERT INTO discovery_tasks(id,source_id,node,kind,config_version,config,encrypted_secret) SELECT $1,id,node,'snmp',config_version,config,encrypted_secret FROM discovery_sources WHERE id=$2 ON CONFLICT DO NOTHING`, id, source)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("source missing or already queued")
	}
	return nil
}
func (r Repository) Claim(ctx context.Context, node string) (Task, error) {
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return Task{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "discovery-node:"+node); err != nil {
		return Task{}, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE discovery_tasks SET status=CASE WHEN cancel_requested THEN 'cancelled' WHEN attempt>=3 THEN 'failed' ELSE 'pending' END,error='worker lease expired',lease_until=NULL WHERE node=$1 AND status='running' AND lease_until<now()`, node)
	if err != nil {
		return Task{}, err
	}
	var active int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM discovery_tasks WHERE node=$1 AND status='running'`, node).Scan(&active); err != nil {
		return Task{}, err
	}
	if active >= 3 {
		return Task{}, sql.ErrNoRows
	}
	var t Task
	err = tx.QueryRowContext(ctx, `UPDATE discovery_tasks SET status='running',attempt=attempt+1,started_at=now(),lease_until=now()+interval '2 hours' WHERE id=(SELECT id FROM discovery_tasks WHERE node=$1 AND status='pending' AND NOT cancel_requested AND ((kind='snmp' AND (SELECT count(*) FROM discovery_tasks a WHERE a.node=$1 AND a.status='running' AND a.kind='snmp')<2) OR (kind='scan' AND NOT EXISTS(SELECT 1 FROM discovery_tasks a WHERE a.node=$1 AND a.status='running' AND a.kind='scan'))) ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING id,coalesce(source_id,''),node,kind,status,config_version,config,encrypted_secret,created_at`, node).Scan(&t.ID, &t.SourceID, &t.Node, &t.Kind, &t.Status, &t.Version, &t.Config, &t.EncryptedSecret, &t.CreatedAt)
	if err != nil {
		return t, err
	}
	return t, tx.Commit()
}
func (r Repository) Schedule(ctx context.Context) error {
	_, err := r.DB.ExecContext(ctx, `WITH due AS (SELECT * FROM discovery_sources WHERE enabled AND next_poll<=now() FOR UPDATE SKIP LOCKED), queued AS (INSERT INTO discovery_tasks(id,source_id,node,kind,config_version,config,encrypted_secret) SELECT 'poll-'||md5(id||clock_timestamp()::text),id,node,'snmp',config_version,config,encrypted_secret FROM due ON CONFLICT DO NOTHING RETURNING source_id) UPDATE discovery_sources SET next_poll=now()+make_interval(secs=>greatest(60,coalesce((config->>'interval_seconds')::int,300))) WHERE id IN (SELECT source_id FROM queued)`)
	return err
}
func (r Repository) Finish(ctx context.Context, t Task, s Snapshot, runErr error) error {
	status, message := "complete", ""
	if runErr != nil {
		status = "failed"
		message = "采集失败，请核对连接、权限及协议支持"
	}
	for _, v := range s.Tables {
		if !v.Complete && runErr == nil {
			status = "partial"
		}
	}
	b, _ := json.Marshal(s)
	_, err := r.DB.ExecContext(ctx, `UPDATE discovery_tasks SET status=CASE WHEN cancel_requested THEN 'cancelled' ELSE $2 END,result=$3,error=$4,completed_at=now(),lease_until=NULL,encrypted_secret='' WHERE id=$1 AND status='running'`, t.ID, status, b, message)
	if err == nil && t.Kind == "snmp" {
		if runErr != nil || status == "partial" {
			_, err = r.DB.ExecContext(ctx, `UPDATE discovery_sources SET consecutive_failures=least(consecutive_failures+1,6),next_poll=now()+make_interval(secs=>least(3600,60*(1<<least(consecutive_failures+1,6)))) WHERE id=$1`, t.SourceID)
		} else {
			_, err = r.DB.ExecContext(ctx, `UPDATE discovery_sources SET consecutive_failures=0 WHERE id=$1`, t.SourceID)
		}
	}
	return err
}
func (r Repository) Devices(ctx context.Context, limit, offset int) (map[string]any, error) {
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Latest observation per source/service wins, including withdrawals; no capped evidence aggregation.
	const cte = `WITH latest AS (
 SELECT device_key,observed_at,valid_until,withdrawn,data FROM discovery_observation_latest WHERE observed_at<=now()
 UNION ALL
 SELECT old.device_key,old.observed_at,old.valid_until,old.withdrawn,old.data FROM discovery_observation_latest future
 CROSS JOIN LATERAL(SELECT device_key,observed_at,valid_until,withdrawn,data FROM discovery_observations o WHERE o.device_key=future.device_key AND o.source_id=future.source_id AND o.origin=future.origin AND coalesce(o.data->'evidence'->'payload'->>'service_type','')=future.service_type AND coalesce(o.data->>'port','')=future.port AND o.observed_at<=now() ORDER BY observed_at DESC,id DESC LIMIT 1) old WHERE future.observed_at>now()
 ), active AS(SELECT * FROM latest WHERE NOT withdrawn AND valid_until>now()), devices AS(SELECT device_key,max(observed_at) AS observed_at FROM active GROUP BY device_key) `
	var total int
	if err := tx.QueryRowContext(ctx, cte+`SELECT count(*) FROM devices`).Scan(&total); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, cte+`SELECT page.device_key,(SELECT jsonb_agg(a.data ORDER BY a.observed_at DESC) FROM active a WHERE a.device_key=page.device_key) AS evidence FROM (SELECT device_key,observed_at FROM devices ORDER BY observed_at DESC,device_key LIMIT $1 OFFSET $2) page ORDER BY page.observed_at DESC,page.device_key`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id string
		var b []byte
		if err = rows.Scan(&id, &b); err != nil {
			return nil, err
		}
		var ev []Observation
		if err = json.Unmarshal(b, &ev); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": id, "observations": ev})
	}
	return map[string]any{"items": items, "total": total, "limit": limit, "offset": offset}, rows.Err()
}
