package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

func (r Repository) EnqueueScan(ctx context.Context, id, profile string, scheduled ...bool) error {
	var raw []byte
	var version int
	if e := r.DB.QueryRowContext(ctx, `SELECT config,version FROM discovery_scan_profiles WHERE id=$1`, profile).Scan(&raw, &version); e != nil {
		return e
	}
	var p ScanProfile
	if e := json.Unmarshal(raw, &p); e != nil {
		return e
	}
	known, e := r.KnownAddresses(ctx, p)
	if e != nil {
		return e
	}
	p.Targets, e = p.Config.Targets(known)
	if e != nil {
		return e
	}
	if len(p.Targets) == 0 {
		return fmt.Errorf("no targets in configured scope")
	}
	raw, _ = json.Marshal(p)
	result, e := r.DB.ExecContext(ctx, `INSERT INTO discovery_tasks(id,profile_id,node,kind,config_version,config) SELECT $1,id,node,'scan',version,$3 FROM discovery_scan_profiles WHERE id=$2 AND version=$4 AND ($5 OR (enabled AND trial_version=version)) ON CONFLICT DO NOTHING`, id, profile, raw, version, len(scheduled) == 0)
	if e != nil {
		return e
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("profile changed or already queued")
	}
	return nil
}
func (r Repository) KnownAddresses(ctx context.Context, p ScanProfile) ([]string, error) {
	rows, e := r.DB.QueryContext(ctx, `SELECT DISTINCT data->>'ip' FROM discovery_observations WHERE data->>'site'=$1 AND data->>'domain'=$2 AND observed_at<=now() AND valid_until>now() AND NOT withdrawn AND data->>'ip'<>'' LIMIT 4097`, p.Site, p.Domain)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	result := []string{}
	for rows.Next() {
		var ip string
		if e = rows.Scan(&ip); e != nil {
			return nil, e
		}
		result = append(result, ip)
	}
	return result, rows.Err()
}
func (r Repository) ScheduleScans(ctx context.Context) error {
	rows, e := r.DB.QueryContext(ctx, `SELECT id FROM discovery_scan_profiles WHERE enabled AND trial_version=version AND next_scan<=now() LIMIT 100`)
	if e != nil {
		return e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, id := range ids {
		task := "scan-" + id + "-" + fmt.Sprint(time.Now().UnixNano())
		if e = r.EnqueueScan(ctx, task, id, true); e != nil {
			continue
		}
		if _, e = r.DB.ExecContext(ctx, `UPDATE discovery_scan_profiles SET next_scan=now()+make_interval(secs=>greatest(3600,(config->'config'->>'interval_seconds')::int)) WHERE id=$1`, id); e != nil {
			return e
		}
	}
	return nil
}
func (r Repository) runScan(ctx context.Context, t Task) (Snapshot, error) {
	var p ScanProfile
	if e := json.Unmarshal(t.Config, &p); e != nil {
		return Snapshot{}, e
	}
	p.Version = t.Version
	if len(p.Targets) == 0 || len(p.Targets) > 4096 {
		return Snapshot{}, fmt.Errorf("invalid frozen target list")
	}
	return Scan(ctx, p, t.ID, p.Targets)
}
