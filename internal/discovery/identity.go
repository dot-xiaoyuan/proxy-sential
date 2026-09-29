package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"time"
)

// Associate requires an administrator-declared sensor/campus/VLAN/VRF binding
// and an event-time DHCP lease with the same MAC. Infrastructure observations
// never create terminal identity or extend leases.
func (r Repository) Associate(ctx context.Context) error {
	var exists bool
	if e := r.DB.QueryRowContext(ctx, `SELECT to_regclass('device_address_leases') IS NOT NULL`).Scan(&exists); e != nil || !exists {
		return e
	}
	rows, e := r.DB.QueryContext(ctx, `SELECT o.data,s.config FROM discovery_observations o JOIN discovery_sources s ON o.source_id=s.id WHERE o.observed_at<=now() AND o.valid_until>now() AND NOT o.withdrawn AND coalesce(s.config->>'identity_sensor','')<>'' AND NOT EXISTS(SELECT 1 FROM discovery_identity_links l WHERE l.observation_id=o.id) LIMIT 500`)
	if e != nil {
		return e
	}
	type pair struct {
		o Observation
		s Source
	}
	items := []pair{}
	for rows.Next() {
		var a, b []byte
		if e = rows.Scan(&a, &b); e != nil {
			rows.Close()
			return e
		}
		var p pair
		if json.Unmarshal(a, &p.o) == nil && json.Unmarshal(b, &p.s) == nil {
			items = append(items, p)
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, p := range items {
		o, s := p.o, p.s
		if o.ConfigVersion != s.ConfigVersion {
			continue
		}
		if o.MAC == "" || o.Site != s.Site || o.Domain != s.Domain || o.VLAN != s.IdentityVLAN || o.VRF != s.IdentityVRF {
			continue
		}
		m, e := net.ParseMAC(o.MAC)
		if e != nil || m[0]&2 != 0 {
			continue
		}
		if o.IP == "" {
			var count int
			var candidate string
			e = r.DB.QueryRowContext(ctx, `SELECT count(DISTINCT host(ip)),coalesce(min(host(ip)),'') FROM device_address_leases WHERE sensor_id=$1 AND campus_id=$2 AND endpoint_id=$3 AND observed_at<=$4 AND valid_until>$4 AND action='ack'`, s.IdentitySensor, s.IdentityCampus, "mac:"+o.MAC, o.ObservedAt).Scan(&count, &candidate)
			if e != nil {
				return e
			}
			if count != 1 {
				continue
			}
			o.IP = candidate
		}
		var endpoint, action string
		var until time.Time
		e = r.DB.QueryRowContext(ctx, `SELECT endpoint_id,valid_until,action FROM device_address_leases WHERE sensor_id=$1 AND campus_id=$2 AND ip=$3::inet AND observed_at<=$4 ORDER BY observed_at DESC,event_id DESC LIMIT 1`, s.IdentitySensor, s.IdentityCampus, o.IP, o.ObservedAt).Scan(&endpoint, &until, &action)
		if e == sql.ErrNoRows {
			continue
		}
		if e != nil {
			return e
		}
		if action != "ack" || endpoint != "mac:"+o.MAC || !until.After(o.ObservedAt) {
			continue
		}
		var conflicts int
		e = r.DB.QueryRowContext(ctx, `SELECT count(*) FROM device_address_leases WHERE sensor_id=$1 AND campus_id=$2 AND ip=$3::inet AND observed_at>$4 AND observed_at<=now() AND (action='stop' OR endpoint_id<>$5)`, s.IdentitySensor, s.IdentityCampus, o.IP, o.ObservedAt, endpoint).Scan(&conflicts)
		if e != nil {
			return e
		}
		var overlap int
		if e = r.DB.QueryRowContext(ctx, `SELECT count(DISTINCT endpoint_id) FROM device_address_leases WHERE sensor_id=$1 AND campus_id=$2 AND ip=$3::inet AND observed_at<=$4 AND valid_until>$4 AND action='ack'`, s.IdentitySensor, s.IdentityCampus, o.IP, o.ObservedAt).Scan(&overlap); e != nil {
			return e
		}
		if conflicts > 0 || overlap != 1 {
			continue
		}
		if until.After(o.ValidUntil) {
			until = o.ValidUntil
		}
		basis, _ := json.Marshal(map[string]any{"kind": "scoped_event_time_dhcp", "ip": o.IP, "sensor": s.IdentitySensor, "campus": s.IdentityCampus, "source_version": s.ConfigVersion})
		if _, e = r.DB.ExecContext(ctx, `INSERT INTO discovery_identity_links(observation_id,endpoint_id,valid_until,basis) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, o.ID, endpoint, until, basis); e != nil {
			return e
		}
	}
	// A later DHCP reassignment invalidates visibility of the old link immediately.
	_, e = r.DB.ExecContext(ctx, `DELETE FROM discovery_identity_links l USING discovery_observations o WHERE l.observation_id=o.id AND EXISTS(SELECT 1 FROM device_address_leases d WHERE d.sensor_id=l.basis->>'sensor' AND d.campus_id=l.basis->>'campus' AND host(d.ip)=coalesce(l.basis->>'ip',o.data->>'ip') AND d.observed_at>o.observed_at AND d.observed_at<=now() AND (d.action='stop' OR d.endpoint_id<>l.endpoint_id))`)
	return e
}
func (r Repository) EndpointEvidence(ctx context.Context, id string, limit, offset int) (map[string]any, error) {
	var total int
	if e := r.DB.QueryRowContext(ctx, `SELECT count(*) FROM discovery_identity_links WHERE endpoint_id=$1 AND valid_until>now()`, id).Scan(&total); e != nil {
		return nil, e
	}
	rows, e := r.DB.QueryContext(ctx, `SELECT o.data FROM discovery_identity_links l JOIN discovery_observations o ON o.id=l.observation_id WHERE l.endpoint_id=$1 AND l.valid_until>now() ORDER BY o.observed_at DESC,o.id LIMIT $2 OFFSET $3`, id, limit, offset)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	items := []Observation{}
	for rows.Next() {
		var b []byte
		if e = rows.Scan(&b); e != nil {
			return nil, e
		}
		var o Observation
		if e = json.Unmarshal(b, &o); e != nil {
			return nil, e
		}
		items = append(items, o)
	}
	return map[string]any{"items": items, "total": total}, rows.Err()
}

type Summary struct {
	Capabilities  []string `json:"capabilities"`
	Types         []string `json:"types"`
	Positions     []string `json:"positions"`
	Conflict      bool     `json:"conflict"`
	EvidenceCount int      `json:"evidence_count"`
}

func (r Repository) Summaries(ctx context.Context, ids []string) (map[string]*Summary, error) {
	rows, e := r.DB.QueryContext(ctx, `SELECT l.endpoint_id,o.data FROM discovery_identity_links l JOIN discovery_observations o ON o.id=l.observation_id JOIN discovery_sources s ON s.id=o.source_id WHERE l.endpoint_id=ANY($1::text[]) AND l.valid_until>now() AND o.valid_until>now() AND NOT o.withdrawn AND o.observed_at<=now() AND o.data->>'config_version'=s.config_version::text`, ids)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	result := map[string]*Summary{}
	add := func(values []string, v string) []string {
		if v == "" {
			return values
		}
		for _, s := range values {
			if s == v {
				return values
			}
		}
		return append(values, v)
	}
	for rows.Next() {
		var id string
		var b []byte
		if e = rows.Scan(&id, &b); e != nil {
			return nil, e
		}
		var o Observation
		if e = json.Unmarshal(b, &o); e != nil {
			return nil, e
		}
		v := result[id]
		if v == nil {
			v = &Summary{Capabilities: []string{}, Types: []string{}, Positions: []string{}}
			result[id] = v
		}
		v.EvidenceCount++
		v.Types = add(v.Types, o.DeviceType)
		for _, c := range o.Capabilities {
			v.Capabilities = add(v.Capabilities, c)
		}
		if o.Port != "" {
			v.Positions = add(v.Positions, o.SourceID+" / "+o.Port)
		}
		v.Conflict = len(v.Types) > 1
	}
	return result, rows.Err()
}
