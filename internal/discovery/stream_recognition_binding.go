package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
)

type streamRecognitionIP struct {
	IP        string `json:"ip"`
	Sensor    string `json:"sensor"`
	Site      string `json:"site"`
	Domain    string `json:"domain"`
	VLAN      string `json:"vlan"`
	VRF       string `json:"vrf"`
	Interface string `json:"interface"`
}

type streamRecognitionDirty struct {
	macs map[string]bool
	ips  map[streamRecognitionIP]bool
}

func newStreamRecognitionDirty() *streamRecognitionDirty {
	return &streamRecognitionDirty{macs: map[string]bool{}, ips: map[streamRecognitionIP]bool{}}
}

// routeRecognitionWake keeps visible changes on the immediate path and sends
// repeat observations to a bounded deferred set. A repeat keeps the same
// semantic hash, but observed_at/valid_until still decide whether a binding is
// live at recognition time; dropping it would lose a same-content renewal that
// follows expiry. Deferral coalesces those wakes without discarding them.
func routeRecognitionWake(immediate, deferred *streamRecognitionDirty, previous *streamDiscoveryFact, next streamDiscoveryFact, decision streamFactDecision) {
	if decision.VisibleChanged {
		immediate.add(previous, next)
		return
	}
	deferred.add(previous, next)
}

// dropImmediateOverlap keeps a visible change on the immediate path when the
// same endpoint is also present in the deferred set. Without this, the later
// deferred statement could push a just-woken job to the end of the window.
func dropImmediateOverlap(immediate, deferred map[string]bool) {
	for mac := range deferred {
		if immediate[mac] {
			delete(deferred, mac)
		}
	}
}

func (d *streamRecognitionDirty) add(previous *streamDiscoveryFact, next streamDiscoveryFact) {
	addRecognitionDirtyMACs(d.macs, previous, next)
	for _, f := range []*streamDiscoveryFact{previous, &next} {
		if f == nil {
			continue
		}
		binding := f.Protocol == "dhcp" || f.Protocol == "dhcpv6" || f.Protocol == "arp" || f.Protocol == "ndp"
		if binding && f.MAC != "" {
			// Retain the previous owner even when a correction overwrites its MAC.
			d.macs[f.MAC] = true
		}
		if f.IP != "" && (binding || len(f.RecognitionFields) > 0) {
			d.ips[streamRecognitionIP{f.IP, f.Sensor, f.Site, f.Domain, f.VLAN, f.VRF, f.Interface}] = true
		}
	}
}

// resolve expands scoped IP wakes into their physical owners once, so the
// immediate and deferred paths share the same saturation guard.
func (d *streamRecognitionDirty) resolve(ctx context.Context, tx *sql.Tx) (map[string]bool, error) {
	macs := make(map[string]bool, len(d.macs)+len(d.ips))
	for mac := range d.macs {
		macs[mac] = true
	}
	if len(d.ips) > 0 {
		values := make([]streamRecognitionIP, 0, len(d.ips))
		for ip := range d.ips {
			values = append(values, ip)
		}
		sort.Slice(values, func(i, j int) bool { return contentHash(values[i]) < contentHash(values[j]) })
		raw, err := json.Marshal(values)
		if err != nil {
			return nil, err
		}
		rows, err := tx.QueryContext(ctx, streamRecognitionAffectedBindingsSQL, raw)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var mac string
			var saturated bool
			if err := rows.Scan(&mac, &saturated); err != nil {
				return nil, err
			}
			if saturated {
				return nil, errors.New("stream recognition scoped binding budget exceeded; repair required")
			}
			macs[mac] = true
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	return macs, nil
}

// Binding changes only wake owners of the touched physical IP scopes. Include
// withdrawn/expired rows so loss of ownership also removes product evidence.
// No endpoint creation, raw-event read or historical replay occurs here.
func (d *streamRecognitionDirty) mark(ctx context.Context, tx *sql.Tx) error {
	macs, err := d.resolve(ctx, tx)
	if err != nil {
		return err
	}
	return markStreamRecognitionDirtyNow(ctx, tx, macs)
}

const streamRecognitionAffectedBindingsSQL = `WITH scopes AS (
 SELECT * FROM jsonb_to_recordset($1::jsonb) v(ip text,sensor text,site text,domain text,vlan text,vrf text,interface text)
)
SELECT DISTINCT b.mac,b.saturated FROM scopes v
CROSS JOIN LATERAL (
 SELECT limited.mac,count(*) OVER()>=65 AS saturated FROM (
  SELECT b.mac FROM stream_source_cutovers c
  JOIN stream_discovery_facts b ON b.epoch=c.epoch
  WHERE c.state='active' AND b.ip=v.ip AND b.ip<>'' AND b.mac<>''
   AND b.protocol IN ('dhcp','dhcpv6','arp','ndp')
   AND b.sensor_id=v.sensor AND b.site=v.site AND b.domain=v.domain
   AND b.vlan=v.vlan AND b.vrf=v.vrf AND b.interface_name=v.interface
  LIMIT 65
 ) limited
) b`
