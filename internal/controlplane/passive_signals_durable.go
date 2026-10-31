package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// The stream fact is a compact projection with a reference to the retained
// normalized event. Direct MAC evidence is used; requested IPs do not create
// an address binding. Each requested MAC and active epoch returns at most four
// recent DHCP facts.
const durableDHCPSignalsSQL = `SELECT f.sensor_id,f.mac,f.ip,f.vlan,f.address_binding,f.recognition_fields,
       f.observed_at,f.visible_event_key
FROM unnest(string_to_array($1,',')) AS requested(mac)
JOIN (SELECT DISTINCT epoch,sensor_id FROM stream_source_cutovers WHERE state='active') active ON true
JOIN LATERAL (
 SELECT f.sensor_id,f.mac,f.ip,f.vlan,f.address_binding,f.recognition_fields,
        f.observed_at,f.visible_event_key
 FROM stream_discovery_facts f
 WHERE f.epoch=active.epoch AND f.sensor_id=active.sensor_id AND f.mac=requested.mac AND f.mac<>'' AND f.protocol='dhcp'
   AND NOT f.withdrawn AND f.observed_at<=now() AND f.valid_until>now()
   AND f.recognition_fields<>'{}'::jsonb
 ORDER BY f.observed_at DESC,f.visible_event_key DESC LIMIT 4
) f ON true`

func readDurableDHCPSignals(ctx context.Context, db *sql.DB, macs []string) ([]PassiveSignal, error) {
	if len(macs) == 0 {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, durableDHCPSignalsSQL, strings.Join(macs, ","))
	if err != nil {
		return nil, fmt.Errorf("read durable DHCP clues: %w", err)
	}
	defer rows.Close()
	items := []PassiveSignal{}
	for rows.Next() {
		var signal PassiveSignal
		var ip, eventID string
		var binding bool
		var raw []byte
		var observed time.Time
		if err := rows.Scan(&signal.SensorID, &signal.MAC, &ip, &signal.DHCPVLAN, &binding, &raw, &observed, &eventID); err != nil {
			return nil, err
		}
		var fields map[string]string
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, fmt.Errorf("decode durable DHCP clues: %w", err)
		}
		if binding {
			signal.IP = ip
		}
		signal.DHCPHostname = fields["hostname"]
		signal.DHCPVendorClass = fields["dhcp_vendor_class"]
		signal.DHCPOptions = fields["dhcp_requested_options"]
		signal.DHCPClientIDHWType = fields["dhcp_client_id_hwtype"]
		signal.DHCPOption93Present = fields["dhcp_option93_present"] == "true"
		signal.DHCPObservedAt = observed.UTC().Format(time.RFC3339)
		signal.DHCPEvidenceID = eventID
		enrichDHCPVendor(&signal)
		items = append(items, signal)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}
