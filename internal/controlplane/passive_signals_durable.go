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
// an address binding. A closed DHCP source can still own a valid current lease:
// expose its facts only while that device state remains current and no active
// source has a valid identification fact for the same sensor, MAC and VLAN.
// A new ACK without option fields must not erase an older, still valid clue.
// An expired REQUEST clue is retained for at most 24 hours only when its
// active source still has a valid ACK lease for the same sensor, MAC and VLAN.
// It remains a historical clue, never a current address binding. Each source
// epoch returns at most four recent DHCP facts.
const durableDHCPSignalsSQL = `SELECT f.sensor_id,f.mac,f.ip,f.vlan,f.address_binding,f.recognition_fields,
       f.observed_at,f.visible_event_key,f.valid_until<=now() AS historical
FROM unnest(string_to_array($1,',')) AS requested(mac)
JOIN (
 SELECT DISTINCT c.epoch,c.sensor_id,c.state
 FROM stream_source_cutovers c
 WHERE c.source_kind='zeek-dhcp-binding' AND c.state IN ('active','closed')
) source ON true
JOIN LATERAL (
 SELECT f.sensor_id,f.mac,f.ip,f.vlan,f.address_binding,f.recognition_fields,
        f.observed_at,f.visible_event_key,f.valid_until
 FROM stream_discovery_facts f
 WHERE f.epoch=source.epoch AND f.sensor_id=source.sensor_id AND f.mac=requested.mac AND f.mac<>'' AND f.protocol='dhcp'
   AND NOT f.withdrawn AND f.observed_at<=now()
   AND (f.valid_until>now() OR (
     source.state='active' AND NOT f.address_binding AND f.observed_at>=now()-interval '24 hours'
     AND EXISTS (SELECT 1 FROM stream_discovery_facts lease
       JOIN stream_discovery_device_state current_lease ON current_lease.epoch=lease.epoch
         AND current_lease.device_key=lease.device_key AND current_lease.expires_at>now()
       WHERE lease.epoch=f.epoch AND lease.sensor_id=f.sensor_id AND lease.mac=f.mac AND lease.mac<>''
         AND lease.vlan=f.vlan AND lease.protocol='dhcp' AND lease.address_binding
         AND lease.valid_until>now() AND NOT lease.withdrawn)
   ))
   AND f.recognition_fields<>'{}'::jsonb
   AND (source.state='active' OR (
     EXISTS (SELECT 1 FROM stream_discovery_device_state s
       WHERE s.epoch=f.epoch AND s.device_key=f.device_key AND s.expires_at>now())
     AND NOT EXISTS (
       SELECT 1 FROM stream_discovery_facts newer
       JOIN stream_source_cutovers current_source ON current_source.epoch=newer.epoch
         AND current_source.state='active' AND current_source.source_kind='zeek-dhcp-binding'
       WHERE newer.sensor_id=f.sensor_id AND newer.mac=f.mac AND newer.vlan=f.vlan
         AND newer.protocol='dhcp' AND NOT newer.withdrawn AND newer.valid_until>now()
         AND newer.recognition_fields<>'{}'::jsonb
     )
   ))
 ORDER BY f.observed_at DESC,f.visible_event_key DESC LIMIT 4
) f ON true`

func readDurableDHCPSignals(ctx context.Context, db *sql.DB, macs []string) ([]PassiveSignal, error) {
	if len(macs) == 0 {
		return nil, nil
	}
	// The bounded page lookup contains several correlated scope checks. On a
	// large current lease set PostgreSQL may spend over a second compiling a
	// JIT plan, exceeding the API's 250 ms read budget. Keep the setting local
	// to this read-only transaction rather than changing the pooled connection.
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin durable DHCP clue read: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "SET LOCAL jit=off"); err != nil {
		return nil, fmt.Errorf("disable JIT for durable DHCP clue read: %w", err)
	}
	rows, err := tx.QueryContext(ctx, durableDHCPSignalsSQL, strings.Join(macs, ","))
	if err != nil {
		return nil, fmt.Errorf("read durable DHCP clues: %w", err)
	}
	defer rows.Close()
	items := []PassiveSignal{}
	for rows.Next() {
		var signal PassiveSignal
		var ip, eventID string
		var binding, historical bool
		var raw []byte
		var observed time.Time
		if err := rows.Scan(&signal.SensorID, &signal.MAC, &ip, &signal.DHCPVLAN, &binding, &raw, &observed, &eventID, &historical); err != nil {
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
		signal.DHCPObservedAt = observed.UTC().Format(time.RFC3339Nano)
		signal.DHCPEvidenceID = eventID
		signal.DHCPHistorical = historical
		ref := PassiveEvidenceRef{EventID: eventID, ObservedAt: signal.DHCPObservedAt, Historical: historical}
		for _, field := range []string{"hostname", "dhcp_vendor_class", "dhcp_requested_options", "dhcp_client_id_hwtype", "dhcp_option93_present"} {
			if value := fields[field]; value != "" && value != "false" {
				if signal.DHCPFieldEvidence == nil {
					signal.DHCPFieldEvidence = make(map[string]PassiveEvidenceRef)
				}
				signal.DHCPFieldEvidence[field] = ref
			}
		}
		enrichDHCPVendor(&signal)
		if historical && signal.OSFamily != "" {
			signal.OSConfidence = "weak"
			signal.OSEvidence += "（历史 DHCP REQUEST 线索）"
		}
		items = append(items, signal)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("finish durable DHCP clue read: %w", err)
	}
	return items, nil
}
