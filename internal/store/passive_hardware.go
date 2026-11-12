package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/normalized"
)

func passiveScopeField(e normalized.Event, key string) string {
	if value := passiveString(e.Payload, key); value != "" {
		return value
	}
	return passiveString(e.Subject, key)
}

// A frame/claim MAC is not sufficient for routed responses. The new projection
// admits only parser-verified direct ownership or a unique event-time binding
// in every scope dimension. Legacy link lookup remains behind the old reader.
func resolveHardwareOwnership(ctx context.Context, db passiveDiscoveryDB, o discovery.Observation) (discovery.Observation, error) {
	if o.Evidence.Payload["endpoint_identity_unverified"] == true {
		return o, nil
	}
	if o.Origin == "snmp" && (o.Evidence.Payload["is_response"] != true || passiveString(o.Evidence.Payload, "response_source_ip") != o.IP) {
		o.MAC = ""
		return o, nil
	}
	if o.Origin == "arp" || o.Origin == "ndp" || o.Origin == "dhcp" || passiveDirectResponderIdentity(o) {
		return o, nil
	}
	if o.Origin == "sadp" {
		return o, nil
	} // SADP already has its stricter claimed-MAC verifier.
	if o.IP == "" || o.Node == "" || o.Site == "" || o.Domain == "" {
		return o, nil
	}
	var mac sql.NullString
	var count int
	err := db.QueryRowContext(ctx, `SELECT CASE WHEN count(DISTINCT mac)=1 AND count(*)<=64 THEN min(mac) ELSE NULL END,count(*) FROM (
 SELECT lower(data->>'mac') mac FROM discovery_observations v
 WHERE data->>'node'=$1 AND data->>'ip'=$2 AND origin IN ('arp','ndp','dhcp')
 AND observed_at<=$3 AND valid_until>$3 AND NOT withdrawn AND coalesce(data->>'mac','')<>''
 AND coalesce(data->>'site','')=$4 AND coalesce(data->>'domain','')=$5
 AND coalesce(data->>'vlan','')=$6 AND coalesce(data->>'vrf','')=$7
 AND NOT EXISTS(SELECT 1 FROM discovery_observations revoked WHERE revoked.withdrawn
  AND revoked.origin IN ('arp','ndp','dhcp') AND coalesce(revoked.data->>'mac','')<>''
  AND revoked.origin=v.origin AND revoked.data->>'node'=$1 AND revoked.data->>'ip'=$2
  AND lower(coalesce(revoked.data->>'mac',''))=lower(v.data->>'mac')
  AND coalesce(revoked.data->>'site','')=$4 AND coalesce(revoked.data->>'domain','')=$5
  AND coalesce(revoked.data->>'vlan','')=$6 AND coalesce(revoked.data->>'vrf','')=$7
  AND revoked.observed_at>=v.observed_at AND revoked.observed_at<=$3)
 ORDER BY observed_at DESC,id DESC LIMIT 65) binding`, o.Node, o.IP, o.ObservedAt, o.Site, o.Domain, o.VLAN, o.VRF).Scan(&mac, &count)
	if err != nil {
		return o, err
	}
	p := make(map[string]any, len(o.Evidence.Payload)+1)
	for k, v := range o.Evidence.Payload {
		p[k] = v
	}
	o.Evidence.Payload = p
	if !mac.Valid || validPassiveMAC(mac.String) == "" {
		o.MAC = ""
		p["hardware_identity"] = "ambiguous_or_missing"
		return o, nil
	}
	if o.MAC != "" && !strings.EqualFold(o.MAC, mac.String) {
		o.MAC = ""
		p["hardware_identity"] = "conflicting_mac"
		return o, nil
	}
	o.MAC = validPassiveMAC(mac.String)
	p["hardware_identity"] = "unique_binding"
	return o, nil
}

func passiveSNMPVarbindsPresent(v any) bool {
	switch values := v.(type) {
	case map[string]string:
		return len(values) > 0
	case map[string]any:
		return len(values) > 0
	}
	return false
}

func (s *DBStore) runPassiveHardwareProjection(ctx context.Context, sensor string) {
	if !discovery.HardwareProjectionEnabled() {
		return
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		work, cancel := context.WithTimeout(ctx, 10*time.Second)
		probe := fingerprint.EvaluateHardware(fingerprint.HardwareInput{}, time.Now().UTC())
		err := hardwareWorkerReadiness(probe)
		if err == nil {
			_, err = discovery.RequeueHardwareRuleVersion(work, s.pg.db, sensor, probe.Version)
		}
		if err == nil {
			_, err = discovery.ProcessHardwareProjection(work, s.pg.db, sensor, 100)
		}
		if err == nil && os.Getenv("PROXY_SENTINEL_HARDWARE_BACKFILL") == "true" {
			err = s.backfillPassiveHardwareLatest(work, sensor)
		}
		message := ""
		if err != nil {
			message = err.Error()
		}
		recordCtx, recordCancel := context.WithTimeout(context.WithoutCancel(work), 2*time.Second)
		_, recordErr := s.pg.db.ExecContext(recordCtx, `INSERT INTO passive_hardware_runtime(sensor_id,last_error,last_success_at) VALUES($1,$2,CASE WHEN $2='' THEN now() ELSE NULL END)
 ON CONFLICT(sensor_id) DO UPDATE SET last_error=EXCLUDED.last_error,last_success_at=CASE WHEN EXCLUDED.last_error='' THEN now() ELSE passive_hardware_runtime.last_success_at END,updated_at=now()`, sensor, message)
		recordCancel()
		if err == nil {
			err = recordErr
		}
		cancel()
		if err != nil && ctx.Err() == nil {
			log.Printf("passive hardware projection: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func hardwareWorkerReadiness(result fingerprint.HardwareResult) error {
	if result.Incomplete || result.SourceStatus != "verified_bundle" || result.Version == "" {
		return fmt.Errorf("hardware rules unavailable: source_status=%s %s", result.SourceStatus, result.Error)
	}
	return nil
}

// backfillPassiveHardwareLatest only reuses retained current evidence with an
// authoritative source reference, from a fixed window. It never scans history
// in a request or competes with live ingestion without an explicit gate.
func (s *DBStore) backfillPassiveHardwareLatest(ctx context.Context, sensor string) error {
	tx, err := s.pg.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO passive_hardware_runtime(sensor_id) VALUES($1) ON CONFLICT DO NOTHING`, sensor); err != nil {
		return err
	}
	var cursor string
	var complete bool
	var started time.Time
	if err = tx.QueryRowContext(ctx, `SELECT backfill_cursor,backfill_complete,backfill_started_at FROM passive_hardware_runtime WHERE sensor_id=$1 FOR UPDATE`, sensor).Scan(&cursor, &complete, &started); err != nil {
		return err
	}
	if complete {
		return nil
	}
	position := []string{"", "", "", "", ""}
	if cursor != "" {
		if err = json.Unmarshal([]byte(cursor), &position); err != nil || len(position) != 5 {
			return fmt.Errorf("invalid hardware backfill cursor")
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT device_key,source_id,origin,service_type,port,data FROM discovery_observation_latest
 WHERE (device_key COLLATE "C",source_id COLLATE "C",origin COLLATE "C",service_type COLLATE "C",port COLLATE "C")>($1,$2,$3,$4,$5)
 AND data->>'node'=$6 AND observed_at>=$7
 ORDER BY device_key COLLATE "C",source_id COLLATE "C",origin COLLATE "C",service_type COLLATE "C",port COLLATE "C" LIMIT 100`, position[0], position[1], position[2], position[3], position[4], sensor, started.Add(-30*24*time.Hour))
	if err != nil {
		return err
	}
	observations := []discovery.Observation{}
	count, missing, changed := 0, 0, 0
	for rows.Next() {
		var raw []byte
		var o discovery.Observation
		if err = rows.Scan(&position[0], &position[1], &position[2], &position[3], &position[4], &raw); err != nil {
			rows.Close()
			return err
		}
		if err = json.Unmarshal(raw, &o); err != nil {
			rows.Close()
			return err
		}
		count++
		if o.ObservedAt.After(started) {
			changed++
			continue
		}
		if len(o.Evidence.RawRef) == 0 || o.EventID == "" {
			missing++
			continue
		}
		observations = append(observations, o)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	encoded, _ := json.Marshal(position)
	cursor = string(encoded)
	var available *time.Time
	for i := range observations {
		if available == nil || observations[i].ObservedAt.Before(*available) {
			at := observations[i].ObservedAt
			available = &at
		}
		observations[i], err = resolveHardwareOwnership(ctx, tx, observations[i])
		if err != nil {
			return err
		}
	}
	if err = discovery.EnqueueHardwareObservations(ctx, tx, observations); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE passive_hardware_runtime SET backfill_cursor=$2,backfill_complete=$3,backfill_rows=backfill_rows+$4,backfill_missing_refs=backfill_missing_refs+$5,available_from=least(available_from,$6),backfill_changed_rows=backfill_changed_rows+$7,last_success_at=now(),updated_at=now() WHERE sensor_id=$1`, sensor, cursor, count < 100, count, missing, available, changed)
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if count < 100 {
		// New compact projections need statistics before switching shadow reads.
		// Without ANALYZE a freshly filled scope can select a quadratic join.
		_, err = s.pg.db.ExecContext(ctx, `ANALYZE passive_hardware_facts; ANALYZE passive_hardware_current; ANALYZE passive_hardware_dirty`)
	}
	return err
}
