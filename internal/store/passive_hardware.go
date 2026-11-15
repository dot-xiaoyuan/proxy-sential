package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
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

func resolveHardwareOwnership(ctx context.Context, db passiveDiscoveryDB, o discovery.Observation) (discovery.Observation, error) {
	observations := []discovery.Observation{o}
	err := resolveHardwareOwnershipBatch(ctx, db, observations)
	return observations[0], err
}

type hardwareBindingProbe struct {
	Ordinal    int       `json:"ordinal"`
	Node       string    `json:"node"`
	IP         string    `json:"ip"`
	ObservedAt time.Time `json:"observed_at"`
	Site       string    `json:"site"`
	Domain     string    `json:"domain"`
	VLAN       string    `json:"vlan"`
	VRF        string    `json:"vrf"`
}

// Isolate the valid-time range so PostgreSQL uses the validity index for
// candidates and the observed-at index for revocations.
const hardwareBindingQuery = `WITH incoming AS MATERIALIZED (
 SELECT * FROM jsonb_to_recordset($1::jsonb) AS r(ordinal int,node text,ip text,observed_at timestamptz,site text,domain text,vlan text,vrf text)
)
SELECT i.ordinal, binding.mac
FROM incoming i CROSS JOIN LATERAL (
 WITH candidates AS MATERIALIZED (
  SELECT id,origin,observed_at,withdrawn,lower(data->>'mac') mac,
   coalesce(data->>'site','') site,coalesce(data->>'domain','') domain,
   coalesce(data->>'vlan','') vlan,coalesce(data->>'vrf','') vrf
  FROM discovery_observations
  WHERE data->>'node'=i.node AND data->>'ip'=i.ip AND origin IN ('arp','ndp','dhcp')
   AND coalesce(data->>'mac','')<>'' AND valid_until>i.observed_at
  ORDER BY valid_until DESC,observed_at DESC,id DESC
 )
 SELECT CASE WHEN count(DISTINCT mac)=1 AND count(*)<=64 THEN min(mac) END AS mac FROM (
  SELECT v.mac FROM candidates v
  WHERE v.observed_at<=i.observed_at AND NOT v.withdrawn
   AND v.site=i.site AND v.domain=i.domain AND v.vlan=i.vlan AND v.vrf=i.vrf
   AND NOT EXISTS (
    SELECT 1 FROM discovery_observations revoked WHERE revoked.withdrawn
     AND revoked.origin IN ('arp','ndp','dhcp') AND coalesce(revoked.data->>'mac','')<>''
     AND revoked.origin=v.origin AND revoked.data->>'node'=i.node AND revoked.data->>'ip'=i.ip
     AND lower(coalesce(revoked.data->>'mac',''))=v.mac
     AND coalesce(revoked.data->>'site','')=i.site AND coalesce(revoked.data->>'domain','')=i.domain
     AND coalesce(revoked.data->>'vlan','')=i.vlan AND coalesce(revoked.data->>'vrf','')=i.vrf
     AND revoked.observed_at>=v.observed_at AND revoked.observed_at<=i.observed_at
   )
  LIMIT 65
 ) claims
) binding
ORDER BY i.ordinal`

// Probe event-time bindings in bounded groups, including responses to distinct
// IPs. PostgreSQL returns at most one MAC per response. Revocations and scope
// checks run before the 65-row ambiguity cutoff.
func resolveHardwareOwnershipBatch(ctx context.Context, db passiveDiscoveryDB, observations []discovery.Observation) error {
	const maxProbes = 128
	probes := make([]hardwareBindingProbe, 0, min(maxProbes, len(observations)))
	for ordinal, o := range observations {
		switch {
		case o.Evidence.Payload["endpoint_identity_unverified"] == true:
			continue
		case o.Origin == "snmp" && (o.Evidence.Payload["is_response"] != true || passiveString(o.Evidence.Payload, "response_source_ip") != o.IP):
			observations[ordinal].MAC = ""
		case o.Origin == "arp" || o.Origin == "ndp" || o.Origin == "dhcp" || o.Origin == "sadp" || passiveDirectResponderIdentity(o):
			continue
		case o.IP != "" && o.Node != "" && o.Site != "" && o.Domain != "":
			probes = append(probes, hardwareBindingProbe{ordinal, o.Node, o.IP, o.ObservedAt, o.Site, o.Domain, o.VLAN, o.VRF})
			if len(probes) == maxProbes {
				if err := applyHardwareBindings(ctx, db, observations, probes); err != nil {
					return err
				}
				probes = probes[:0]
			}
		}
	}
	if len(probes) > 0 {
		if err := applyHardwareBindings(ctx, db, observations, probes); err != nil {
			return err
		}
	}
	for i := range observations {
		observations[i].MarkUnattributedSNMPClue()
	}
	return nil
}

func applyHardwareBindings(ctx context.Context, db passiveDiscoveryDB, observations []discovery.Observation, probes []hardwareBindingProbe) error {
	raw, err := json.Marshal(probes)
	if err != nil {
		return err
	}
	rows, err := db.QueryContext(ctx, hardwareBindingQuery, string(raw))
	if err != nil {
		return err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var ordinal int
		var mac sql.NullString
		if err := rows.Scan(&ordinal, &mac); err != nil {
			return err
		}
		if count >= len(probes) || ordinal != probes[count].Ordinal {
			return fmt.Errorf("unexpected hardware binding ordinal %d", ordinal)
		}
		o := &observations[ordinal]
		payload := make(map[string]any, len(o.Evidence.Payload)+1)
		for k, v := range o.Evidence.Payload {
			payload[k] = v
		}
		o.Evidence.Payload = payload
		switch resolved := validPassiveMAC(mac.String); {
		case !mac.Valid || resolved == "":
			o.MAC = ""
			payload["hardware_identity"] = "ambiguous_or_missing"
		case o.MAC != "" && !strings.EqualFold(o.MAC, mac.String):
			o.MAC = ""
			payload["hardware_identity"] = "conflicting_mac"
		default:
			o.MAC = resolved
			payload["hardware_identity"] = "unique_binding"
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if count != len(probes) {
		return fmt.Errorf("incomplete hardware binding result: %d of %d", count, len(probes))
	}
	return nil
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
	var lastRuleCheck time.Time
	var lastRuleVersion string
	for ctx.Err() == nil {
		work, cancel := context.WithTimeout(ctx, 12*time.Second)
		cycleStarted := time.Now()
		probe := fingerprint.EvaluateHardware(fingerprint.HardwareInput{}, time.Now().UTC())
		err := hardwareWorkerReadiness(probe)
		if err == nil && (probe.Version != lastRuleVersion || time.Since(lastRuleCheck) >= 30*time.Second) {
			_, err = discovery.RequeueHardwareRuleVersion(work, s.pg.db, sensor, probe.Version)
			if err == nil {
				lastRuleVersion, lastRuleCheck = probe.Version, time.Now()
			}
		}
		processed := 0
		if err == nil {
			// Independent identity transactions can overlap their indexed reads
			// without sharing a device lock. Keep the whole cycle capped at 16.
			var wg sync.WaitGroup
			results := make(chan struct {
				count int
				err   error
			}, 2)
			for lane := 0; lane < 2; lane++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					count, runErr := discovery.ProcessHardwareProjectionWithin(work, s.pg.db, sensor, 8, 8*time.Second)
					results <- struct {
						count int
						err   error
					}{count, runErr}
				}()
			}
			wg.Wait()
			close(results)
			for result := range results {
				processed += result.count
				if err == nil {
					err = result.err
				}
			}
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
 ON CONFLICT(sensor_id) DO UPDATE SET last_error=EXCLUDED.last_error,last_success_at=CASE WHEN EXCLUDED.last_error='' THEN now() ELSE passive_hardware_runtime.last_success_at END,updated_at=now()
 WHERE passive_hardware_runtime.last_error IS DISTINCT FROM EXCLUDED.last_error
    OR passive_hardware_runtime.last_success_at IS NULL
    OR passive_hardware_runtime.updated_at < now()-interval '10 seconds'`, sensor, message)
		recordCancel()
		if err == nil {
			err = recordErr
		}
		cancel()
		if elapsed := time.Since(cycleStarted); elapsed >= 5*time.Second || err != nil {
			log.Printf("passive hardware projection cycle: processed=%d elapsed_ms=%d error=%v", processed, elapsed.Milliseconds(), err)
		}
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
