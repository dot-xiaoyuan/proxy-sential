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
	// Materialize the valid-time range first. PostgreSQL otherwise prefers the
	// observed-at index and reads many expired claims for every response while
	// replay is behind real time. The outer filters retain event-time and full
	// scope semantics, including later revocations.
	err := db.QueryRowContext(ctx, `WITH candidates AS MATERIALIZED (
 SELECT id,origin,observed_at,withdrawn,lower(data->>'mac') mac,
  coalesce(data->>'site','') site,coalesce(data->>'domain','') domain,
  coalesce(data->>'vlan','') vlan,coalesce(data->>'vrf','') vrf
 FROM discovery_observations
 WHERE data->>'node'=$1 AND data->>'ip'=$2 AND origin IN ('arp','ndp','dhcp')
  AND coalesce(data->>'mac','')<>'' AND valid_until>$3
 ORDER BY valid_until DESC,observed_at DESC,id DESC
)
SELECT CASE WHEN count(DISTINCT mac)=1 AND count(*)<=64 THEN min(mac) ELSE NULL END,count(*) FROM (
 SELECT v.mac FROM candidates v
 WHERE v.observed_at<=$3 AND NOT v.withdrawn AND v.site=$4 AND v.domain=$5 AND v.vlan=$6 AND v.vrf=$7
 AND NOT EXISTS(SELECT 1 FROM discovery_observations revoked WHERE revoked.withdrawn
  AND revoked.origin IN ('arp','ndp','dhcp') AND coalesce(revoked.data->>'mac','')<>''
  AND revoked.origin=v.origin AND revoked.data->>'node'=$1 AND revoked.data->>'ip'=$2
  AND lower(coalesce(revoked.data->>'mac',''))=v.mac
  AND coalesce(revoked.data->>'site','')=$4 AND coalesce(revoked.data->>'domain','')=$5
  AND coalesce(revoked.data->>'vlan','')=$6 AND coalesce(revoked.data->>'vrf','')=$7
  AND revoked.observed_at>=v.observed_at AND revoked.observed_at<=$3)
 LIMIT 65) binding`, o.Node, o.IP, o.ObservedAt, o.Site, o.Domain, o.VLAN, o.VRF).Scan(&mac, &count)
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

type hardwareBindingClaim struct {
	origin, mac, site, domain, vlan, vrf string
	observedAt, validUntil               time.Time
	withdrawn                            bool
}

// Most response events in one batch revisit the same IP. Read that IP's
// bounded claim and withdrawal history once, then apply the same event-time
// predicates as resolveHardwareOwnership to each response. Oversized histories
// use the individual indexed lookup so the batch remains bounded.
func resolveHardwareOwnershipBatch(ctx context.Context, db passiveDiscoveryDB, observations []discovery.Observation) error {
	groups := map[string][]int{}
	for i, o := range observations {
		if !hardwareOwnershipNeedsLookup(o) {
			resolved, err := resolveHardwareOwnership(ctx, db, o)
			if err != nil {
				return err
			}
			observations[i] = resolved
			continue
		}
		groups[o.Node+"\x00"+o.IP] = append(groups[o.Node+"\x00"+o.IP], i)
	}
	for _, indices := range groups {
		if len(indices) == 1 {
			resolved, err := resolveHardwareOwnership(ctx, db, observations[indices[0]])
			if err != nil {
				return err
			}
			observations[indices[0]] = resolved
			continue
		}
		first := observations[indices[0]]
		minimum, maximum := first.ObservedAt, first.ObservedAt
		for _, i := range indices[1:] {
			at := observations[i].ObservedAt
			if at.Before(minimum) {
				minimum = at
			}
			if at.After(maximum) {
				maximum = at
			}
		}
		claims, revocations, bounded, err := loadHardwareBindingClaims(ctx, db, first.Node, first.IP, minimum, maximum)
		if err != nil {
			return err
		}
		if len(claims)*max(1, len(revocations))*len(indices) > 2_000_000 {
			bounded = false
		}
		for _, i := range indices {
			if bounded {
				observations[i] = resolveHardwareOwnershipFromClaims(observations[i], claims, revocations)
			} else {
				resolved, err := resolveHardwareOwnership(ctx, db, observations[i])
				if err != nil {
					return err
				}
				observations[i] = resolved
			}
		}
	}
	return nil
}

func hardwareOwnershipNeedsLookup(o discovery.Observation) bool {
	if o.Evidence.Payload["endpoint_identity_unverified"] == true || o.Origin == "arp" || o.Origin == "ndp" || o.Origin == "dhcp" || o.Origin == "sadp" || passiveDirectResponderIdentity(o) {
		return false
	}
	if o.Origin == "snmp" && (o.Evidence.Payload["is_response"] != true || passiveString(o.Evidence.Payload, "response_source_ip") != o.IP) {
		return false
	}
	return o.IP != "" && o.Node != "" && o.Site != "" && o.Domain != ""
}

func loadHardwareBindingClaims(ctx context.Context, db passiveDiscoveryDB, node, ip string, minimum, maximum time.Time) ([]hardwareBindingClaim, []hardwareBindingClaim, bool, error) {
	const maxClaims = 4096
	read := func(query string, args ...any) ([]hardwareBindingClaim, bool, error) {
		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, false, err
		}
		defer rows.Close()
		claims := make([]hardwareBindingClaim, 0, 16)
		for rows.Next() {
			var claim hardwareBindingClaim
			if err := rows.Scan(&claim.origin, &claim.observedAt, &claim.validUntil, &claim.withdrawn, &claim.mac, &claim.site, &claim.domain, &claim.vlan, &claim.vrf); err != nil {
				return nil, false, err
			}
			claims = append(claims, claim)
		}
		if err := rows.Err(); err != nil {
			return nil, false, err
		}
		return claims, len(claims) <= maxClaims, nil
	}
	const fields = `origin,observed_at,valid_until,withdrawn,lower(data->>'mac'),coalesce(data->>'site',''),coalesce(data->>'domain',''),coalesce(data->>'vlan',''),coalesce(data->>'vrf','')`
	claims, bounded, err := read(`WITH candidates AS MATERIALIZED (
 SELECT `+fields+` FROM discovery_observations
 WHERE data->>'node'=$1 AND data->>'ip'=$2 AND origin IN ('arp','ndp','dhcp')
  AND coalesce(data->>'mac','')<>'' AND valid_until>$3
 ORDER BY valid_until DESC,observed_at DESC,id DESC
)
SELECT * FROM candidates WHERE observed_at<=$4 LIMIT 4097`, node, ip, minimum, maximum)
	if err != nil || !bounded || len(claims) == 0 {
		return claims, nil, bounded, err
	}
	oldest := claims[0].observedAt
	for _, claim := range claims[1:] {
		if claim.observedAt.Before(oldest) {
			oldest = claim.observedAt
		}
	}
	revocations, bounded, err := read(`SELECT `+fields+` FROM discovery_observations
WHERE data->>'node'=$1 AND data->>'ip'=$2 AND origin IN ('arp','ndp','dhcp')
 AND coalesce(data->>'mac','')<>'' AND withdrawn AND observed_at>=$3 AND observed_at<=$4
ORDER BY observed_at,id LIMIT 4097`, node, ip, oldest, maximum)
	return claims, revocations, bounded, err
}

func resolveHardwareOwnershipFromClaims(o discovery.Observation, claims, revocations []hardwareBindingClaim) discovery.Observation {
	var mac string
	count, ambiguous := 0, false
	for _, claim := range claims {
		if claim.withdrawn || claim.observedAt.After(o.ObservedAt) || !claim.validUntil.After(o.ObservedAt) || claim.site != o.Site || claim.domain != o.Domain || claim.vlan != o.VLAN || claim.vrf != o.VRF {
			continue
		}
		revoked := false
		for _, withdrawal := range revocations {
			if withdrawal.origin == claim.origin && withdrawal.mac == claim.mac && withdrawal.site == claim.site && withdrawal.domain == claim.domain && withdrawal.vlan == claim.vlan && withdrawal.vrf == claim.vrf && !withdrawal.observedAt.Before(claim.observedAt) && !withdrawal.observedAt.After(o.ObservedAt) {
				revoked = true
				break
			}
		}
		if revoked {
			continue
		}
		count++
		if mac != "" && mac != claim.mac {
			ambiguous = true
		}
		mac = claim.mac
		if count > 64 {
			ambiguous = true
			break
		}
	}
	p := make(map[string]any, len(o.Evidence.Payload)+1)
	for key, value := range o.Evidence.Payload {
		p[key] = value
	}
	o.Evidence.Payload = p
	if count == 0 || ambiguous || validPassiveMAC(mac) == "" {
		o.MAC = ""
		p["hardware_identity"] = "ambiguous_or_missing"
	} else if o.MAC != "" && !strings.EqualFold(o.MAC, mac) {
		o.MAC = ""
		p["hardware_identity"] = "conflicting_mac"
	} else {
		o.MAC = validPassiveMAC(mac)
		p["hardware_identity"] = "unique_binding"
	}
	return o
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
			processed, err = discovery.ProcessHardwareProjectionWithin(work, s.pg.db, sensor, 16, 8*time.Second)
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
