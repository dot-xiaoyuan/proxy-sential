package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"proxy-sentinel/internal/census"
)

var censusPriorityTypes = map[string]bool{"printer": true, "camera": true, "recorder": true, "access_control": true, "voip_phone": true}

func RefreshCensusTerminalMAC(ctx context.Context, db *sql.DB, sensor, mac string) error {
	parsed, err := net.ParseMAC(mac)
	if err != nil || len(parsed) != 6 || parsed[0]&1 != 0 {
		return nil
	}
	rows, err := db.QueryContext(ctx, `SELECT DISTINCT device_key FROM discovery_observation_latest WHERE lower(coalesce(data->>'mac',''))=$1 AND data->>'node'=$2 LIMIT 1001`, strings.ToLower(parsed.String()), sensor)
	if err != nil {
		return err
	}
	keys := []string{}
	for rows.Next() {
		var key string
		if err = rows.Scan(&key); err != nil {
			rows.Close()
			return err
		}
		keys = append(keys, key)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(keys) > 1000 {
		return fmt.Errorf("MAC has more than 1000 discovery keys")
	}
	return RefreshCensusTerminals(ctx, db, sensor, keys)
}

// RefreshCensusTerminals reads only the latest facts for MACs affected by a
// committed discovery batch. It reuses discovery's identity and classification
// logic; weak service capabilities never become an identified type by itself.
func RefreshCensusTerminals(ctx context.Context, db *sql.DB, sensor string, deviceKeys []string) error {
	if len(deviceKeys) == 0 {
		return nil
	}
	for start := 0; start < len(deviceKeys); start += 100 {
		end := min(start+100, len(deviceKeys))
		if err := refreshCensusTerminalChunk(ctx, db, sensor, deviceKeys[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func refreshCensusTerminalChunk(ctx context.Context, db *sql.DB, sensor string, keys []string) error {
	changed, err := db.QueryContext(ctx, `SELECT DISTINCT lower(coalesce(data->>'mac','')) FROM discovery_observation_latest WHERE device_key=ANY($1::text[]) AND data->>'node'=$2 AND coalesce(data->>'mac','')<>''`, keys, sensor)
	if err != nil {
		return err
	}
	macs := []string{}
	for changed.Next() {
		var mac string
		if err = changed.Scan(&mac); err != nil {
			changed.Close()
			return err
		}
		parsed, parseErr := net.ParseMAC(mac)
		if parseErr == nil && len(parsed) == 6 && parsed[0]&1 == 0 && parsed.String() != "00:00:00:00:00:00" {
			macs = append(macs, strings.ToLower(parsed.String()))
		}
	}
	err = changed.Err()
	changed.Close()
	if err != nil || len(macs) == 0 {
		return err
	}
	rows, err := db.QueryContext(ctx, `SELECT l.device_key,l.data,
 coalesce(link.endpoint_id,''),coalesce(rec.role,''),
 coalesce(NULLIF(rec.summary->>'device_type_confidence','')::double precision,rec.confidence,0),
 CASE WHEN jsonb_array_length(coalesce(rec.summary->'conflict_dimensions','[]'::jsonb))>0 THEN rec.summary->'conflict_dimensions' ? 'device_type' ELSE coalesce(rec.conflict,false) END
 FROM discovery_observation_latest l
 LEFT JOIN discovery_identity_links link ON link.observation_id=l.id
 LEFT JOIN endpoint_recognition_summary rec ON rec.endpoint_id=coalesce(link.endpoint_id,'mac:'||lower(l.data->>'mac'))
	WHERE lower(coalesce(l.data->>'mac',''))=ANY($1::text[]) AND l.data->>'node'=$2
 ORDER BY l.device_key,l.id LIMIT 20001`, macs, sensor)
	if err != nil {
		return err
	}
	observations := []deviceObservationRow{}
	for rows.Next() {
		var row deviceObservationRow
		var raw []byte
		if err = rows.Scan(&row.DeviceKey, &raw, &row.EndpointID, &row.ProfileDeviceType, &row.ProfileTypeConfidence, &row.ProfileConflict); err != nil {
			rows.Close()
			return err
		}
		if err = json.Unmarshal(raw, &row.Observation); err != nil {
			rows.Close()
			return err
		}
		observations = append(observations, row)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(observations) > 20000 {
		return fmt.Errorf("affected terminal evidence exceeds 20000 latest rows")
	}
	views := mergeCensusTerminalViews(aggregateDeviceRows(observations, time.Now().UTC()))
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, view := range views {
		if len(view.Observations) == 0 || view.MAC == "" {
			continue
		}
		first := view.Observations[0]
		key := census.ScopeKey(first.Node, first.Site, first.Domain, first.VLAN, first.VRF)
		typeName := censusTerminalType(view)
		classificationStatus := view.ClassificationStatus
		if classificationStatus == "identified" && !censusDirectTypeEvidence(view, typeName, time.Now().UTC()) {
			classificationStatus = "candidate"
		}
		identityRaw, _ := json.Marshal([]string{"identity", first.Node, first.Site, first.Domain, first.VLAN, first.VRF, "mac", strings.ToLower(view.MAC)})
		identity := string(identityRaw)
		if typeName == "" {
			if _, err = tx.ExecContext(ctx, `DELETE FROM passive_census_terminal_current WHERE identity_key=$1`, identity); err != nil {
				return err
			}
			continue
		}
		var until, typedUntil, firstTypeExpiry time.Time
		var observed time.Time
		var rule string
		for _, observation := range view.Observations {
			if !observation.ValidUntil.IsZero() && observation.ValidUntil.After(until) {
				until = observation.ValidUntil
			}
			if observation.DeviceType == typeName && observation.ValidUntil.After(typedUntil) {
				typedUntil = observation.ValidUntil
			}
			if view.ClassificationStatus == "conflict" && censusPriorityTypes[observation.DeviceType] && observation.ValidUntil.After(time.Now()) && (firstTypeExpiry.IsZero() || observation.ValidUntil.Before(firstTypeExpiry)) {
				firstTypeExpiry = observation.ValidUntil
			}
			if observation.ObservedAt.After(observed) {
				observed, rule = observation.ObservedAt, observation.RuleVersion
			}
		}
		if until.IsZero() {
			until = view.LastSeen
		}
		if view.ClassificationStatus == "identified" && typedUntil.After(time.Now()) {
			until = typedUntil
		}
		if !firstTypeExpiry.IsZero() {
			until = firstTypeExpiry
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO passive_census_terminal_current(identity_key,scope_key,device_key,effective_type,classification_status,first_seen,last_seen,evidence_observed_at,rule_version,sensor_id,campus_id,access_domain,vlan,vrf,effective_until,mac)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
 ON CONFLICT(identity_key) DO UPDATE SET device_key=EXCLUDED.device_key,effective_type=EXCLUDED.effective_type,classification_status=EXCLUDED.classification_status,
 first_seen=least(passive_census_terminal_current.first_seen,EXCLUDED.first_seen),last_seen=greatest(passive_census_terminal_current.last_seen,EXCLUDED.last_seen),evidence_observed_at=EXCLUDED.evidence_observed_at,
 rule_version=EXCLUDED.rule_version,effective_until=EXCLUDED.effective_until,mac=EXCLUDED.mac,updated_at=now()
 WHERE (passive_census_terminal_current.device_key,passive_census_terminal_current.effective_type,passive_census_terminal_current.classification_status,passive_census_terminal_current.last_seen,passive_census_terminal_current.effective_until,passive_census_terminal_current.mac)
 IS DISTINCT FROM (EXCLUDED.device_key,EXCLUDED.effective_type,EXCLUDED.classification_status,EXCLUDED.last_seen,EXCLUDED.effective_until,EXCLUDED.mac)`, identity, key, view.ID, typeName, classificationStatus, view.FirstSeen, view.LastSeen, observed, rule, first.Node, first.Site, first.Domain, first.VLAN, first.VRF, until, strings.ToLower(view.MAC))
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func mergeCensusTerminalViews(views []DeviceView) []DeviceView {
	merged := make([]DeviceView, 0, len(views))
	position := map[string]int{}
	for _, view := range views {
		if view.MAC == "" || len(view.Observations) == 0 {
			continue
		}
		first := view.Observations[0]
		key := census.ScopeKey(first.Node, first.Site, first.Domain, first.VLAN, first.VRF) + "\x00" + strings.ToLower(view.MAC)
		index, found := position[key]
		if !found {
			position[key] = len(merged)
			merged = append(merged, view)
			continue
		}
		prior := &merged[index]
		priorType, nextType := censusTerminalType(*prior), censusTerminalType(view)
		if prior.ClassificationStatus == "conflict" || view.ClassificationStatus == "conflict" || priorType != "" && nextType != "" && priorType != nextType {
			prior.ClassificationStatus = "conflict"
		} else if prior.ClassificationStatus == "identified" || view.ClassificationStatus == "identified" {
			prior.ClassificationStatus = "identified"
		} else if prior.ClassificationStatus == "candidate" || view.ClassificationStatus == "candidate" {
			prior.ClassificationStatus = "candidate"
		} else {
			prior.ClassificationStatus = "expired"
		}
		if priorType == "" || nextType != "" && nextType < priorType {
			prior.DeviceType = nextType
		}
		if view.FirstSeen.Before(prior.FirstSeen) {
			prior.FirstSeen = view.FirstSeen
		}
		if view.LastSeen.After(prior.LastSeen) {
			prior.LastSeen = view.LastSeen
		}
		if view.ID < prior.ID {
			prior.ID = view.ID
		}
		prior.Observations = append(prior.Observations, view.Observations...)
	}
	return merged
}

func censusDirectTypeEvidence(view DeviceView, typeName string, now time.Time) bool {
	for _, observation := range view.Observations {
		if observation.DeviceType == typeName && observation.Current(now) && (observation.Confidence == "strong" || observation.Confidence == "confirmed") {
			return true
		}
	}
	return false
}

func censusTerminalType(view DeviceView) string {
	if censusPriorityTypes[view.DeviceType] {
		return view.DeviceType
	}
	if censusPriorityTypes[view.LastDeviceType] {
		return view.LastDeviceType
	}
	if view.ClassificationStatus == "conflict" {
		types := []string{}
		for _, observation := range view.Observations {
			if censusPriorityTypes[observation.DeviceType] {
				types = append(types, observation.DeviceType)
			}
		}
		sort.Strings(types)
		if len(types) > 0 {
			return types[0]
		}
	}
	return ""
}
