package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

func coverageIdentityPendingStatement(sensor string, window time.Duration, at time.Time) (string, []any, error) {
	query := DeviceQuery{Mode: "passive", Window: window, SnapshotAt: at, HardwareV2: true, includeCandidateTypes: true}
	selection, err := buildIndexedDeviceSelection(query)
	if err != nil {
		return "", nil, err
	}
	dumbTypes := make([]string, 0, len(dumbHardwareTypes))
	for kind := range dumbHardwareTypes {
		dumbTypes = append(dumbTypes, kind)
	}
	sensorArg := fmt.Sprintf("$%d", len(selection.Args)+1)
	untilArg := fmt.Sprintf("$%d", len(selection.Args)+2)
	dumbArg := fmt.Sprintf("$%d", len(selection.Args)+3)
	args := append(selection.Args, sensor, at, dumbTypes)
	// A join on materialized CTEs underestimates the number of profile matches
	// and can repeatedly scan the observation set in long report windows.
	statement := selection.CTE + fmt.Sprintf(`, profile_inputs AS (
 SELECT DISTINCT identity_key COLLATE "C" identity_key,device_key,false has_profile
 FROM candidate_rows WHERE sensor_id=%s
 UNION ALL
 SELECT identity_key,NULL::text device_key,true
 FROM matched WHERE classification_status='candidate' AND cardinality(effective_types)=0 AND candidate_role<>''
), profile_keys AS MATERIALIZED (
 SELECT DISTINCT device_key FROM (
  SELECT device_key,bool_or(has_profile) OVER (PARTITION BY identity_key) has_profile
  FROM profile_inputs
 ) p WHERE device_key IS NOT NULL AND has_profile
), `, sensorArg) + coveragePerIPSQL(sensorArg, "$1", untilArg,
		"LEFT JOIN profile_keys p ON p.device_key=h.device_key", "p.device_key IS NOT NULL") + coveragePendingRowsSQL + fmt.Sprintf(`
SELECT identities.*,evidence.* FROM (
 SELECT now(),count(*),
  count(*) FILTER (WHERE classification_status='identified'),
  count(*) FILTER (WHERE classification_status='identified' AND effective_types[1]=ANY(%s::text[])),
  count(*) FILTER (WHERE classification_status='candidate' AND cardinality(effective_types)=0 AND candidate_role<>''),
  (SELECT coalesce(jsonb_agg(to_jsonb(p)),'[]'::jsonb) FROM pending_counts p)
 FROM matched
) identities CROSS JOIN (%s) evidence`, dumbArg, coverageEvidenceSelectSQL)
	return statement, args, nil
}

func coverageIdentityAndPendingCounts(ctx context.Context, db coverageQueryRower, sensor string, window time.Duration, at time.Time, out *CoverageReport) error {
	statement, args, err := coverageIdentityPendingStatement(sensor, window, at)
	if err != nil {
		return err
	}
	var asOf time.Time
	var total, identified, dumb, candidates int64
	var raw []byte
	destinations := append([]any{&asOf, &total, &identified, &dumb, &candidates, &raw}, coverageEvidenceDestinations(out)...)
	if err := db.QueryRowContext(ctx, statement, args...).Scan(destinations...); err != nil {
		return err
	}
	var rows []CoverageIPv4PendingRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		return err
	}
	var count int64
	for _, row := range rows {
		count += row.NetworkOnly + row.DHCPOnly + row.DeviceProtocol + row.Other
	}
	if count != out.IdentityNoTypeIPv4+out.NoIdentityIPv4 {
		return fmt.Errorf("IPv4 pending evidence counts do not reconcile")
	}
	out.IdentityAsOf, out.IdentityTotal = &asOf, &total
	out.Identified, out.DumbTerminals = &identified, &dumb
	out.ProfileCandidates = &candidates
	out.IPv4Pending = rows
	return nil
}

const coveragePendingRowsSQL = `, pending AS (
 SELECT CASE WHEN NOT has_identity THEN 'unlinked'
   WHEN withdrawn_confirmation THEN 'withdrawn_confirmation'
   WHEN type_conflict THEN 'conflict'
   WHEN has_profile THEN 'with_profile'
   ELSE 'without_profile' END status,
  network_only,dhcp,app
 FROM per_ip WHERE NOT typed
), pending_counts AS (
 SELECT status,
  count(*) FILTER (WHERE network_only) network_only,
  count(*) FILTER (WHERE dhcp AND NOT app) dhcp_only,
  count(*) FILTER (WHERE app) device_protocol,
  count(*) FILTER (WHERE NOT network_only AND NOT dhcp AND NOT app) other
 FROM pending GROUP BY status
)
`
