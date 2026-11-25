package discovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"proxy-sentinel/internal/fingerprint"
)

// MirrorFunnel uses the mirror census rather than the device-observation index.
// Address and MAC counts are raw distinct values seen in the selected window.
// Pairs are currently valid, unambiguous IPv4/MAC bindings seen in that window;
// discovery identities retain their access scope.
type MirrorFunnel struct {
	Status            string     `json:"status"`
	AsOf              *time.Time `json:"as_of,omitempty"`
	EvaluatedAt       time.Time  `json:"evaluated_at"`
	AvailableFrom     *time.Time `json:"available_from,omitempty"`
	IPv4Total         int64      `json:"ipv4_total"`
	IPv4Only          int64      `json:"ipv4_only"`
	MACTotal          int64      `json:"mac_total"`
	MACOnly           int64      `json:"mac_only"`
	IPMACPairs        int64      `json:"ip_mac_pairs"`
	ScopedPairs       int64      `json:"scoped_pairs"`
	TrustedIdentities int64      `json:"trusted_identities"`
	IdentifiedPairs   int64      `json:"identified_pairs"`
	TypedPairs        int64      `json:"typed_pairs"`
	TypedIdentities   int64      `json:"typed_identities"`
	OUIMatched        int64      `json:"oui_matched"`
	LocallyAdminMAC   int64      `json:"locally_administered_mac"`
	NoOUIGlobalMAC    int64      `json:"no_oui_global_mac"`
	OUILibraryVersion string     `json:"oui_library_version"`

	IPv4BindingFreshness *CoverageBindingFreshness `json:"ipv4_binding_freshness,omitempty"`
}

func classifyMirrorMACs(library *fingerprint.Library, macs []string) (matched, local, unmatched int64) {
	for _, mac := range macs {
		switch {
		case fingerprint.IsRandomizedMAC(mac):
			local++
		case library.LookupOUIVendor(mac) != "":
			matched++
		default:
			unmatched++
		}
	}
	return
}

// Keep the census watermark and the current projections in one MVCC snapshot.
func coverageAddressAndMirrorCounts(ctx context.Context, db *sql.DB, sensor string, window time.Duration, at time.Time, out *CoverageReport) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := coverageAddressAndMirrorSnapshot(ctx, tx, sensor, window, at, out); err != nil {
		return err
	}
	return tx.Commit()
}

func coverageAddressAndMirrorSnapshot(ctx context.Context, tx *sql.Tx, sensor string, window time.Duration, at time.Time, out *CoverageReport) error {
	result := &out.MirrorFunnel
	result.Status, result.EvaluatedAt = "initializing", time.Now().UTC()
	var source, available, success, pending sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT last_source_at,available_from,last_success_at,oldest_pending_at FROM passive_census_runtime WHERE sensor_id=$1`, sensor).Scan(&source, &available, &success, &pending)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if available.Valid {
		result.AvailableFrom = &available.Time
	}
	if !source.Valid {
		return coverageAddressCounts(ctx, tx, sensor, at.Add(-window), at, out)
	}
	result.AsOf = &source.Time
	cutoff := source.Time.Add(-window)
	result.Status = "ready"
	if !available.Valid || available.Time.After(cutoff) || pending.Valid {
		result.Status = "partial"
	}
	if success.Valid && time.Since(success.Time) > 10*time.Minute {
		result.Status = "delayed"
	}
	// If the optional intersection fails, preserve the address and mirror
	// counts from the same snapshot. Only this exceptional path retries.
	if _, err := tx.ExecContext(ctx, "SAVEPOINT coverage_overlap"); err != nil {
		return err
	}
	var rawMACs []byte
	var freshness CoverageBindingFreshness
	destinations := append(coverageAddressDestinations(out),
		&result.IPv4Total, &result.IPv4Only, &result.MACTotal, &result.MACOnly,
		&result.IPMACPairs, &result.ScopedPairs, &result.TrustedIdentities,
		&result.IdentifiedPairs, &result.TypedPairs, &result.TypedIdentities, &rawMACs,
		&freshness.Current, &freshness.Expired, &freshness.Uncertain, &freshness.NoBinding,
	)
	const counts = "WITH " + coverageAddressSetsSQL + ", " + mirrorSetsSQL +
		", device_totals AS (" + coverageAddressTotalsSQL + "), mirror_totals AS (" + mirrorTotalsSQL + ") SELECT d.*, m.*"
	const fromTotals = " FROM device_totals d CROSS JOIN mirror_totals m"
	const overlap = ", (SELECT count(*) FROM observed_ips d JOIN ips m USING(ip) WHERE d.v4)"
	args := []any{sensor, at.Add(-window), at, cutoff, source.Time, result.EvaluatedAt}
	var intersection int64
	err = tx.QueryRowContext(ctx, counts+overlap+fromTotals, args...).Scan(append(destinations, &intersection)...)
	if err == nil {
		out.IPv4MirrorOverlap = &intersection
	} else {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, err := tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT coverage_overlap"); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, counts+fromTotals, args...).Scan(destinations...); err != nil {
			return fmt.Errorf("coverage address and mirror counts: %w", err)
		}
	}
	result.IPv4BindingFreshness = &freshness
	var macs []string
	if err = json.Unmarshal(rawMACs, &macs); err != nil {
		return err
	}
	library := fingerprint.Default()
	result.OUILibraryVersion = library.Version()
	result.OUIMatched, result.LocallyAdminMAC, result.NoOUIGlobalMAC = classifyMirrorMACs(library, macs)
	if result.OUIMatched+result.LocallyAdminMAC+result.NoOUIGlobalMAC != result.MACTotal {
		return fmt.Errorf("mirror census MAC buckets do not reconcile")
	}
	return nil
}

// The binding primary key distinguishes MACs within each scoped IP. Check
// every live peer before restricting the remaining pair to the report window.
const mirrorSetsSQL = `ids AS MATERIALIZED (
 SELECT scope_key,kind,value,ip_family FROM passive_census_identifier_current
 WHERE sensor_id=$1 AND last_seen>=$4 AND last_seen<=$5
), ips AS MATERIALIZED (
 SELECT DISTINCT value ip FROM ids WHERE kind='ip' AND ip_family=4
), macs AS MATERIALIZED (
 SELECT DISTINCT value mac FROM ids WHERE kind='mac'
), unambiguous AS MATERIALIZED (
 SELECT scope_key,ip,min(mac) mac,max(observed_at) observed_at
 FROM passive_census_binding_current
 WHERE valid_until>$6 AND NOT withdrawn AND observed_at<=$5
 GROUP BY scope_key,ip HAVING count(*)=1
), scoped_pairs AS MATERIALIZED (
 SELECT b.scope_key,b.ip,b.mac,h.identity_key,h.hardware_type,h.hardware_type_status
 FROM unambiguous b
 JOIN ids i ON i.scope_key=b.scope_key AND i.kind='ip' AND i.value=b.ip AND i.ip_family=4
 JOIN ids m ON m.scope_key=b.scope_key AND m.kind='mac' AND m.value=b.mac
 LEFT JOIN passive_hardware_current h ON h.scope_key=b.scope_key AND h.mac=b.mac
  AND h.sensor_id=$1 AND h.first_seen<=$5 AND h.last_seen<=$5
 WHERE b.observed_at>=$4 AND b.observed_at<=$5
), raw_pairs AS MATERIALIZED (
 SELECT ip,mac,bool_or(identity_key IS NOT NULL) identified,
  bool_or(hardware_type_status='identified' AND hardware_type<>'') typed
 FROM scoped_pairs GROUP BY ip,mac
), observed_bindings AS (
 SELECT b.ip,bool_or(b.withdrawn OR b.valid_until>$6) uncertain
 FROM ids i
 JOIN passive_census_binding_current b ON b.scope_key=i.scope_key AND b.ip=i.value
 JOIN ids m ON m.scope_key=b.scope_key AND m.kind='mac' AND m.value=b.mac
 WHERE i.kind='ip' AND i.ip_family=4 AND b.observed_at>=$4 AND b.observed_at<=$5
 GROUP BY b.ip
), mirror_freshness_counts AS (
 SELECT count(*) FILTER(WHERE p.ip IS NOT NULL) current,
  count(*) FILTER(WHERE p.ip IS NULL AND b.uncertain=false) expired,
  count(*) FILTER(WHERE p.ip IS NULL AND b.uncertain=true) uncertain,
  count(*) FILTER(WHERE p.ip IS NULL AND b.ip IS NULL) no_binding
 FROM ips i LEFT JOIN (SELECT DISTINCT ip FROM raw_pairs) p USING(ip)
 LEFT JOIN observed_bindings b USING(ip)
)`

const mirrorTotalsSQL = `SELECT (SELECT count(*) FROM ips),
 (SELECT count(*) FROM ips WHERE NOT EXISTS(SELECT 1 FROM raw_pairs p WHERE p.ip=ips.ip)),
 (SELECT count(*) FROM macs),
 (SELECT count(*) FROM macs WHERE NOT EXISTS(SELECT 1 FROM raw_pairs p WHERE p.mac=macs.mac)),
 (SELECT count(*) FROM raw_pairs),
 (SELECT count(*) FROM scoped_pairs),
 (SELECT count(DISTINCT identity_key) FROM scoped_pairs WHERE identity_key IS NOT NULL),
 (SELECT count(*) FROM raw_pairs WHERE identified),
 (SELECT count(*) FROM raw_pairs WHERE typed),
 (SELECT count(DISTINCT identity_key) FROM scoped_pairs WHERE hardware_type_status='identified' AND hardware_type<>''),
 (SELECT coalesce(jsonb_agg(mac),'[]'::jsonb) FROM macs),
 current,expired,uncertain,no_binding
FROM mirror_freshness_counts`
