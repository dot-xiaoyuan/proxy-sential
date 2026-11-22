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
	OUIMatched        int64      `json:"oui_matched"`
	LocallyAdminMAC   int64      `json:"locally_administered_mac"`
	NoOUIGlobalMAC    int64      `json:"no_oui_global_mac"`
	OUILibraryVersion string     `json:"oui_library_version"`
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

// mirrorFunnelCounts reads one repeatable snapshot so the address cohorts and
// OUI denominator reconcile even while the stream updates current projections.
func mirrorFunnelCounts(ctx context.Context, db *sql.DB, sensor string, window time.Duration) (MirrorFunnel, error) {
	result := MirrorFunnel{Status: "initializing", EvaluatedAt: time.Now().UTC()}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	var source, available, success, pending sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT last_source_at,available_from,last_success_at,oldest_pending_at FROM passive_census_runtime WHERE sensor_id=$1`, sensor).Scan(&source, &available, &success, &pending)
	if err == sql.ErrNoRows {
		return result, tx.Commit()
	}
	if err != nil {
		return result, err
	}
	if available.Valid {
		result.AvailableFrom = &available.Time
	}
	if !source.Valid {
		return result, tx.Commit()
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
	// The binding primary key distinguishes MACs within each scoped IP. Check
	// every live peer before restricting the remaining pair to the report window.
	const statement = `WITH ids AS MATERIALIZED (
 SELECT scope_key,kind,value,ip_family FROM passive_census_identifier_current
 WHERE sensor_id=$1 AND last_seen>=$2 AND last_seen<=$3
), ips AS MATERIALIZED (
 SELECT DISTINCT value ip FROM ids WHERE kind='ip' AND ip_family=4
), macs AS MATERIALIZED (
 SELECT DISTINCT value mac FROM ids WHERE kind='mac'
), unambiguous AS MATERIALIZED (
 SELECT scope_key,ip,min(mac) mac,max(observed_at) observed_at
 FROM passive_census_binding_current
 WHERE valid_until>$4 AND NOT withdrawn
 GROUP BY scope_key,ip HAVING count(*)=1
), scoped_pairs AS MATERIALIZED (
 SELECT b.scope_key,b.ip,b.mac,h.identity_key,h.hardware_type,h.hardware_type_status
 FROM unambiguous b
 JOIN ids i ON i.scope_key=b.scope_key AND i.kind='ip' AND i.value=b.ip AND i.ip_family=4
 JOIN ids m ON m.scope_key=b.scope_key AND m.kind='mac' AND m.value=b.mac
 LEFT JOIN passive_hardware_current h ON h.scope_key=b.scope_key AND h.mac=b.mac
  AND h.sensor_id=$1 AND h.first_seen<=$3 AND h.last_seen<=$3
 WHERE b.observed_at>=$2 AND b.observed_at<=$3
), raw_pairs AS MATERIALIZED (
 SELECT DISTINCT ip,mac FROM scoped_pairs
), typed_pairs AS MATERIALIZED (
 SELECT DISTINCT ip,mac FROM scoped_pairs
 WHERE hardware_type_status='identified' AND hardware_type<>''
)
SELECT (SELECT count(*) FROM ips),
 (SELECT count(*) FROM ips WHERE NOT EXISTS(SELECT 1 FROM raw_pairs p WHERE p.ip=ips.ip)),
 (SELECT count(*) FROM macs),
 (SELECT count(*) FROM macs WHERE NOT EXISTS(SELECT 1 FROM raw_pairs p WHERE p.mac=macs.mac)),
 (SELECT count(*) FROM raw_pairs),
 (SELECT count(*) FROM scoped_pairs),
 (SELECT count(DISTINCT identity_key) FROM scoped_pairs WHERE identity_key IS NOT NULL),
 (SELECT count(*) FROM raw_pairs p WHERE EXISTS(
  SELECT 1 FROM scoped_pairs s WHERE s.ip=p.ip AND s.mac=p.mac AND s.identity_key IS NOT NULL)),
 (SELECT count(*) FROM typed_pairs),
 (SELECT coalesce(jsonb_agg(mac),'[]'::jsonb) FROM macs)`
	var rawMACs []byte
	err = tx.QueryRowContext(ctx, statement, sensor, cutoff, source.Time, result.EvaluatedAt).Scan(
		&result.IPv4Total, &result.IPv4Only, &result.MACTotal, &result.MACOnly,
		&result.IPMACPairs, &result.ScopedPairs, &result.TrustedIdentities,
		&result.IdentifiedPairs, &result.TypedPairs, &rawMACs,
	)
	if err != nil {
		return MirrorFunnel{}, fmt.Errorf("mirror census funnel: %w", err)
	}
	var macs []string
	if err = json.Unmarshal(rawMACs, &macs); err != nil {
		return MirrorFunnel{}, err
	}
	library := fingerprint.Default()
	result.OUILibraryVersion = library.Version()
	result.OUIMatched, result.LocallyAdminMAC, result.NoOUIGlobalMAC = classifyMirrorMACs(library, macs)
	if result.OUIMatched+result.LocallyAdminMAC+result.NoOUIGlobalMAC != result.MACTotal {
		return MirrorFunnel{}, fmt.Errorf("mirror census MAC buckets do not reconcile")
	}
	if err = tx.Commit(); err != nil {
		return MirrorFunnel{}, err
	}
	return result, nil
}
