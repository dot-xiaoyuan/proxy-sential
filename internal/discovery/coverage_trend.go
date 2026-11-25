package discovery

import (
	"context"
	"time"
)

// These are scoped identities recorded in the retained projection. It has
// no continuous capture attestation, so absence of a row cannot prove zero.
type HardwareTrend struct {
	WindowDays      int        `json:"window_days"`
	AsOf            time.Time  `json:"as_of"`
	ObservationFrom *time.Time `json:"observation_from,omitempty"`
	ChangesFrom     *time.Time `json:"changes_from,omitempty"`
	LastSuccessAt   *time.Time `json:"last_success_at,omitempty"`
	FirstSeen       int64      `json:"first_seen,omitempty"`
	ChangedType     int64      `json:"changed_type,omitempty"`
	PreviousOnly    int64      `json:"previous_only,omitempty"`
}

// Called only by the background publisher. All counts use a single SQL
// snapshot and the same boundary: (previous start, start], then (start, end].
func hardwareTrend(ctx context.Context, db coverageQueryRower, sensor string, asOf time.Time, window time.Duration) (*HardwareTrend, error) {
	result := &HardwareTrend{AsOf: asOf, WindowDays: int(window / (24 * time.Hour))}
	err := db.QueryRowContext(ctx, `WITH observations AS (
	   SELECT count(*) FILTER (WHERE first_seen>$2 AND first_seen<=$3) AS new_count,
	          count(*) FILTER (WHERE last_seen>$4 AND last_seen<=$2) AS previous_count
	   FROM passive_hardware_current WHERE sensor_id=$1 AND last_seen>$4
	), changed AS (
	   SELECT count(DISTINCT c.identity_key) AS changed_count
	   FROM passive_hardware_changes c JOIN passive_hardware_current h USING(identity_key)
	   WHERE h.sensor_id=$1 AND c.changed_at>$2 AND c.changed_at<=$3
	     AND c.before_status='identified' AND c.after_status='identified'
	     AND c.before_type<>'' AND c.after_type<>'' AND c.before_type<>c.after_type
	)
	SELECT r.available_from,r.backfill_started_at,r.last_success_at,new_count,changed_count,previous_count
	FROM observations CROSS JOIN changed LEFT JOIN passive_hardware_runtime r ON r.sensor_id=$1`,
		sensor, asOf.Add(-window), asOf, asOf.Add(-2*window)).Scan(&result.ObservationFrom, &result.ChangesFrom, &result.LastSuccessAt,
		&result.FirstSeen, &result.ChangedType, &result.PreviousOnly)
	return result, err
}
