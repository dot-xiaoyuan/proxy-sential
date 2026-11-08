package discovery

import (
	"context"
)

// CleanupDiscoveryObservations runs the discovery observation retention in the
// v2 pipeline, where the legacy Cleanup loop is skipped. It removes rows past
// the hot window and folds repeated DNS-SD advertisements into one row.
func (r Repository) CleanupDiscoveryObservations(ctx context.Context) error {
	for _, q := range []string{
		`DELETE FROM discovery_observations WHERE id IN(SELECT id FROM discovery_observations WHERE observed_at<now()-interval '30 days' LIMIT 5000)`,
		`DELETE FROM discovery_observations WHERE id IN(
			SELECT o.id FROM discovery_observations o
			JOIN discovery_observations n ON n.origin='dns_sd' AND n.source_id=o.source_id
			 AND n.data->>'ip'=o.data->>'ip'
			 AND n.data->'evidence'->'payload'->>'service_instance'=o.data->'evidence'->'payload'->>'service_instance'
			 AND (n.observed_at>o.observed_at OR (n.observed_at=o.observed_at AND n.id>o.id))
			WHERE o.origin='dns_sd' AND o.observed_at<now()-interval '2 days' LIMIT 5000)`,
	} {
		if _, e := r.DB.ExecContext(ctx, q); e != nil {
			return e
		}
	}
	return nil
}

func (r Repository) Cleanup(ctx context.Context) error {
	// Bounded deletes so retention does not monopolize the worker database.
	// The duplicate pass removes repeated DNS-SD advertisements of the same
	// (source, address, service instance); the row with the newest observation
	// is kept. It is bounded so one hourly run cannot hold the table.
	for _, q := range []string{
		`DELETE FROM discovery_observations WHERE id IN(SELECT id FROM discovery_observations WHERE observed_at<now()-interval '30 days' LIMIT 10000)`,
		`DELETE FROM discovery_observations WHERE id IN(
			SELECT o.id FROM discovery_observations o
			JOIN discovery_observations n ON n.origin='dns_sd' AND n.source_id=o.source_id
			 AND n.data->>'ip'=o.data->>'ip'
			 AND n.data->'evidence'->'payload'->>'service_instance'=o.data->'evidence'->'payload'->>'service_instance'
			 AND (n.observed_at>o.observed_at OR (n.observed_at=o.observed_at AND n.id>o.id))
			WHERE o.origin='dns_sd' AND o.observed_at<now()-interval '2 days' LIMIT 10000)`,
		`DELETE FROM discovery_snapshots WHERE id IN(SELECT id FROM discovery_snapshots WHERE observed_at<now()-interval '30 days' LIMIT 10000)`,
		`DELETE FROM discovery_tasks WHERE id IN(SELECT id FROM discovery_tasks WHERE created_at<now()-interval '90 days' AND status NOT IN ('pending','running') LIMIT 10000)`,
	} {
		if _, e := r.DB.ExecContext(ctx, q); e != nil {
			return e
		}
	}
	return nil
}
