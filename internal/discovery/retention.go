package discovery

import (
	"context"
)

func (r Repository) Cleanup(ctx context.Context) error {
	// Bounded deletes so retention does not monopolize the worker database.
	for _, q := range []string{
		`DELETE FROM discovery_observations WHERE id IN(SELECT id FROM discovery_observations WHERE observed_at<now()-interval '30 days' LIMIT 1000)`,
		`DELETE FROM discovery_snapshots WHERE id IN(SELECT id FROM discovery_snapshots WHERE observed_at<now()-interval '30 days' LIMIT 1000)`,
		`DELETE FROM discovery_tasks WHERE id IN(SELECT id FROM discovery_tasks WHERE created_at<now()-interval '90 days' AND status NOT IN ('pending','running') LIMIT 1000)`,
	} {
		if _, e := r.DB.ExecContext(ctx, q); e != nil {
			return e
		}
	}
	return nil
}
