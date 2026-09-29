package store

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

func (s *DBStore) PrepareStatisticsReadModel(ctx context.Context) error {
	if err := BackfillNormalizedEventFeatures(ctx, s.pg.db, s.ch); err != nil {
		return err
	}
	if err := BackfillActivityChartKeys(ctx, s.pg.db, s.ch); err != nil {
		return err
	}
	if err := s.DrainActivityChartReadModel(ctx); err != nil {
		return err
	}
	if err := BackfillApplicationObservationKeys(ctx, s.pg.db, s.ch); err != nil {
		return err
	}
	if err := s.DrainApplicationObservationReadModel(ctx); err != nil {
		return err
	}
	return s.pg.WarmEndpointRecognitionCatalog(ctx)
}

func (s *DBStore) StatisticsReadModelHealth(ctx context.Context) error {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("PROXY_SENTINEL_ACTIVITY_READ_MODEL_V3")), "true") {
		var refreshed time.Time
		if err := s.pg.db.QueryRowContext(ctx, `SELECT updated_at FROM read_model_runtime_state WHERE name='activity-v3-5m'`).Scan(&refreshed); err != nil {
			return fmt.Errorf("activity v3 read model is warming: %w", err)
		}
		if time.Since(refreshed) > 5*time.Minute {
			return fmt.Errorf("activity v3 statistics refresh is older than five minutes")
		}
		return nil
	}
	if err := s.activityStatisticsReadModelHealth(ctx); err != nil {
		return err
	}
	return s.pg.recognitionCatalogHealth(ctx)
}

func (s *DBStore) activityStatisticsReadModelHealth(ctx context.Context) error {
	var completed bool
	if err := s.pg.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM application_read_model_backfills WHERE name IN ('normalized-event-features-v1','activity-chart-buckets-v2') AND status='completed' GROUP BY status HAVING count(*)=2)`).Scan(&completed); err != nil {
		return err
	}
	if !completed {
		return fmt.Errorf("normalized event feature historical backfill is not completed")
	}
	var refreshed time.Time
	if err := s.pg.db.QueryRowContext(ctx, `SELECT updated_at FROM activity_chart_read_model_cursor_v2 WHERE id=1`).Scan(&refreshed); err != nil {
		return err
	}
	if time.Since(refreshed) > 3*time.Minute {
		return fmt.Errorf("activity statistics refresh is older than three minutes")
	}
	return nil
}

func (s *DBStore) ApplicationReadModelHealth(ctx context.Context) error {
	var completed bool
	var refreshed time.Time
	err := s.pg.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM application_read_model_backfills WHERE name IN('latest-observations-v1','application-observation-buckets-v2') AND status='completed' GROUP BY status HAVING count(*)=2),least(c.updated_at,o.updated_at) FROM application_connection_read_model_v2_cursor c JOIN application_observation_read_model_cursor_v2 o USING(id) WHERE c.id=1`).Scan(&completed, &refreshed)
	if err != nil {
		return fmt.Errorf("application read model not prepared: %w", err)
	}
	if !completed {
		return fmt.Errorf("application read model historical backfill not completed")
	}
	if time.Since(refreshed) > 60*time.Second {
		return fmt.Errorf("application read model refresh is older than one minute")
	}
	return nil
}
