package store

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

func (s *DBStore) PrepareStatisticsReadModel(ctx context.Context) error {
	if err := s.backfillActivityStatistics(ctx); err != nil {
		return err
	}
	return s.pg.WarmEndpointRecognitionCatalog(ctx)
}

func (s *DBStore) backfillActivityStatistics(ctx context.Context) error {
	if err := BackfillNormalizedEventFeatures(ctx, s.pg.db, s.ch); err != nil {
		return err
	}
	if err := BackfillActivityChartKeys(ctx, s.pg.db, s.ch); err != nil {
		return err
	}
	return s.DrainActivityChartReadModel(ctx)
}

func (s *DBStore) StatisticsReadModelHealth(ctx context.Context) error {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("PROXY_SENTINEL_ACTIVITY_READ_MODEL_V3")), "true") {
		lag, err := s.activityV3RealtimeLag(ctx, time.Now().UTC())
		if err != nil {
			return fmt.Errorf("activity v3 read model is not ready: %w", err)
		}
		if lag > 300 {
			return fmt.Errorf("activity v3 statistics event coverage is older than five minutes with unfinished work")
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

func (s *DBStore) RunStatisticsReadModels(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = s.pg.WarmEndpointRecognitionCatalog(ctx)
			}
		}
	}()
	s.RunActivityChartReadModel(ctx)
}
