package controlplane

import (
	"context"
	"fmt"
	"proxy-sentinel/internal/sharedaccess"
	"proxy-sentinel/internal/store"
	"time"
)

func (s *Server) sharedWindows(ctx context.Context, at time.Time) ([]sharedaccess.Window, error) {
	if len(s.sharedConfig.Sources) == 0 {
		return nil, nil
	}
	source, ok := s.reader.(store.SharedAccessReader)
	if !ok {
		return nil, fmt.Errorf("shared evidence store unavailable")
	}
	// Evidence older than the configured freshness interval cannot satisfy any
	// policy. Bound the database scan once per evaluation cycle, outside ops lock.
	windows, err := source.ListSharedAccessWindows(ctx, at.Add(-time.Duration(s.sharedConfig.FreshnessSeconds)*time.Second), at, 10000)
	if err != nil {
		return nil, err
	}
	diagnostics, healthErr := s.sharedCoverageDiagnostics(ctx)
	windows = append([]sharedaccess.Window{}, windows...)
	for i := range windows {
		// Do not mutate a reader's cached window or reuse its conflict backing array.
		windows[i].Conflicts = append([]string{}, windows[i].Conflicts...)
		windows[i].CoverageVerified = false
		blockers := coverageBlockers(windows[i], diagnostics, at)
		if healthErr != nil {
			blockers = []string{"capture_health_query_failed"}
		}
		if len(windows) >= 10000 {
			blockers = appendUnique(blockers, "shared_query_truncated")
		}
		if len(blockers) == 0 && windows[i].Complete {
			windows[i].CoverageVerified = true
		}
		if len(blockers) > 0 {
			windows[i].Complete = false
			for _, reason := range blockers {
				windows[i].Conflicts = appendUnique(windows[i].Conflicts, reason)
			}
		}
	}
	return windows, nil
}
