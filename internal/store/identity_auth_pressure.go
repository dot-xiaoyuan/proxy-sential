package store

import (
	"context"
	"errors"
	"sync"
	"time"
)

// A scheduling threshold, not a freshness promise. Include leased work: the
// primary inbox being empty says nothing about session projection completion.
// The age index bounds each source lookup and the immutable cutover excludes
// intentionally retired test work. There is no fragment/body/history scan.
const authenticationPendingAgeSQL = `SELECT COALESCE(max(extract(epoch FROM clock_timestamp()-pending.accepted_at)),0)
FROM (SELECT sensor_id,min(accepted_after) AS accepted_after FROM identity_derived_fresh_starts GROUP BY sensor_id) c
CROSS JOIN LATERAL (
 SELECT q.accepted_at FROM identity_derived_ready q
 WHERE q.sensor_id=c.sensor_id AND q.accepted_at>=c.accepted_after
 ORDER BY q.accepted_at LIMIT 1
) pending`

func (s *PostgresStore) authenticationPendingAge(ctx context.Context) (time.Duration, error) {
	var seconds float64
	err := s.db.QueryRowContext(ctx, authenticationPendingAgeSQL).Scan(&seconds)
	return time.Duration(seconds * float64(time.Second)), err
}

const authenticationBackgroundYieldAge = 30 * time.Second

// All profile workers in this process share one advisory probe per second.
// The mutex protects metadata only and is never held across database I/O.
type authenticationPressureCache struct {
	mu         sync.Mutex
	checked    time.Time
	age        time.Duration
	err        error
	refreshing bool
}

func (s *PostgresStore) cachedAuthenticationPendingAge(ctx context.Context) (time.Duration, error) {
	c := &s.authPressure
	c.mu.Lock()
	if time.Since(c.checked) < time.Second {
		age, err := c.age, c.err
		c.mu.Unlock()
		return age, err
	}
	if c.refreshing {
		age, err := c.age, c.err
		if c.checked.IsZero() || time.Since(c.checked) > 2*time.Second {
			err = errors.New("authentication pressure probe pending")
		}
		c.mu.Unlock()
		return age, err
	}
	c.refreshing = true
	c.mu.Unlock()
	age, err := s.authenticationPendingAge(ctx)
	c.mu.Lock()
	c.age, c.err, c.checked, c.refreshing = age, err, time.Now(), false
	c.mu.Unlock()
	return age, err
}
