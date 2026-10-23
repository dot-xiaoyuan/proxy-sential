package store

import (
	"context"
	"log"
	"time"
)

func identityBackgroundWorkers(age time.Duration, failed bool) int {
	if failed || age > 5*time.Second {
		return 1
	}
	return sharedDeviceProfileWorkerCount
}

// Compatibility device profiles share the same disks as authoritative identity.
// Keep one consumer making progress when realtime falls behind; the other
// consumers leave their jobs durable and unclaimed. Shared observation decision
// workers have their own unchanged budget.
func (s *DBStore) identityBackgroundPriority(ctx context.Context, index int, p *identityDeltaPressure) bool {
	if !s.pg.identityDeltaEnabled || index == 0 {
		return true
	}
	probe, cancel := context.WithTimeout(ctx, time.Second)
	var age float64
	err := s.pg.db.QueryRowContext(probe, IdentityScopeStatusSQL(`SELECT COALESCE(max(extract(epoch FROM now()-oldest_pending_at)) FILTER (WHERE enabled AND pending_records>0),0) FROM identity_pipeline_scopes`)).Scan(&age)
	cancel()
	before := p.paused
	allowed := p.allow(time.Duration(age*float64(time.Second)), err != nil)
	if index == 1 && before != p.paused {
		log.Printf("identity_background_budget paused=%t workers=%d realtime_oldest_ms=%d probe_failed=%t", p.paused, identityBackgroundWorkers(time.Duration(age*float64(time.Second)), err != nil), int64(age*1000), err != nil)
	}
	if allowed {
		return true
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
	}
	return false
}
