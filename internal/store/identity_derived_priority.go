package store

import (
	"sync/atomic"
	"time"
)

// A low-priority slot is available at most once per ten seconds while the
// realtime identity inbox is behind. The first busy check starts the interval;
// it does not immediately bypass the realtime gate.
const identityDerivedQuotaInterval = 10 * time.Second

// Different workers share the same gate and report at most once per interval.
func identityDerivedGateReportDue(last *atomic.Int64, now time.Time) bool {
	nowUnixNano := now.UnixNano()
	for {
		previous := last.Load()
		if previous != 0 && nowUnixNano >= previous && nowUnixNano-previous < int64(30*time.Second) {
			return false
		}
		if last.CompareAndSwap(previous, nowUnixNano) {
			return true
		}
	}
}

func identityDerivedQuotaAllow(last *atomic.Int64, now time.Time) bool {
	nowUnixNano := now.UnixNano()
	for {
		previous := last.Load()
		if previous == 0 {
			if last.CompareAndSwap(0, nowUnixNano) {
				return false
			}
			continue
		}
		if nowUnixNano-previous < int64(identityDerivedQuotaInterval) {
			return false
		}
		if last.CompareAndSwap(previous, nowUnixNano) {
			return true
		}
	}
}
