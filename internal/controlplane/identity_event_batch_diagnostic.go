package controlplane

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
)

// Only fixed labels and a five-character SQLSTATE enter the bounded log.
// Request IDs, account data and driver error strings stay out of it.
var identityInboxFailureLogs apiSlowLogLimiter

func logIdentityInboxFailure(stage string, elapsed time.Duration, err error) {
	observeIdentityInboxFailure(&identityInboxFailureLogs, time.Now(), stage, elapsed, err, func(line string) { log.Print(line) })
}

func observeIdentityInboxFailure(limiter *apiSlowLogLimiter, now time.Time, stage string, elapsed time.Duration, err error, emit func(string)) {
	switch stage {
	case "lookup", "accept":
	default:
		stage = "other"
	}
	if !limiter.allow(now, stage) {
		return
	}
	var postgresError interface{ SQLState() string }
	sqlState := "none"
	if errors.As(err, &postgresError) && validIdentitySQLState(postgresError.SQLState()) {
		sqlState = postgresError.SQLState()
	}
	if elapsed < 0 {
		elapsed = 0
	}
	emit(fmt.Sprintf("identity_inbox_failed stage=%s status=503 duration_ms=%d deadline=%t sqlstate=%s",
		stage, elapsed.Milliseconds(), errors.Is(err, context.DeadlineExceeded), sqlState))
}

func validIdentitySQLState(value string) bool {
	if len(value) != 5 {
		return false
	}
	for _, ch := range value {
		if ch < '0' || ch > '9' && (ch < 'A' || ch > 'Z') {
			return false
		}
	}
	return true
}
