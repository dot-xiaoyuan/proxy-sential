package store

import (
	"testing"
	"time"
)

func TestIdentityBackgroundPriorityKeepsProgressUnderPressure(t *testing.T) {
	if identityBackgroundWorkers(6*time.Second, false) != 1 {
		t.Fatal("keep one background worker while realtime is late")
	}
	if identityBackgroundWorkers(0, true) != 1 {
		t.Fatal("failed pressure probe must not open all workers")
	}
	if identityBackgroundWorkers(time.Second, false) != 4 {
		t.Fatal("compatibility profile workers must leave WAL capacity for realtime writes")
	}
}
