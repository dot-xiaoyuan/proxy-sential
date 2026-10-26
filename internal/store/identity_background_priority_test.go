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
	if identityBackgroundWorkers(time.Second, false) != 8 {
		t.Fatal("compatibility profiles need eight consumers to drain sustained live input")
	}
}
