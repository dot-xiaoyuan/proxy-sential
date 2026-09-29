package appdomain

import (
	"context"
	"testing"
	"time"
)

type laneRecorder struct {
	DatabaseBackend
	lanes []string
}

func (b *laneRecorder) Step(_ context.Context, lane string, _ time.Time, _ *Bundle) (bool, error) {
	b.lanes = append(b.lanes, lane)
	return false, nil
}
func TestHistoryDisabledSurvivesReopenAndKeepsRealtime(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_APPLICATION_HISTORY_DISABLED", "true")
	dir := t.TempDir()
	for i := 0; i < 2; i++ {
		b := &laneRecorder{}
		s, err := OpenService(dir, providerFixture{backend: b})
		if err != nil {
			t.Fatal(err)
		}
		for _, lane := range []string{"history", "reconcile", "realtime"} {
			if _, err = s.databaseStep(context.Background(), lane, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
		if len(b.lanes) != 1 || b.lanes[0] != "realtime" {
			t.Fatalf("unexpected work: %v", b.lanes)
		}
		if s.StartReclassification(time.Now()) == nil {
			t.Fatal("history creation allowed")
		}
		if s.ControlJob("resume") == nil {
			t.Fatal("history resume allowed")
		}
	}
}
