package appdomain

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type providerFixture struct {
	EventSource
	backend DatabaseBackend
}

func (p providerFixture) ApplicationBackend() DatabaseBackend { return p.backend }

type schedulerFixture struct {
	DatabaseBackend
	realtime chan struct{}
	history  chan struct{}
	once     sync.Once
}

func (f *schedulerFixture) Step(ctx context.Context, lane string, _ time.Time, _ *Bundle) (bool, error) {
	if lane == "history" {
		f.once.Do(func() { close(f.history) })
		<-ctx.Done()
		return false, ctx.Err()
	}
	if lane == "realtime" {
		select {
		case <-f.history:
			select {
			case f.realtime <- struct{}{}:
			default:
			}
		default:
		}
		return true, nil
	}
	return false, nil
}
func TestDatabaseOpenIgnoresLegacyFilesAndRealtimeDoesNotWaitForHistory(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "observations"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"state.json", "observations/bad.json"} {
		if err := os.WriteFile(filepath.Join(dir, p), []byte("legacy invalid JSON, must not be read in database mode"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	backend := &schedulerFixture{realtime: make(chan struct{}, 1), history: make(chan struct{})}
	s, err := OpenService(dir, providerFixture{backend: backend})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Snapshot()) != 0 {
		t.Fatal("database initialized retained memory")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	select {
	case <-backend.realtime:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("realtime blocked on slow history")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not stop")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if string(raw) != "legacy invalid JSON, must not be read in database mode" {
		t.Fatal("legacy files modified")
	}
}
