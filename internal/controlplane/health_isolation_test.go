package controlplane

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/store"
)

type delayedStatisticsHealthReader struct {
	store.Reader
	storageError error
}

func (r delayedStatisticsHealthReader) StatisticsReadModelHealth(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (r delayedStatisticsHealthReader) Health(ctx context.Context) error {
	if r.storageError != nil {
		return r.storageError
	}
	return ctx.Err()
}

// Optional statistics timing out must remain visible without consuming the
// entire deadline before the mandatory storage check can even start.
func TestHealthOptionalTimeoutDoesNotInvalidateReadyStorage(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	s.reader = delayedStatisticsHealthReader{Reader: s.reader}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	components, ready := s.healthSnapshot(ctx)
	if !ready || components["storage"].Status != "ready" {
		t.Fatalf("optional timeout marked healthy storage unavailable: ready=%v components=%+v", ready, components)
	}
	if item := components["statistics_read_model"]; item.Status != "delayed" || !strings.Contains(item.Error, "deadline exceeded") {
		t.Fatalf("timeout hidden: %+v", item)
	}
}

func TestHealthRequiredFailureStillBlocksReadiness(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	s.reader = delayedStatisticsHealthReader{Reader: s.reader, storageError: errors.New("database transport unavailable")}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	components, ready := s.healthSnapshot(ctx)
	if ready || components["storage"].Status != "unavailable" || !strings.Contains(components["storage"].Error, "transport unavailable") {
		t.Fatalf("mandatory failure hidden: ready=%v components=%+v", ready, components)
	}
}

type uncancellableStatisticsHealthReader struct {
	delayedStatisticsHealthReader
	release <-chan struct{}
}

func (r uncancellableStatisticsHealthReader) StatisticsReadModelHealth(context.Context) error {
	<-r.release
	return nil
}

func TestHealthDeadlineBoundsUnresponsiveOptionalProbe(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	release := make(chan struct{})
	defer close(release)
	s.reader = uncancellableStatisticsHealthReader{delayedStatisticsHealthReader: delayedStatisticsHealthReader{Reader: s.reader}, release: release}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		components, ready := s.healthSnapshot(ctx)
		if !ready || components["statistics_read_model"].Status != "delayed" {
			t.Errorf("unresponsive optional probe changed readiness: %v %+v", ready, components)
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("health snapshot ignored its deadline")
	}
}
