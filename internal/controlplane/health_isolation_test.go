package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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

type stalledDatabaseHealthReader struct{ delayedStatisticsHealthReader }

func (r stalledDatabaseHealthReader) Health(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
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

func TestReadinessReturnsWithinOneSecondWhenDatabaseProbeStalls(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	s.reader = stalledDatabaseHealthReader{delayedStatisticsHealthReader{Reader: s.reader}}
	response := httptest.NewRecorder()
	started := time.Now()
	s.handleReadiness(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("readiness waited %s for a stalled database probe", elapsed)
	}
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("stalled required storage probe returned HTTP %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), `"storage":{"status":"unavailable"`) {
		t.Fatal("storage timeout was hidden")
	}
}

func TestSystemStatusReturnsWithinOneSecondWhenDatabaseProbeStalls(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	s.reader = stalledDatabaseHealthReader{delayedStatisticsHealthReader{Reader: s.reader}}
	response := httptest.NewRecorder()
	started := time.Now()
	s.handleSystemStatus(response, httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil))
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("system status waited %s for a stalled database probe", elapsed)
	}
	if !strings.Contains(response.Body.String(), `"storage":{"status":"unavailable"`) {
		t.Fatal("storage timeout was hidden")
	}
}
