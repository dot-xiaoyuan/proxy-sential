package controlplane

import (
	"context"
	"errors"
	"proxy-sentinel/internal/store"
	"testing"
	"time"
)

type sensorScopedHealthReader struct {
	store.Reader
	local    []store.Run
	global   []store.Run
	err      error
	selected string
}

func (r *sensorScopedHealthReader) ListRuns(context.Context, int) ([]store.Run, error) {
	return r.global, nil
}
func (r *sensorScopedHealthReader) ListSensorRuns(_ context.Context, sensor string, _ int) ([]store.Run, error) {
	r.selected = sensor
	return r.local, r.err
}

func TestCollectorHealthUsesConfiguredSensor(t *testing.T) {
	for _, tc := range []struct {
		name   string
		local  []store.Run
		err    error
		status string
	}{
		{"stale local", []store.Run{{SensorID: "local", FinishedAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano), Normalized: store.NormalizedCounts{Read: 3}}}, nil, "stale"},
		{"quiet local", nil, nil, "no_data"},
		{"invalid local timestamp", []store.Run{{SensorID: "local", FinishedAt: "bad", Normalized: store.NormalizedCounts{Read: 3}}}, nil, "unavailable"},
		{"future local timestamp", []store.Run{{SensorID: "local", FinishedAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano), Normalized: store.NormalizedCounts{Read: 3}}}, nil, "unavailable"},
		{"local error", nil, errors.New("local read failed"), "unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewServer(Options{ShadowDir: t.TempDir(), SensorID: "local", ReadOnly: true})
			r := &sensorScopedHealthReader{Reader: s.reader, local: tc.local, err: tc.err, global: []store.Run{{SensorID: "other", FinishedAt: time.Now().UTC().Format(time.RFC3339Nano), Normalized: store.NormalizedCounts{Read: 99}}}}
			s.reader = r
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			components, ready := s.healthSnapshot(ctx)
			if r.selected != "local" || components["collector"].Status != tc.status {
				t.Fatalf("other sensor borrowed: selected=%q collector=%+v", r.selected, components["collector"])
			}
			if tc.status == "unavailable" && ready {
				t.Fatal("required local error hidden")
			}
		})
	}
}
