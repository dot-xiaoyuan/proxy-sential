package controlplane

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"proxy-sentinel/internal/store"
)

// SignalExpectation declares that a signal must keep arriving. Source is
// optional so one rule can cover a type emitted by several collectors; when
// set it separates, for example, router TTL from shared-access SYN TTL.
type SignalExpectation struct {
	Source          string
	SourceEventType string
	MaxAge          time.Duration
}

func (e SignalExpectation) Name() string {
	if e.Source == "" {
		return e.SourceEventType
	}
	return e.Source + ":" + e.SourceEventType
}

// ParseSignalExpectations reads "type=10m,source:type=30m".
func ParseSignalExpectations(spec string) ([]SignalExpectation, error) {
	out := []SignalExpectation{}
	seen := map[string]bool{}
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		key, rawAge, ok := strings.Cut(item, "=")
		if !ok {
			return nil, fmt.Errorf("signal expectation %q must be name=duration", item)
		}
		age, err := time.ParseDuration(strings.TrimSpace(rawAge))
		if err != nil || age < time.Minute || age > 24*time.Hour {
			return nil, fmt.Errorf("signal expectation %q needs a duration between 1m and 24h", item)
		}
		expectation := SignalExpectation{MaxAge: age}
		key = strings.TrimSpace(key)
		if source, kind, scoped := strings.Cut(key, ":"); scoped {
			expectation.Source, expectation.SourceEventType = strings.TrimSpace(source), strings.TrimSpace(kind)
			if expectation.Source == "" {
				return nil, fmt.Errorf("signal expectation %q has an empty source", item)
			}
		} else {
			expectation.SourceEventType = key
		}
		if expectation.SourceEventType == "" {
			return nil, fmt.Errorf("signal expectation %q has an empty event type", item)
		}
		if seen[expectation.Name()] {
			return nil, fmt.Errorf("signal expectation %q is duplicated", expectation.Name())
		}
		seen[expectation.Name()] = true
		out = append(out, expectation)
	}
	return out, nil
}

type signalFreshness struct {
	Signal     string `json:"signal"`
	Status     string `json:"status"`
	MaxAge     int64  `json:"max_age_seconds"`
	AgeSeconds *int64 `json:"age_seconds,omitempty"`
	LastSeen   string `json:"last_seen,omitempty"`
}

type signalFreshnessSnapshot struct {
	health    componentHealth
	signals   []signalFreshness
	checkedAt time.Time
}

// signalFreshnessMonitor keeps the ClickHouse scan off the request path:
// readiness probes poll every few seconds during upgrades, while arrival ages
// only need minute resolution.
type signalFreshnessMonitor struct {
	reader       store.SignalArrivalReader
	expectations []SignalExpectation
	interval     time.Duration
	mu           sync.RWMutex
	snapshot     signalFreshnessSnapshot
}

func newSignalFreshnessMonitor(reader store.SignalArrivalReader, expectations []SignalExpectation) *signalFreshnessMonitor {
	if reader == nil || len(expectations) == 0 {
		return nil
	}
	return &signalFreshnessMonitor{reader: reader, expectations: expectations, interval: time.Minute,
		snapshot: signalFreshnessSnapshot{health: componentHealth{Status: "pending"}}}
}

func (m *signalFreshnessMonitor) run(ctx context.Context) {
	for {
		m.refresh(ctx)
		timer := time.NewTimer(m.interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (m *signalFreshnessMonitor) refresh(parent context.Context) {
	lookback := time.Duration(0)
	for _, expectation := range m.expectations {
		if expectation.MaxAge > lookback {
			lookback = expectation.MaxAge
		}
	}
	// One extra window distinguishes "late" from "gone for a while" without
	// scanning arbitrary history.
	lookback *= 2
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	arrivals, err := m.reader.SignalArrivals(ctx, lookback)
	now := time.Now().UTC()
	if err != nil {
		m.mu.Lock()
		m.snapshot.health = componentHealth{Status: "delayed", Error: err.Error(), UpdatedAt: m.snapshot.health.UpdatedAt}
		m.mu.Unlock()
		return
	}
	signals, stale := evaluateSignalFreshness(m.expectations, arrivals)
	health := componentHealth{Status: "ready", UpdatedAt: now.Format(time.RFC3339Nano)}
	if len(stale) > 0 {
		health.Status, health.Error = "stale", "signals not arriving: "+strings.Join(stale, ", ")
	}
	m.mu.Lock()
	m.snapshot = signalFreshnessSnapshot{health: health, signals: signals, checkedAt: now}
	m.mu.Unlock()
}

func evaluateSignalFreshness(expectations []SignalExpectation, arrivals []store.SignalArrival) ([]signalFreshness, []string) {
	signals := make([]signalFreshness, 0, len(expectations))
	stale := []string{}
	for _, expectation := range expectations {
		item := signalFreshness{Signal: expectation.Name(), Status: "missing", MaxAge: int64(expectation.MaxAge / time.Second)}
		var newest *store.SignalArrival
		for index := range arrivals {
			arrival := &arrivals[index]
			if arrival.SourceEventType != expectation.SourceEventType || expectation.Source != "" && arrival.Source != expectation.Source {
				continue
			}
			if newest == nil || arrival.AgeSeconds < newest.AgeSeconds {
				newest = arrival
			}
		}
		if newest != nil {
			age := newest.AgeSeconds
			if age < 0 {
				age = 0
			}
			item.AgeSeconds, item.LastSeen = &age, newest.LastSeen.Format(time.RFC3339Nano)
			item.Status = "ready"
			if age > item.MaxAge {
				item.Status = "stale"
			}
		}
		if item.Status != "ready" {
			stale = append(stale, item.Signal)
		}
		signals = append(signals, item)
	}
	sort.Strings(stale)
	return signals, stale
}

func (m *signalFreshnessMonitor) current() signalFreshnessSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	snapshot := m.snapshot
	snapshot.signals = append([]signalFreshness(nil), m.snapshot.signals...)
	return snapshot
}
