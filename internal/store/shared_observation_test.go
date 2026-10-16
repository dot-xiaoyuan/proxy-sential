package store

import (
	"encoding/json"
	"proxy-sentinel/internal/sharedaccess"
	"testing"
	"time"
)

func TestSharedObservationSwitchMatchesCommandLineBooleanParsing(t *testing.T) {
	for _, value := range []string{"true", "TRUE", "1", " true ", "false", "0", "", "invalid"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("PROXY_SENTINEL_SHARED_OBSERVATION_ENABLED", value)
			want := value == "true" || value == "TRUE" || value == "1" || value == " true "
			if SharedObservationEnabled() != want {
				t.Fatalf("unexpected switch for %q", value)
			}
		})
	}
}

func handshakeReplayFixture() (SharedObservationScope, sharedaccess.Config, []sharedObservationEvent, time.Time) {
	now := time.Date(2026, 10, 16, 1, 0, 0, 0, time.UTC)
	scope := SharedObservationScope{"sensor", "campus", "mirror", "192.0.2.4"}
	cfg := sharedaccess.Config{Version: "test", FreshnessSeconds: 180, Sources: []sharedaccess.Source{{SensorID: scope.SensorID, CampusID: scope.CampusID, AccessDomain: scope.AccessDomain, Source: "handshake-sidecar"}}}
	samples := []sharedaccess.HandshakeSample{}
	for n, ua := range []string{"Mozilla/5.0 (Linux; Android 14; SM-S9280 Build/UP1A) AppleWebKit/537.36 Chrome/120", "Mozilla/5.0 (Linux; Android 13; V2241A Build/TP1A) AppleWebKit/537.36 Chrome/120"} {
		for i := 0; i < 3; i++ {
			at := now.Add(-time.Duration(20-i*5) * time.Second)
			id := string(rune('a' + n*3 + i))
			samples = append(samples, sharedaccess.HandshakeSample{Family: "user_agent", Value: ua, EventID: id, ObservedAt: at}, sharedaccess.HandshakeSample{Family: "ja3", Value: []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}[n], EventID: id + "tls", ObservedAt: at})
		}
	}
	raw, _ := json.Marshal(map[string]any{"handshake_schema": "handshake-samples/v1", "feature_samples": samples, "capture_coverage": sharedaccess.CoverageV2{SchemaVersion: "capture-coverage/v2", From: now.Add(-30 * time.Second), To: now, KernelStatsKnown: true}})
	return scope, cfg, []sharedObservationEvent{{EventID: "raw", Source: "handshake-sidecar", Instance: "collector", IP: scope.IP, Payload: string(raw)}}, now
}

func TestSharedHandshakeReplayAndCoverage(t *testing.T) {
	scope, cfg, rows, now := handshakeReplayFixture()
	w, got, err := buildHandshakeObservation(scope, cfg, rows, now)
	if err != nil || got.Status == "confirmed" || got.DeviceLowerBound != 0 || got.StrongAnchor != "" {
		t.Fatalf("%+v %v", got, err)
	}
	duplicate := append(append([]sharedObservationEvent{}, rows...), rows...)
	w2, got2, err := buildHandshakeObservation(scope, cfg, duplicate, now)
	if err != nil || w2.ID != w.ID || got2.Status == "confirmed" {
		t.Fatalf("duplicate changed evidence: %+v %v", got2, err)
	}
	for _, field := range []string{"dropped_packets", "parse_truncated", "feature_overflow", "output_omitted", "unscoped_parse_truncated"} {
		t.Run(field, func(t *testing.T) {
			var payload map[string]any
			_ = json.Unmarshal([]byte(rows[0].Payload), &payload)
			payload["capture_coverage"].(map[string]any)[field] = 1
			raw, _ := json.Marshal(payload)
			bad := append([]sharedObservationEvent{}, rows...)
			bad[0].Payload = string(raw)
			_, item, e := buildHandshakeObservation(scope, cfg, bad, now)
			if e != nil || item.Status == "confirmed" {
				t.Fatalf("loss confirmed: %+v %v", item, e)
			}
		})
	}
	_, old, _ := buildHandshakeObservation(scope, cfg, rows, now.Add(11*time.Minute))
	if old.Current || old.Status == "confirmed" {
		t.Fatalf("expired revived: %+v", old)
	}
}

func TestSharedHandshakeSingleDeviceAndSequentialModels(t *testing.T) {
	scope, cfg, rows, now := handshakeReplayFixture()
	for _, mode := range []string{"same_model", "sequential", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			var payload struct {
				Schema   string                         `json:"handshake_schema"`
				Samples  []sharedaccess.HandshakeSample `json:"feature_samples"`
				Coverage sharedaccess.CoverageV2        `json:"capture_coverage"`
			}
			_ = json.Unmarshal([]byte(rows[0].Payload), &payload)
			for i := range payload.Samples {
				if mode == "same_model" && payload.Samples[i].Family == "user_agent" {
					payload.Samples[i].Value = "Mozilla/5.0 (Linux; Android 14; SM-S9280 Build/UP1A)"
				}
				if mode == "sequential" && i >= 6 {
					payload.Samples[i].ObservedAt = payload.Samples[i].ObservedAt.Add(-5 * time.Minute)
				}
			}
			if mode == "legacy" {
				payload.Schema = ""
				payload.Samples = nil
			}
			payload.Coverage.From = now.Add(-10 * time.Minute)
			raw, _ := json.Marshal(payload)
			bad := append([]sharedObservationEvent{}, rows...)
			bad[0].Payload = string(raw)
			_, item, err := buildHandshakeObservation(scope, cfg, bad, now)
			if err != nil || item.Status == "confirmed" {
				t.Fatalf("false positive: %+v %v", item, err)
			}
		})
	}
}

func TestSharedCoverageConflictsOnlyApplyToContributingInstance(t *testing.T) {
	scope, cfg, rows, now := handshakeReplayFixture()
	conflict := rows[0]
	conflict.EventID = "global-conflict"
	conflict.IP = ""
	conflict.PayloadVersions = 2
	same := append(append([]sharedObservationEvent{}, rows...), conflict)
	_, item, err := buildHandshakeObservation(scope, cfg, same, now)
	if err != nil || item.Status == "confirmed" {
		t.Fatalf("ambiguous global proof confirmed: %+v %v", item, err)
	}
	conflict.Instance = "unrelated-instance"
	other := append(append([]sharedObservationEvent{}, rows...), conflict)
	_, item, err = buildHandshakeObservation(scope, cfg, other, now)
	if err != nil || item.CoverageState != "verified" || len(item.Conflicts) != 0 {
		t.Fatalf("unrelated instance blocked proof: %+v %v", item, err)
	}
}
