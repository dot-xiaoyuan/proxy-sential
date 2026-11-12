package main

import (
	"reflect"
	"testing"
	"time"
)

func TestCompareRouterRowsOnlyComparesMatchingVersions(t *testing.T) {
	stream := &assetRow{Key: "router-a", Epoch: "epoch-a", Version: 12, Document: map[string]any{
		"current": true, "device_type": "router", "last_device_type": "router",
		"current_addresses": []any{"10.0.0.2"}, "classification": map[string]any{"evidence_ids": []any{"e-1"}},
	}}
	shadow := &assetRow{Key: "router-a", Epoch: "epoch-a", Version: 11, Document: map[string]any{
		"current": true, "device_type": "access_point", "last_device_type": "access_point",
		"current_addresses": []any{"10.0.0.1"}, "classification": map[string]any{"evidence_ids": []any{"old"}},
	}}
	result := compareRouterRows(stream, shadow, 12)
	if result.Status != "shadow_uncovered" || len(result.Fields) != 0 {
		t.Fatalf("stale shadow was misreported as a stream field mismatch: %+v", result)
	}
	shadow.Version = 12
	result = compareRouterRows(stream, shadow, 12)
	if result.Status != "different" || !reflect.DeepEqual(result.Fields, []string{"device_type", "last_device_type", "current_addresses", "evidence_refs"}) {
		t.Fatalf("same-version differences were missed: %+v", result)
	}
}

func TestCompareRouterRowsPreservesValidityAndCoverageLimits(t *testing.T) {
	expires := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	stream := &assetRow{Key: "router-a", Epoch: "epoch-a", Version: 9, ExpiresAt: &expires,
		Document: map[string]any{"current": true, "last_device_type": "router", "classification": map[string]any{"evidence_ids": []any{"b", "a"}}}}
	shadow := &assetRow{Key: "router-a", Epoch: "epoch-a", Version: 9,
		Document: map[string]any{"current": true, "last_device_type": "router", "classification": map[string]any{"evidence_ids": []any{"a", "b"}}}}
	result := compareRouterRows(stream, shadow, 9)
	if result.Status != "partial_match" || !reflect.DeepEqual(result.Unverified, []string{"expiry_boundary"}) {
		t.Fatalf("missing expiry boundary was treated as a mismatch: %+v", result)
	}
	shadow.Epoch = "other-epoch"
	result = compareRouterRows(stream, shadow, 9)
	if result.Status != "shadow_uncovered" || len(result.Fields) != 0 {
		t.Fatalf("other epoch was compared: %+v", result)
	}
	shadow.Epoch = "epoch-a"
	result = compareRouterRows(stream, shadow, 8)
	if result.Status != "stream_advanced" || len(result.Fields) != 0 {
		t.Fatalf("state beyond fixed watermark was compared: %+v", result)
	}
	shadow.Document["current"] = false
	result = compareRouterRows(stream, shadow, 9)
	if result.Status != "shadow_not_visible" || len(result.Fields) != 0 {
		t.Fatalf("shadow row hidden by old page was treated as a match: %+v", result)
	}
}

func TestCompareRouterRowsUsesShadowFactAddressesLikeOldPage(t *testing.T) {
	stream := &assetRow{Key: "router-a", Epoch: "epoch-a", Version: 5, Document: map[string]any{
		"current": true, "device_type": "router", "current_addresses": []any{"10.0.0.1"},
	}}
	shadow := &assetRow{Key: "router-a", Epoch: "epoch-a", Version: 5, Document: map[string]any{
		"device_type": "router", "current_addresses": []any{"10.0.0.99"},
	}, Facts: map[string]any{"f1": map[string]any{"ip": "10.0.0.1"}}}
	result := compareRouterRows(stream, shadow, 5)
	if result.Status != "matched" || len(result.Fields) != 0 {
		t.Fatalf("old page fact-address overlay was ignored: %+v", result)
	}
}
