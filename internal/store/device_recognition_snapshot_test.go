package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/fingerprint"
)

func TestRecognitionSummaryIsPreparedFromSameCatalogSemantics(t *testing.T) {
	items := []EndpointDeviceInventory{
		{EndpointID: "first", Vendor: "Dell", VendorConfidence: .9, Brand: "Dell", BrandConfidence: .9,
			Model: "OptiPlex", ModelConfidence: .9, DeviceType: "desktop", DeviceTypeConfidence: .9,
			OSFamily: "Windows", OSFamilyConfidence: .9},
		{EndpointID: "second", Vendor: "Dell", VendorConfidence: .9, Brand: "Dell", BrandConfidence: .9,
			Model: "OptiPlex", ModelConfidence: .9, DeviceType: "desktop", DeviceTypeConfidence: .9,
			ConflictDimensions: []string{"brand"}},
	}
	summary := summarizeRecognitionCatalog(items)
	if summary.TotalEndpoints != 2 || summary.Coverage["vendor"].Known != 2 || summary.Coverage["brand"].Known != 1 ||
		summary.Coverage["device_type"].Known != 2 || len(summary.TopModels) != 1 || summary.TopModels[0].Count != 2 ||
		len(summary.TopTypeBrands) != 1 || summary.TopTypeBrands[0].Count != 1 {
		t.Fatalf("prepared summary changed recognition rules: %+v", summary)
	}
}

func TestRecognitionSummarySnapshotRequiresFreshPrewarm(t *testing.T) {
	store := &PostgresStore{}
	ctx := context.WithValue(context.Background(), domainReadKey{}, domainReadSnapshot{version: "active", enabled: true})
	key := "active:true:" + fingerprint.Default().Version()
	store.recognitionCatalog.entries = map[string]*recognitionCatalogEntry{key: {loading: make(chan struct{})}}
	if _, _, err := store.endpointRecognitionSummarySnapshot(ctx); err == nil || !strings.Contains(err.Error(), "not prepared") {
		t.Fatalf("cold summary was not marked unprepared: %v", err)
	}
	store = &PostgresStore{}
	store.recognitionCatalog.entries = map[string]*recognitionCatalogEntry{
		key: {summary: DeviceRecognitionSummary{TotalEndpoints: 4}, summaryReady: true, asOf: time.Now().Add(-recognitionCatalogStaleLimit - time.Second), loading: make(chan struct{})},
	}
	if _, _, err := store.endpointRecognitionSummarySnapshot(ctx); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("stale summary was returned as current: %v", err)
	}
	store.recognitionCatalog.entries[key].asOf = time.Now()
	store.recognitionCatalog.entries[key].loading = nil
	summary, _, err := store.endpointRecognitionSummarySnapshot(ctx)
	if err != nil || summary.TotalEndpoints != 4 {
		t.Fatalf("prepared summary unavailable: %+v, err=%v", summary, err)
	}
}
