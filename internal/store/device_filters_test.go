package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/normalized"
)

func TestDeviceFiltersCombineCluesAndKeepUnidentified(t *testing.T) {
	items := []EndpointDeviceInventory{
		{Brand: "Dell", OSFamily: "Windows"},
		{Brand: "dell", OSFamily: "windows"},
		{Brand: "unknown", BrandInference: &fingerprint.BrandInference{Status: "inferred", Brand: "Apple"}},
		{Brand: "Samsung", OSFamily: "Android", RecognitionConflict: true},
	}
	want := DeviceFilterFacets{Brands: []string{"Apple", "Dell", "unknown"}, OSFamilies: []string{"unknown", "Windows"}}
	if got := deviceFilterFacets(items); !reflect.DeepEqual(got, want) {
		t.Fatalf("facets=%+v want=%+v", got, want)
	}
	if !deviceRecognitionMatches(items[0], Query{Brand: "DELL", OSFamily: "windows"}) {
		t.Fatal("case insensitive combined filters must match")
	}
	if deviceRecognitionMatches(items[0], Query{Brand: "Dell", OSFamily: "Android"}) {
		t.Fatal("both filters must match")
	}
	if !deviceRecognitionMatches(items[2], Query{Brand: "Apple", OSFamily: "unknown"}) {
		t.Fatal("inferred brand must be filterable without asserting an OS")
	}
	if !deviceRecognitionMatches(items[3], Query{Brand: "unknown", OSFamily: "unknown"}) {
		t.Fatal("conflicting recognition is unidentified")
	}
	if got, _ := deviceFilterValues(EndpointDeviceInventory{Brand: "Xiaomi", BrandConfidence: .5, BrandInference: &fingerprint.BrandInference{Status: "inferred", Brand: "Apple"}}); got != "Apple" {
		t.Fatal("filter must follow the displayed inferred brand")
	}
}

func TestFileDeviceFiltersBeforePaginationAndGlobalFacets(t *testing.T) {
	dir := t.TempDir()
	s := NewFileStore(FileOptions{ShadowDir: dir})
	events := []normalized.Event{}
	for i, brand := range []string{"Dell", "Apple", "Dell"} {
		e := identityStoreEvent(brand+string(rune('a'+i)), "student", "10.0.0.1", []string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"}[i], "ap", "endpoint", "", "2026-09-17T10:00:00Z")
		e.Payload["brand"] = brand
		e.Payload["os_family"] = map[string]string{"Dell": "Windows", "Apple": "iOS"}[brand]
		events = append(events, e)
	}
	state := BuildIdentityState(events)
	all := BuildEndpointDeviceInventories(state, Query{})
	if len(all) != 3 {
		t.Fatalf("replay created %d endpoints", len(all))
	}
	run := filepath.Join(dir, "runs", "run1")
	if err := os.MkdirAll(run, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(run, "run-summary.json"), []byte(`{"started_at":"2026-09-17T10:00:00Z","finished_at":"2026-09-17T10:00:00Z"}`), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(filepath.Join(run, "normalized.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if err := json.NewEncoder(file).Encode(event); err != nil {
			file.Close()
			t.Fatal(err)
		}
	}
	file.Close()
	for cursor := 0; cursor < 2; cursor++ {
		page, err := s.ListEndpointDevices(context.Background(), Query{Brand: "Dell", OSFamily: "Windows", Limit: 1, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		if page.Page.Total != 2 || len(page.Items) != 1 || page.Items[0].Brand != "Dell" {
			t.Fatalf("filtered page=%+v", page)
		}
		if !reflect.DeepEqual(page.Facets.Brands, []string{"Apple", "Dell"}) {
			t.Fatalf("facets must include brands outside page/filter: %+v", page.Facets)
		}
	}
}

func TestDeviceBrandFiltersExcludeMACManufacturers(t *testing.T) {
	cases := []struct {
		name string
		item EndpointDeviceInventory
		want string
	}{
		{"vendor only", EndpointDeviceInventory{Vendor: "Huawei Technologies Co.,Ltd.", VendorConfidence: .95}, "unknown"},
		{"vendor does not replace brand clue", EndpointDeviceInventory{Brand: "Xiaomi", BrandConfidence: .5, Vendor: "Dell Inc.", VendorConfidence: .9}, "Xiaomi"},
		{"confirmed brand first", EndpointDeviceInventory{Brand: "Apple", BrandConfidence: .9, Vendor: "Dell Inc.", VendorConfidence: .9}, "Apple"},
		{"inferred brand first", EndpointDeviceInventory{Vendor: "Dell Inc.", VendorConfidence: .9, BrandInference: &fingerprint.BrandInference{Status: "inferred", Brand: "Apple"}}, "Apple"},
		{"weak vendor", EndpointDeviceInventory{Vendor: "Dell Inc.", VendorConfidence: .5}, "unknown"},
		{"conflict", EndpointDeviceInventory{Vendor: "Dell Inc.", VendorConfidence: .9, RecognitionConflict: true}, "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := deviceFilterValues(c.item)
			if got != c.want {
				t.Fatalf("brand=%q want=%q", got, c.want)
			}
			if !deviceRecognitionMatches(c.item, Query{Brand: c.want}) {
				t.Fatal("displayed brand must match selection")
			}
			if facets := deviceFilterFacets([]EndpointDeviceInventory{c.item}); !reflect.DeepEqual(facets.Brands, []string{c.want}) {
				t.Fatalf("facets=%+v", facets)
			}
		})
	}
}

func TestMacOSDiscoveryFromStandardIdentityReplay(t *testing.T) {
	event := identityStoreEvent("macos-dhcp", "", "10.0.0.41", "12:34:56:78:9a:41", "ap", "endpoint", "", "2026-09-17T10:00:00Z")
	event.Payload["hostname"] = "office-mac41.local"
	event.Payload["vendor_class"] = "darwin"
	items := BuildEndpointDeviceInventories(BuildIdentityState([]normalized.Event{event}), Query{})
	if len(items) != 1 || items[0].OSFamily != "macOS" || items[0].OSFamilyConfidence >= .8 || items[0].Brand != "" {
		t.Fatalf("macOS clue must not assert a hardware brand: %+v", items)
	}
	if !deviceRecognitionMatches(items[0], Query{OSFamily: "macOS", Brand: "unknown"}) {
		t.Fatal("macOS must be selectable independently of brand")
	}
	if got := deviceFilterFacets(items); !reflect.DeepEqual(got.OSFamilies, []string{"macOS"}) {
		t.Fatalf("macOS missing from facets: %+v", got)
	}
}

func TestDeviceManufacturerReferenceReplayAndFilters(t *testing.T) {
	for _, vendor := range []string{"Huawei Technologies Co.,Ltd.", "vivo Mobile Communication Co., Ltd."} {
		event := identityStoreEvent("vendor-reference", "", "10.0.0.1", "00:10:20:30:40:50", "ap", "endpoint", "", "2026-09-17T10:00:00Z")
		event.Payload["oui_vendor"] = vendor
		items := BuildEndpointDeviceInventories(BuildIdentityState([]normalized.Event{event}), Query{})
		if len(items) != 1 || items[0].BrandReference == nil || items[0].Brand != "" || items[0].BrandConfidence != 0 || items[0].OSFamily != "" {
			t.Fatalf("reference must stay independent of device brand and OS: %+v", items)
		}
		reference := items[0].BrandReference
		if !deviceRecognitionMatches(items[0], Query{Brand: reference.Brand}) {
			t.Fatal("reference brand must be filterable")
		}
		if got := deviceFilterFacets(items); !reflect.DeepEqual(got.Brands, []string{reference.Brand}) {
			t.Fatalf("facets=%+v", got)
		}
		items[0].Brand = "Apple"
		items[0].BrandConfidence = .9
		if got, _ := deviceFilterValues(items[0]); got != "Apple" {
			t.Fatal("reference must not replace confirmed brand")
		}
	}
}
