package discovery

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestIndexedDiscoverySearchUsesStructuredColumns(t *testing.T) {
	raw, err := os.ReadFile("indexed.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	if strings.Contains(source, "data::text") || !strings.Contains(source, "data->>'name'") || !strings.Contains(source, "data->>'mac'") {
		t.Fatal("discovery search fell back to a whole JSON document scan")
	}
}

func TestIndexedDeviceCursorBindsCompleteQuery(t *testing.T) {
	query := DeviceQuery{Mode: "passive", Search: "printer", DeviceType: "printer", Category: "service", Capability: "printing", Window: 24 * time.Hour}
	item := DeviceView{ID: "device-a", LastSeen: time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)}
	cursor, err := encodeIndexedDeviceCursor(query, item)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeIndexedDeviceCursor(DeviceQuery{Mode: query.Mode, Search: query.Search, DeviceType: query.DeviceType, Category: query.Category, Capability: query.Capability, Window: query.Window, Cursor: cursor})
	if err != nil {
		t.Fatal(err)
	}
	if decoded.DeviceKey != item.ID || decoded.LastSeen != item.LastSeen.Format(time.RFC3339Nano) {
		t.Fatalf("cursor did not preserve position: %+v", decoded)
	}
	for _, changed := range []DeviceQuery{
		{Mode: query.Mode, Search: "other", Window: query.Window, Cursor: cursor},
		{Mode: query.Mode, Search: query.Search, Window: 48 * time.Hour, Cursor: cursor},
	} {
		if _, err := decodeIndexedDeviceCursor(changed); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("cursor accepted changed query: %+v, err=%v", changed, err)
		}
	}
}

func TestDecodeIndexedDeviceCursorRejectsMalformedValues(t *testing.T) {
	query := DeviceQuery{Window: 24 * time.Hour, Cursor: "%%%"}
	if _, err := decodeIndexedDeviceCursor(query); err == nil {
		t.Fatal("malformed cursor was accepted")
	}
	query.Cursor = "e30"
	if _, err := decodeIndexedDeviceCursor(query); err == nil {
		t.Fatal("cursor without position was accepted")
	}
}
