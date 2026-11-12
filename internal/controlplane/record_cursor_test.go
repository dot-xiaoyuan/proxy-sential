package controlplane

import (
	"testing"
	"time"
)

func TestRecordCursorRoundTripAndRejectsMalformedInput(t *testing.T) {
	want := recordCursor{Snapshot: time.Date(2026, 11, 12, 2, 0, 0, 0, time.UTC), At: time.Date(2026, 11, 12, 1, 0, 0, 123456000, time.UTC), ID: "row-2"}
	got, err := decodeRecordCursor(encodeRecordCursor(want))
	if err != nil || got != want {
		t.Fatalf("round trip: got=%+v err=%v", got, err)
	}
	for _, raw := range []string{"invalid", "e30", encodeRecordCursor(recordCursor{Snapshot: want.Snapshot, ID: want.ID})} {
		if _, err := decodeRecordCursor(raw); err == nil {
			t.Fatalf("accepted malformed cursor %q", raw)
		}
	}
}
