package store

import (
	"testing"
	"time"
)

func TestChRowAfterCursorAppliesExactResumePoint(t *testing.T) {
	cursorAt := time.Date(2026, 10, 13, 4, 48, 30, 0, time.UTC)
	for _, test := range []struct {
		name     string
		cursorAt time.Time
		cursorID string
		stamp    time.Time
		eventID  string
		want     bool
	}{
		{"empty cursor accepts everything", time.Time{}, "evt-b", cursorAt, "evt-a", true},
		{"later timestamp", cursorAt, "evt-b", cursorAt.Add(time.Microsecond), "evt-a", true},
		{"same timestamp later event", cursorAt, "evt-b", cursorAt, "evt-c", true},
		{"same timestamp same event", cursorAt, "evt-b", cursorAt, "evt-b", false},
		{"same timestamp earlier event", cursorAt, "evt-b", cursorAt, "evt-a", false},
		{"earlier timestamp", cursorAt, "evt-b", cursorAt.Add(-time.Microsecond), "evt-z", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := chRowAfterCursor(test.stamp, test.eventID, test.cursorAt, test.cursorID); got != test.want {
				t.Fatalf("chRowAfterCursor=%v, want %v", got, test.want)
			}
		})
	}
}

func TestChAdvanceCursorNeverMovesBackwards(t *testing.T) {
	cursorAt := time.Date(2026, 10, 13, 4, 48, 30, 0, time.UTC)
	for _, test := range []struct {
		name     string
		cursor   chCursorRow
		next     chCursorRow
		wantID   string
		wantMove bool
	}{
		{"forward timestamp", chCursorRow{cursorAt, "evt-b"}, chCursorRow{cursorAt.Add(time.Microsecond), "evt-a"}, "evt-a", true},
		{"forward event id", chCursorRow{cursorAt, "evt-b"}, chCursorRow{cursorAt, "evt-c"}, "evt-c", true},
		{"same key does not move", chCursorRow{cursorAt, "evt-b"}, chCursorRow{cursorAt, "evt-b"}, "evt-b", false},
		{"backwards timestamp is refused", chCursorRow{cursorAt, "evt-b"}, chCursorRow{cursorAt.Add(-time.Microsecond), "evt-z"}, "evt-b", false},
		{"backwards event id is refused", chCursorRow{cursorAt, "evt-b"}, chCursorRow{cursorAt, "evt-a"}, "evt-b", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			stamp, eventID, moved := chAdvanceCursor(test.cursor.Stamp, test.cursor.EventID, test.next)
			if moved != test.wantMove || eventID != test.wantID {
				t.Fatalf("chAdvanceCursor moved=%v eventID=%q, want moved=%v eventID=%q", moved, eventID, test.wantMove, test.wantID)
			}
			if !moved && !stamp.Equal(test.cursor.Stamp) {
				t.Fatalf("refused advance changed the timestamp to %s", stamp)
			}
		})
	}
}
