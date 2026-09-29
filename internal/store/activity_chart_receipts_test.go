package store

import "testing"

func TestActivityChartReceiptPrefixDoesNotSkipInterleavedReceipts(t *testing.T) {
	rows := []activityChartCursor{
		{WindowStart: "a", SensorID: "one", WrittenAt: "1"},
		{WindowStart: "a", SensorID: "one", WrittenAt: "2"},
		{WindowStart: "a", SensorID: "two", WrittenAt: "3"},
		{WindowStart: "a", SensorID: "one", WrittenAt: "4"},
		{WindowStart: "a", SensorID: "two", CampusID: "other", WrittenAt: "5"},
		{WindowStart: "a", SensorID: "one", WrittenAt: "6"},
	}
	first := activityChartReceiptPrefix(rows, 2)
	if len(first) != 4 || first[len(first)-1].WrittenAt != "4" {
		t.Fatalf("receipt cursor skipped unprocessed scope: %+v", first)
	}
	remaining := activityChartReceiptPrefix(rows[len(first):], 2)
	if len(remaining) != 2 || remaining[0].WrittenAt != "5" {
		t.Fatalf("unprocessed receipts lost: %+v", remaining)
	}
}

func TestActivityChartReceiptPrefixCoalescesRepeatedNotifications(t *testing.T) {
	rows := make([]activityChartCursor, 1000)
	for i := range rows {
		rows[i] = activityChartCursor{WindowStart: "same", SensorID: "sensor"}
	}
	if got := activityChartReceiptPrefix(rows, 20); len(got) != len(rows) {
		t.Fatalf("duplicate notifications needlessly split: %d", len(got))
	}
	if got := activityChartReceiptPrefix(nil, 20); len(got) != 0 {
		t.Fatal("empty queue produced work")
	}
}
