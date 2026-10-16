package store

import (
	"reflect"
	"testing"
)

func TestDistinctSortedStringsMergesLibraryLabels(t *testing.T) {
	got := distinctSortedStrings([]string{"recog", "", "satori", "recog"})
	want := []string{"recog", "satori"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("distinctSortedStrings() = %v, want %v", got, want)
	}
	if empty := distinctSortedStrings(nil); empty == nil || len(empty) != 0 {
		t.Fatalf("distinctSortedStrings(nil) = %#v, want empty non-nil slice", empty)
	}
}

func TestRouterSummaryKeyMatchesDeviceSummaryID(t *testing.T) {
	if got := routerSummaryKey("02:13:36:AA:9C:DB"); got != "mac:02:13:36:aa:9c:db" {
		t.Fatalf("routerSummaryKey() = %q", got)
	}
	if got := routerSummaryKey(""); got != "" {
		t.Fatalf("routerSummaryKey(empty) = %q, want empty", got)
	}
}
