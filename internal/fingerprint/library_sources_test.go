package fingerprint

import (
	"reflect"
	"testing"
)

func TestLibrarySourceIDsDistinctAndSorted(t *testing.T) {
	matches := []SourceMatch{
		{SourceID: "recog", RuleID: "a"},
		{SourceID: "satori", RuleID: "b"},
		{SourceID: "recog", RuleID: "c"},
		{SourceID: "", RuleID: "d"},
	}
	got := LibrarySourceIDs(matches)
	want := []string{"recog", "satori"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LibrarySourceIDs() = %v, want %v", got, want)
	}
}

func TestLibrarySourceIDsEmptyIsNotNil(t *testing.T) {
	got := LibrarySourceIDs(nil)
	if got == nil || len(got) != 0 {
		t.Fatalf("LibrarySourceIDs(nil) = %#v, want empty non-nil slice", got)
	}
}
