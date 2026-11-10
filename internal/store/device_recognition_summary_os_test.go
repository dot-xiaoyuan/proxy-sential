package store

import "testing"

func TestTopOSFamiliesFiltersAndSorts(t *testing.T) {
	items := []EndpointDeviceInventory{
		{OSFamily: "Apple OS", OSFamilyConfidence: .9},
		{OSFamily: "Apple OS", OSFamilyConfidence: .85},
		{OSFamily: "Windows", OSFamilyConfidence: .9},
		{OSFamily: "Linux", OSFamilyConfidence: .5},
		{OSFamily: "iOS", OSFamilyConfidence: .95, ConflictDimensions: []string{"os_family"}},
	}
	got := topOSFamilies(items)
	if len(got) != 2 {
		t.Fatalf("top os=%+v", got)
	}
	if got[0].OS != "Apple OS" || got[0].Count != 2 {
		t.Fatalf("first=%+v", got[0])
	}
	if got[1].OS != "Windows" || got[1].Count != 1 {
		t.Fatalf("second=%+v", got[1])
	}
}
