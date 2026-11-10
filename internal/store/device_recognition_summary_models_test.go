package store

import "testing"

func TestTopModelsKeepsHighConfidenceAndSorts(t *testing.T) {
	items := []EndpointDeviceInventory{
		{Model: "LaserJet Pro MFP", Brand: "HP", ModelConfidence: .9},
		{Model: "LaserJet Pro MFP", Brand: "HP", ModelConfidence: .85},
		{Model: "Low", ModelConfidence: .6},
		{Model: "Conflict", ModelConfidence: .95, ConflictDimensions: []string{"model"}},
		{Model: "AR1220", Brand: "Huawei", ModelConfidence: .9},
	}
	got := topModels(items)
	if len(got) != 2 {
		t.Fatalf("top models=%+v", got)
	}
	if got[0].Model != "LaserJet Pro MFP" || got[0].Brand != "HP" || got[0].Count != 2 {
		t.Fatalf("first=%+v", got[0])
	}
	if got[1].Model != "AR1220" || got[1].Count != 1 {
		t.Fatalf("second=%+v", got[1])
	}
}
	
