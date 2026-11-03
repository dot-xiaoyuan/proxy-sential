package main

import (
	"strings"
	"testing"
)

func TestTailPlanRejectsGapsAndDuplicateIntervals(t *testing.T) {
	p := tailPlan{Epoch: "fresh", SourcePath: "packet://test", FileID: "capture", From: 100, To: 300,
		Entries: []tailEntry{{strings.Repeat("a", 64), strings.Repeat("c", 64), 100, 200}, {strings.Repeat("b", 64), strings.Repeat("d", 64), 200, 300}}}
	if err := validatePlan(p); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*tailPlan){
		func(p *tailPlan) { p.Entries[1].Start++ },
		func(p *tailPlan) { p.Entries[1].ID = p.Entries[0].ID },
		func(p *tailPlan) { p.To++ },
		func(p *tailPlan) { p.Entries = nil },
	} {
		copy := p
		copy.Entries = append([]tailEntry(nil), p.Entries...)
		change(&copy)
		if validatePlan(copy) == nil {
			t.Fatal("unsafe tail admitted")
		}
	}
}
