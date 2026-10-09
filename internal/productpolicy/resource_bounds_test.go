package productpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSnapshotSerializedBoundaryIncludesDigest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	base := Snapshot{SchemaVersion: SchemaVersion, Source: "acceptance", InstanceID: "fixture", ObservedAt: now, Complete: true, Products: []Product{{ID: "p", Name: "product", Manager: "x", ControlIDs: []string{}}}, ContentHash: strings.Repeat("0", 64)}
	encoded, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, delta := range []int{0, 1} {
		s := base
		s.Products = append([]Product{}, base.Products...)
		s.ContentHash = ""
		s.Products[0].Manager = strings.Repeat("x", MaxSnapshotBytes-len(encoded)+1+delta)
		err := s.NormalizeAndValidate(now)
		if delta == 0 {
			if err != nil {
				t.Fatal("exact serialized boundary rejected", err)
			}
			payload, err := json.Marshal(s)
			if err != nil || len(payload) != MaxSnapshotBytes {
				t.Fatal("actual sender document differs from byte bound", len(payload), err)
			}
			if err := s.NormalizeAndValidate(now); err != nil {
				t.Fatal("canonical replay no longer validates", err)
			}
		} else if !errors.Is(err, ErrCatalogResourceLimit) {
			t.Fatal("digest pushed sender beyond HTTP capacity", err)
		}
	}
}

func TestSnapshotRejectsAggregateReferenceVolume(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	s := Snapshot{SchemaVersion: SchemaVersion, Source: "acceptance", InstanceID: "fixture", ObservedAt: now, Complete: true}
	for i := 0; i < 9; i++ {
		c := Control{ID: fmt.Sprint(i), Name: "control", Reference: map[string]string{}}
		for j := 0; j < 256; j++ {
			c.Reference[fmt.Sprint(j)] = strings.Repeat("x", 10000)
		}
		s.Controls = append(s.Controls, c)
	}
	if err := s.NormalizeAndValidate(now); err == nil {
		t.Fatal("individually valid fields bypassed complete snapshot byte bound")
	}
}

func TestSnapshotRejectsAggregateRelationsBeforeCanonicalization(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	s := Snapshot{SchemaVersion: SchemaVersion, Source: "acceptance", InstanceID: "fixture", ObservedAt: now, Complete: true, Controls: []Control{{ID: "c", Name: "control"}}}
	for i := 0; i < 101; i++ {
		p := Product{ID: fmt.Sprint(i), Name: "product", ControlIDs: make([]string, 1000)}
		for j := range p.ControlIDs {
			p.ControlIDs[j] = "c"
		}
		s.Products = append(s.Products, p)
	}
	if err := s.NormalizeAndValidate(now); err == nil {
		t.Fatal("normalization discarded unbounded raw relation volume")
	}
}

func TestSnapshotAggregateReferenceFieldBoundary(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, count := range []int{MaxCatalogReferenceFields, MaxCatalogReferenceFields + 1} {
		s := Snapshot{SchemaVersion: SchemaVersion, Source: "acceptance", InstanceID: "fixture", ObservedAt: now, Complete: true}
		left := count
		for i := 0; left > 0; i++ {
			c := Control{ID: fmt.Sprint(i), Name: "control", Reference: map[string]string{}}
			for j := 0; j < 256 && left > 0; j++ {
				c.Reference[fmt.Sprint(j)] = ""
				left--
			}
			s.Controls = append(s.Controls, c)
		}
		err := s.NormalizeAndValidate(now)
		if count == MaxCatalogReferenceFields && err != nil {
			t.Fatal("configured reference-field capacity rejected", err)
		}
		if count > MaxCatalogReferenceFields && !errors.Is(err, ErrCatalogResourceLimit) {
			t.Fatal("reference-field accumulation exceeded capacity", err)
		}
	}
}
