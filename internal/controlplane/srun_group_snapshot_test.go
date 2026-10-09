package controlplane

import (
	"bytes"
	"context"
	"fmt"
	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/legacy4k"
	"proxy-sentinel/internal/productpolicy"
	"proxy-sentinel/internal/srunapi"
	"reflect"
	"testing"
	"time"
)

func TestSRunGroupSnapshotCanonicalizationPreservesInputAndEmptyDirectory(t *testing.T) {
	original := []srunapi.Group{{ID: "2", Name: "two"}, {ID: "1", Name: "one", ParentID: "root", Path: "/one"}}
	saved := append([]srunapi.Group{}, original...)
	_, raw, hash, err := canonicalSRunGroups(original)
	if err != nil || !reflect.DeepEqual(original, saved) {
		t.Fatalf("canonicalization altered input: %v %v", original, err)
	}
	_, other, otherHash, err := canonicalSRunGroups([]srunapi.Group{original[1], original[0]})
	if err != nil || !bytes.Equal(raw, other) || hash != otherHash {
		t.Fatal("permutation changed snapshot identity")
	}
	_, nilRaw, nilHash, err := canonicalSRunGroups(nil)
	if err != nil || string(nilRaw) != "[]" {
		t.Fatal("empty directory is not an explicit array")
	}
	_, emptyRaw, emptyHash, err := canonicalSRunGroups([]srunapi.Group{})
	if err != nil || !bytes.Equal(nilRaw, emptyRaw) || nilHash != emptyHash {
		t.Fatal("empty directory changed by slice allocation")
	}
	for _, groups := range [][]srunapi.Group{{{ID: ""}}, {{ID: " spaced "}}, {{ID: "1"}, {ID: "1"}}} {
		if _, _, _, err := canonicalSRunGroups(groups); err == nil {
			t.Fatal("invalid group identity accepted")
		}
	}
}

func TestSRunGroupSupersededAndConflictDoNotFailCurrentConnection(t *testing.T) {
	for _, tc := range []struct {
		failure error
		outcome string
	}{{errSRunGroupSnapshotSuperseded, "superseded"}, {errSRunGroupSnapshotConflict, "snapshot_conflict"}, {fmt.Errorf("online inventory: %w", legacy4k.ErrOnlineInventoryChanged), "observation_conflict"}, {fmt.Errorf("product catalog: %w", productpolicy.ErrRedisCatalogChanged), "observation_conflict"}, {fmt.Errorf("catalog volume: %w", productpolicy.ErrCatalogResourceLimit), "catalog_resource_limit"}, {fmt.Errorf("online volume: %w", legacy4k.ErrOnlineResourceLimit), "online_resource_limit"}} {
		t.Run(tc.outcome, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			reader := &srunFailureAudit{}
			s := &Server{operations: &operationsState{db: db}, reader: reader}
			started := time.Now()
			s.recordSRunSyncFailure(context.Background(), "one", tc.failure)
			if len(reader.entries) != 1 || reader.entries[0].Outcome != tc.outcome || reader.entries[0].Action != "integration.srun4k.sync" {
				t.Fatalf("outcome not distinct: %+v", reader.entries)
			}
			if reader.deadlines[0].IsZero() || reader.deadlines[0].After(started.Add(4*time.Second)) {
				t.Fatal("audit is not bounded")
			}
			if err = mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
