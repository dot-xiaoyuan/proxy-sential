package controlplane

import (
	"errors"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/policy"
	"proxy-sentinel/internal/store"
)

func TestImportedPolicyCoverageBlocksRatherThanViolates(t *testing.T) {
	now := time.Now().UTC()
	definition := policy.Definition{Origin: &policy.Origin{Source: "office", ExternalProductID: "p1"}}
	violated := policy.Input{AccountID: "a", Known: true, Violated: true, Reasons: []string{"session_quota_exceeded"}}
	for name, coverage := range map[string]map[string]productPolicyCoverage{
		"missing_source":  {},
		"stale_snapshot":  {"office": {observedAt: now.Add(-4 * time.Minute), products: map[string]bool{"p1": true}}},
		"missing_product": {"office": {observedAt: now, products: map[string]bool{}}},
	} {
		t.Run(name, func(t *testing.T) {
			result := constrainProductPolicyInput(definition, violated, coverage, nil, now)
			if result.Known || result.Violated || len(result.Reasons) != 1 {
				t.Fatalf("coverage blocker became violation: %+v", result)
			}
		})
	}
	result := constrainProductPolicyInput(definition, violated, nil, errors.New("database unavailable"), now)
	if result.Known || result.Violated || result.Reasons[0] != "product_policy_catalog_unavailable" {
		t.Fatalf("catalog error became violation: %+v", result)
	}
	result = constrainProductPolicyInput(definition, violated, map[string]productPolicyCoverage{"office": {observedAt: now, products: map[string]bool{"p1": true}}}, nil, now)
	if !result.Known || !result.Violated {
		t.Fatalf("healthy catalog blocked confirmed input: %+v", result)
	}
}

func TestFourKSyncPath(t *testing.T) {
	for _, path := range []string{"/actions/connectors/office/4k-sync", "/api/v1/actions/connectors/office/4k-sync"} {
		id, ok := fourKSyncPath(path)
		if !ok || id != "office" {
			t.Fatalf("4K sync route not recognized: %s %s %t", path, id, ok)
		}
	}
	if _, ok := fourKSyncPath("/actions/connectors/office/test"); ok {
		t.Fatal("unrelated connector route matched 4K sync")
	}
}

func TestFourKIdentityDirectoryUsesRealSnapshotFieldsWithoutCreatingActions(t *testing.T) {
	snapshot := store.IdentitySnapshot{Events: []normalized.Event{
		{Subject: map[string]any{"account_id": "student-2"}, Payload: map[string]any{"group_id": "20", "product_id": "200"}},
		{Subject: map[string]any{"account_id": "student-1"}, Payload: map[string]any{"group_id": "10", "product_id": "100"}},
		{Subject: map[string]any{"account_id": "student-1"}, Payload: map[string]any{"group_id": "10"}},
	}}
	accounts, groups, vlans := fourKIdentityDirectory(snapshot)
	if len(accounts) != 2 || accounts[0].ID != "student-1" || accounts[1].ID != "student-2" {
		t.Fatalf("unexpected account directory: %+v", accounts)
	}
	if len(groups) != 2 || groups[0].ID != "10" || groups[1].ID != "20" {
		t.Fatalf("unexpected group directory: %+v", groups)
	}
	if len(vlans) != 0 {
		t.Fatalf("unexpected vlan directory: %+v", vlans)
	}
}
