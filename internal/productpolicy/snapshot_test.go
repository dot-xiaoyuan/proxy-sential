package productpolicy

import (
	"testing"
	"time"
)

func TestSnapshotNormalizeAndValidate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	s := Snapshot{SchemaVersion: SchemaVersion, Source: "office-4k", InstanceID: "redis-run", ObservedAt: now, Complete: true,
		Products: []Product{{ID: "3", Name: "办公产品", ControlIDs: []string{"2", "1", "2"}}},
		Controls: []Control{{ID: "2", Name: "宽松策略", MaxOnlineNum: 4}, {ID: "1", Name: "基础策略", MaxOnlineNum: 2}},
	}
	if err := s.NormalizeAndValidate(now); err != nil {
		t.Fatal(err)
	}
	if s.ContentHash == "" || len(s.Products[0].ControlIDs) != 2 || s.Products[0].ControlIDs[0] != "1" {
		t.Fatalf("unexpected normalized snapshot %+v", s)
	}
	s.ContentHash = "bad"
	if err := s.NormalizeAndValidate(now); err == nil {
		t.Fatal("expected content hash mismatch")
	}
}

func TestSnapshotRejectsMissingControlAndNegativeQuota(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	base := Snapshot{SchemaVersion: SchemaVersion, Source: "office-4k", InstanceID: "redis-run", ObservedAt: now, Complete: true, Products: []Product{{ID: "3", Name: "办公产品", ControlIDs: []string{"1"}}}}
	if err := base.NormalizeAndValidate(now); err == nil {
		t.Fatal("expected missing control rejection")
	}
	negative := -1
	base.Products[0].ControlIDs = nil
	base.AntiProxyProfiles = []AntiProxyProfile{{ExternalID: "legacy-1", Name: "旧策略", TargetType: "product", TargetIDs: []string{"3"}, Total: &negative}}
	if err := base.NormalizeAndValidate(now); err == nil {
		t.Fatal("expected negative quota rejection")
	}
}
