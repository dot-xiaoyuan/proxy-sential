package controlplane

import (
	"net/http"
	"testing"
	"time"
)

func TestNormalizeAssetTargetKey(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"AA:BB:CC:DD:EE:FF", "mac:aa:bb:cc:dd:ee:ff", true},
		{"mac:00-11-22-33-44-55", "mac:00:11:22:33:44:55", true},
		{"10.42.0.10", "ip:10.42.0.10", true},
		{"ip:172.24.16.8", "ip:172.24.16.8", true},
		{"invalid-target", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := normalizeAssetTargetKey(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("normalizeAssetTargetKey(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestAssetGovernanceMutationGuard(t *testing.T) {
	t.Setenv("PROXY_SENTINEL_ASSET_ANNOTATIONS_WRITE", "")
	locked := &Server{readOnly: true, assetAnnotationsWrite: false}
	if locked.assetGovernanceMutationAllowed(http.MethodPut, "/discovery/annotations") {
		t.Fatal("全局只读且未开启资产标注轻写时应拒绝 PUT /discovery/annotations")
	}
	if locked.assetGovernanceMutationAllowed(http.MethodPost, "/discovery/ledgers") {
		t.Fatal("全局只读且未开启资产标注轻写时应拒绝 POST /discovery/ledgers")
	}

	scoped := &Server{readOnly: true, assetAnnotationsWrite: true}
	if !scoped.assetGovernanceMutationAllowed(http.MethodPut, "/discovery/annotations") {
		t.Fatal("开启资产标注轻写后应允许 PUT /discovery/annotations")
	}
	if !scoped.assetGovernanceMutationAllowed(http.MethodDelete, "/discovery/annotations") {
		t.Fatal("开启资产标注轻写后应允许 DELETE /discovery/annotations")
	}
	if !scoped.assetGovernanceMutationAllowed(http.MethodPost, "/discovery/ledgers") {
		t.Fatal("开启资产标注轻写后应允许 POST /discovery/ledgers")
	}
	if !scoped.assetGovernanceMutationAllowed(http.MethodDelete, "/discovery/ledgers/ledger-123") {
		t.Fatal("开启资产标注轻写后应允许 DELETE /discovery/ledgers/{id}")
	}
	// 非资产运营路由必须继续受全局只读硬锁保护
	if scoped.assetGovernanceMutationAllowed(http.MethodPost, "/policies") {
		t.Fatal("策略配置路由绝不能被资产标注白名单放行")
	}
	if scoped.assetGovernanceMutationAllowed(http.MethodPost, "/discovery/scan-profiles") {
		t.Fatal("主动扫描配置路由绝不能被资产标注白名单放行")
	}
}

func TestAssetGovernancePermissions(t *testing.T) {
	if got := requiredPermission(http.MethodGet, "/discovery/annotations"); got != "identity:read" {
		t.Fatalf("GET /discovery/annotations permission = %q, want identity:read", got)
	}
	if got := requiredPermission(http.MethodPut, "/discovery/annotations"); got != "endpoints:write" {
		t.Fatalf("PUT /discovery/annotations permission = %q, want endpoints:write", got)
	}
	if got := requiredPermission(http.MethodPost, "/discovery/ledgers"); got != "endpoints:write" {
		t.Fatalf("POST /discovery/ledgers permission = %q, want endpoints:write", got)
	}
	if got := requiredPermission(http.MethodDelete, "/discovery/ledgers/ledger-1"); got != "endpoints:write" {
		t.Fatalf("DELETE /discovery/ledgers permission = %q, want endpoints:write", got)
	}
	if got := requiredPermission(http.MethodPost, "/discovery/scan-profiles"); got != "integrations:write" {
		t.Fatalf("POST /discovery/scan-profiles permission = %q, want integrations:write", got)
	}
}

func TestReconcileAssetLedgerFourQuadrants(t *testing.T) {
	ledger := AssetLedgerSnapshot{
		LedgerID:   "ledger-ap-001",
		Name:       "教学楼瘦AP台账",
		SourceKind: "ac_ap",
		EntryCount: 3,
	}
	entries := []AssetLedgerEntry{
		{
			IP:             "10.10.1.11",
			AssetName:      "教1-101-AP",
			ExpectedType:   "access_point",
			ExpectedVendor: "Ruijie",
			Department:     "网络中心",
		},
		{
			MAC:            "aa:bb:cc:dd:ee:02",
			AssetName:      "教1-102-AP",
			ExpectedType:   "access_point",
			ExpectedVendor: "Ruijie",
		},
		{
			IP:           "10.10.1.13",
			AssetName:    "教1-103-离线AP",
			ExpectedType: "access_point",
		},
	}
	observed := []AssetReconcileObserved{
		// 1. 跨三层 CAPWAP AP（无 MAC，靠 IP 精确匹配 -> registered_active）
		{Key: "ip:10.10.1.11", IP: "10.10.1.11", ObservedType: "access_point", IdentityKind: "l3_managed_entity", LastSeen: "2026-11-26T11:00:00Z"},
		// 2. MAC 匹配但品类不符（台账记 AP，被动观测为 router -> attribute_mismatch）
		{Key: "mac:aa:bb:cc:dd:ee:02", MAC: "aa:bb:cc:dd:ee:02", IP: "10.10.1.12", ObservedType: "router", IdentityKind: "device", LastSeen: "2026-11-26T11:01:00Z"},
		// 3. 被动发现的新 AP 不在台账中 -> discovered_unregistered
		{Key: "ip:10.10.1.99", IP: "10.10.1.99", ObservedType: "access_point", IdentityKind: "l3_managed_entity", LastSeen: "2026-11-26T11:05:00Z"},
		// 4. 学生手机不应混入 ac_ap 专项台账的未登记清单
		{Key: "mac:12:34:56:78:9a:bc", MAC: "12:34:56:78:9a:bc", IP: "10.20.3.4", ObservedType: "phone", IdentityKind: "device", LastSeen: "2026-11-26T11:06:00Z"},
	}

	resp := reconcileAssetLedger(ledger, "24h", entries, observed, time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC))
	if resp.Summary.LedgerTotal != 3 || resp.Summary.ObservedTotal != 4 {
		t.Fatalf("unexpected totals: %+v", resp.Summary)
	}
	if resp.Summary.RegisteredActive != 1 {
		t.Fatalf("RegisteredActive = %d, want 1", resp.Summary.RegisteredActive)
	}
	if resp.Summary.AttributeMismatch != 1 {
		t.Fatalf("AttributeMismatch = %d, want 1", resp.Summary.AttributeMismatch)
	}
	if resp.Summary.LedgerOffline != 1 {
		t.Fatalf("LedgerOffline = %d, want 1", resp.Summary.LedgerOffline)
	}
	if resp.Summary.DiscoveredUnregistered != 1 {
		t.Fatalf("DiscoveredUnregistered = %d, want 1 (phone should be excluded for ac_ap scope)", resp.Summary.DiscoveredUnregistered)
	}
	if len(resp.Items) != 4 {
		t.Fatalf("len(Items) = %d, want 4", len(resp.Items))
	}
}
