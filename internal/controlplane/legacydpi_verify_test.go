package controlplane

import (
	"context"
	"os"
	"testing"
	"time"

	"proxy-sentinel/internal/policy"
)

// TestVerifyMigratedWhitelistReadPath loads the whitelist document exactly as it
// is stored in the control-plane database and runs it through the real read
// path. The read path normalizes and de-duplicates every entry, so a single
// malformed entry would fail the whole list page; this is the check that the
// migrated document renders.
//
//	LEGACY_DPI_STORED_WHITELIST=/tmp/stored-whitelist.json \
//	go test ./internal/controlplane -run TestVerifyMigratedWhitelistReadPath
func TestVerifyMigratedWhitelistReadPath(t *testing.T) {
	path := os.Getenv("LEGACY_DPI_STORED_WHITELIST")
	if path == "" {
		t.Skip("设置 LEGACY_DPI_STORED_WHITELIST 以校验已存储的白名单文档")
	}
	manager := newWhitelistManager(nil, path)
	entries, err := manager.list(context.Background())
	if err != nil {
		t.Fatalf("白名单读取路径失败（页面会报错）: %v", err)
	}
	if len(entries) != 18 {
		t.Fatalf("读取到 %d 条白名单, 期望 18", len(entries))
	}

	now := time.Now().UTC()
	counts := map[string]int{}
	for _, entry := range entries {
		counts[entry.Type]++
		if !entry.Active(now) {
			t.Fatalf("白名单 %s (%s) 读取后不生效", entry.ID, entry.Value)
		}
		if entry.Reason == "" {
			t.Fatalf("白名单 %s 缺少原因", entry.ID)
		}
	}
	for kind, want := range map[string]int{"mac": 8, "account": 6, "network": 4} {
		if counts[kind] != want {
			t.Fatalf("白名单类型 %s = %d 条, 期望 %d", kind, counts[kind], want)
		}
	}

	// Matching proves the stored values are usable, including the MAC form the
	// legacy system compared byte-for-byte and therefore never actually matched.
	cases := []struct {
		name    string
		subject policy.WhitelistSubject
	}{
		{"MAC 大写短横线写法", policy.WhitelistSubject{MAC: "00-5C-C2-C7-A2-07"}},
		{"MAC 小写冒号写法", policy.WhitelistSubject{MAC: "00:5c:c2:c7:a2:07"}},
		{"账号命中", policy.WhitelistSubject{AccountID: "067735"}},
		{"网段命中", policy.WhitelistSubject{IP: "10.202.31.7"}},
	}
	for _, tc := range cases {
		if policy.MatchWhitelist(entries, tc.subject, now) == nil {
			t.Fatalf("%s 未命中白名单", tc.name)
		}
	}

	// A negative control: an address outside every migrated range must not match.
	if match := policy.MatchWhitelist(entries, policy.WhitelistSubject{IP: "10.211.1.1"}, now); match != nil {
		t.Fatalf("范围外地址命中了白名单条目 %s", match.ID)
	}
}
