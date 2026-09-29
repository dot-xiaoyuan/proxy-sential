package appdomain

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testBundle(t *testing.T, version string) []byte {
	t.Helper()
	c := Catalog{Applications: []Target{{ID: "wechat", Name: "微信", Category: "social"}, {ID: "bilibili", Name: "哔哩哔哩", Category: "video"}}}
	rules := []Rule{{ID: "wx", Domain: "weixin.qq.com", MatchType: "suffix", TargetType: "application", TargetID: "wechat", Confidence: .95, Source: "test", SourceVersion: "1"}, {ID: "bili", Domain: "bilibili.com", MatchType: "exact", TargetType: "application", TargetID: "bilibili", Confidence: .95, Source: "test", SourceVersion: "1"}}
	b, err := Build(version, c, rules, []Source{{Name: "test", Version: "1", License: "test-only"}}, map[string][]byte{"licenses/test.txt": []byte("test fixture only")}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestBundleMatchingAndValidation(t *testing.T) {
	b, err := Verify(testBundle(t, "v1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ host, want string }{{"WEIXIN.QQ.COM.", "wechat"}, {"a.weixin.qq.com", "wechat"}, {"fakeweixin.qq.com", ""}, {"weixin.qq.com.evil.com", ""}, {"qq.com", ""}, {"bilibili.com", "bilibili"}, {"a.bilibili.com", ""}} {
		m := b.Match(tt.host)
		if m.TargetID != tt.want {
			t.Errorf("%s: %+v", tt.host, m)
		}
	}
	for _, d := range []string{"com", "co.uk", "127.0.0.1", "a..com"} {
		if _, err := NormalizeDomain(d); err == nil {
			t.Errorf("accepted %s", d)
		}
	}
	b.Rules = append(b.Rules, Rule{ID: "conflict", Domain: "weixin.qq.com", MatchType: "suffix", TargetType: "application", TargetID: "bilibili", Confidence: .9, Source: "test", SourceVersion: "1"})
	if err := b.validate(); err == nil {
		t.Fatal("accepted conflicting rule")
	}
	raw := testBundle(t, "v2")
	raw[len(raw)/2] ^= 0xff
	if _, err := Verify(raw); err == nil {
		t.Fatal("accepted corruption")
	}
}
func TestManagerAtomicRollback(t *testing.T) {
	dir := t.TempDir()
	m, err := OpenManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"v1", "v2", "v3", "v4"} {
		if err := m.Import(testBundle(t, v)); err != nil {
			t.Fatal(err)
		}
	}
	if len(m.Status().Versions) != 3 {
		t.Fatal(m.Status())
	}
	if err := m.Import([]byte("broken")); err == nil {
		t.Fatal("accepted bad import")
	}
	if m.Status().Version != "v4" {
		t.Fatal("lost active version")
	}
	if err := m.Rollback("v2"); err != nil {
		t.Fatal(err)
	}
	again, err := OpenManager(dir)
	if err != nil || again.Status().Version != "v2" {
		t.Fatal(err)
	}
	if err := m.Rollback("../bad"); err == nil {
		t.Fatal("accepted path")
	}
	if _, err := os.Stat(filepath.Join(dir, "active.json")); err != nil {
		t.Fatal(err)
	}
}

func TestFeaturelibSourceIDCompatibility(t *testing.T) {
	var source Source
	if err := json.Unmarshal([]byte(`{"id":"reviewed","version":"v1","license":"MIT"}`), &source); err != nil || source.Name != "reviewed" {
		t.Fatal("featurelib source id missing")
	}
	if err := json.Unmarshal([]byte(`{"id":"reviewed","name":"different"}`), &source); err == nil {
		t.Fatal("conflicting source accepted")
	}
}

func TestReviewedRuleWithUnassessedConfidence(t *testing.T) {
	raw, err := ExampleBundle(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	for i := range b.Rules {
		b.Rules[i].Confidence = 0
	}
	raw, err = Build("unassessed-v1", b.Catalog, b.Rules, b.Manifest.Sources, map[string][]byte{"licenses/NOTICE.txt": []byte("Contract test fixture")}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, err = Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	match := b.Match("weixin.qq.com")
	if match.TargetID != "wechat" || match.Confidence != 0 {
		t.Fatalf("must retain unassessed score: %+v", match)
	}
	b.Rules[0].Confidence = -.01
	if _, err = Build("invalid-v1", b.Catalog, b.Rules, b.Manifest.Sources, map[string][]byte{"licenses/NOTICE.txt": []byte("test")}, time.Now()); err == nil {
		t.Fatal("negative confidence accepted")
	}
}
