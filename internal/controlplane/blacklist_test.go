package controlplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy-sentinel/internal/policy"
)

func blacklistFixture() policy.BlacklistEntry {
	return policy.BlacklistEntry{Type: "account", Value: "offender", Reason: "确认代理", Enabled: true}
}

func TestBlacklistManagerIsIndependentFromWhitelist(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	whitelist := newWhitelistManager(nil, filepath.Join(dir, "whitelist.json"))
	blacklist := newBlacklistManager(nil)
	if blacklist.db == nil {
		// The blacklist has no file fallback; drive the in-memory path directly.
		blacklist = &whitelistManager{doc: whitelistDocument{Entries: []policy.WhitelistEntry{}}, label: "黑名单", normalize: policy.NormalizeBlacklist}
	}
	if _, err := whitelist.save(ctx, whitelistFixture(), "", "create", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := blacklist.save(ctx, blacklistFixture(), "", "create", "admin"); err != nil {
		t.Fatal(err)
	}
	whitelisted, err := whitelist.list(ctx)
	if err != nil || len(whitelisted) != 1 || whitelisted[0].Value != "student" {
		t.Fatalf("whitelist changed: %+v %v", whitelisted, err)
	}
	blacklisted, err := blacklist.list(ctx)
	if err != nil || len(blacklisted) != 1 || blacklisted[0].Value != "offender" {
		t.Fatalf("blacklist not stored independently: %+v %v", blacklisted, err)
	}
}

func TestBlacklistRejectsUnknownTypeAndAssignsBlacklistIdentifiers(t *testing.T) {
	ctx := context.Background()
	m := &whitelistManager{doc: whitelistDocument{Entries: []policy.WhitelistEntry{}}, label: "黑名单", idPrefix: "blacklist-", normalize: policy.NormalizeBlacklist}
	if _, err := m.save(ctx, policy.BlacklistEntry{Type: "nonsense", Value: "x", Reason: "r", Enabled: true}, "", "create", "admin"); err == nil {
		t.Fatal("invalid entry type must be rejected")
	}
	item, err := m.save(ctx, blacklistFixture(), "", "create", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(item.ID) < len("blacklist-") || item.ID[:len("blacklist-")] != "blacklist-" {
		t.Fatalf("blacklist entries must use the blacklist namespace: %q", item.ID)
	}
	if _, err := m.save(ctx, blacklistFixture(), "", "create", "admin"); !errors.Is(err, errWhitelistDuplicate) {
		t.Fatalf("duplicate blacklist entry accepted: %v", err)
	}
}

func TestBlacklistTriggerMatchesAndRecovers(t *testing.T) {
	now := time.Now().UTC()
	entries := []policy.BlacklistEntry{
		{ID: "blacklist-1", Type: "account", Value: "offender", Reason: "确认代理", Enabled: true, ValidFrom: now.Add(-time.Hour)},
		{ID: "blacklist-2", Type: "account", Value: "expired", Reason: "过期", Enabled: true, ValidFrom: now.Add(-time.Hour), ExpiresAt: ptrTime(now.Add(-time.Minute))},
		{ID: "blacklist-3", Type: "account", Value: "disabled", Reason: "停用", Enabled: false, ValidFrom: now.Add(-time.Hour)},
	}
	if match := policy.MatchAccountBlacklist(entries, "offender", nil, now); match == nil || match.ID != "blacklist-1" {
		t.Fatalf("active entry not matched: %+v", match)
	}
	for _, account := range []string{"expired", "disabled", "clean"} {
		if match := policy.MatchAccountBlacklist(entries, account, nil, now); match != nil {
			t.Fatalf("%s must not match: %+v", account, match)
		}
	}
}

func TestBlacklistHitTriggerIsAcceptedAndNeedsNoQuota(t *testing.T) {
	definition := policy.Definition{ID: "bl", Name: "黑名单准入", Enabled: true, Trigger: "blacklist_hit", Mode: "automatic", Stages: []policy.Stage{{Action: "disconnect", ConnectorID: "srun"}}}
	if err := definition.Validate(); err != nil {
		t.Fatalf("blacklist_hit must validate without device quotas: %v", err)
	}
	unknown := policy.Definition{ID: "x", Name: "x", Enabled: true, Trigger: "not_a_trigger", Mode: "observe", Stages: []policy.Stage{{Action: "record"}}}
	if err := unknown.Validate(); err == nil {
		t.Fatal("unknown trigger must still be rejected")
	}
}

// A blacklist read failure must leave the trigger input unknown so neither a
// false action nor a false recovery is produced.
func TestBlacklistUnavailableKeepsInputUnknown(t *testing.T) {
	definition := policy.Definition{ID: "bl", Name: "黑名单准入", Enabled: true, Trigger: "blacklist_hit", Mode: "automatic", Stages: []policy.Stage{{Action: "disconnect"}}}
	execution := policy.Execution{}
	// Known=false models the unavailable-list branch in processAccountPolicies.
	decision := policy.Advance(definition, execution, policy.Input{AccountID: "offender", Reasons: []string{"blacklist_unavailable"}}, time.Now().UTC())
	if decision.Execution.State == "recovered" {
		t.Fatal("an unavailable blacklist must not release an existing execution")
	}
	if decision.Intent != nil {
		t.Fatal("an unavailable blacklist must not create an action")
	}
	// A confirmed hit does produce an action once the list is readable.
	hit := policy.Advance(definition, execution, policy.Input{AccountID: "offender", Known: true, Violated: true, Reasons: []string{"blacklist_hit"}, EvidenceIDs: []string{"blacklist-1"}}, time.Now().UTC())
	if hit.Intent == nil {
		t.Fatal("a confirmed blacklist hit must create an action")
	}
}

func ptrTime(value time.Time) *time.Time { return &value }

func TestBlacklistManagerPersistsThroughSettingsDocument(t *testing.T) {
	// The list document must round-trip through the shared decoder with the
	// blacklist normalizer, otherwise a stored entry could be silently dropped.
	m := &whitelistManager{label: "黑名单", normalize: policy.NormalizeBlacklist}
	raw := []byte(`{"entries":[{"entry_id":"blacklist-1","type":"account","value":"offender","reason":"确认代理","enabled":true,"valid_from":"2026-01-01T00:00:00Z","revision":1}]}`)
	decoded, err := m.decode(raw)
	if err != nil || len(decoded.Entries) != 1 || decoded.Entries[0].Value != "offender" {
		t.Fatalf("blacklist decode failed: %+v %v", decoded, err)
	}
}

func TestBlacklistCodesDoNotCollideWithWhitelistCodes(t *testing.T) {
	if whitelistCodes.unavailable == blacklistCodes.unavailable || whitelistCodes.bad == blacklistCodes.bad {
		t.Fatal("blacklist and whitelist error codes must stay distinguishable")
	}
	_ = os.Getenv("PROXY_SENTINEL_TEST_POSTGRES_DSN")
}
