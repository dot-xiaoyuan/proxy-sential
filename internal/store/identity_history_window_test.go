package store

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseIdentityHistoryWindowContract(t *testing.T) {
	for _, test := range []struct {
		name    string
		raw     string
		want    time.Duration
		wantErr bool
	}{
		{"unset uses the default window", "", defaultIdentityHistoryWindow, false},
		{"zero disables windows", "0", 0, false},
		{"off disables windows", "off", 0, false},
		{"false disables windows", "false", 0, false},
		{"explicit window", "30m", 30 * time.Minute, false},
		{"shorter window", "5m", 5 * time.Minute, false},
		{"unparseable is refused", "soon", 0, true},
		{"negative is refused", "-5m", 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseIdentityHistoryWindow(test.raw)
			if (err != nil) != test.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("parseIdentityHistoryWindow(%q)=%s, want %s", test.raw, got, test.want)
			}
		})
	}
}

func TestIdentityHistoryWindowDefaultsOnInvalidValue(t *testing.T) {
	defer resetIdentityHistoryWindowForTest()
	resetIdentityHistoryWindowForTest()
	t.Setenv(identityHistoryWindowEnv, "not-a-duration")
	if got := identityHistoryWindow(); got != defaultIdentityHistoryWindow {
		t.Fatalf("invalid value must fall back to the default window, got %s", got)
	}
}

func TestIdentityHistoryWindowCanBeDisabled(t *testing.T) {
	defer resetIdentityHistoryWindowForTest()
	resetIdentityHistoryWindowForTest()
	t.Setenv(identityHistoryWindowEnv, "0")
	if got := identityHistoryWindow(); got != 0 {
		t.Fatalf("zero must disable window collapsing, got %s", got)
	}
}

func observationKey(endpointID, ip, mac string) string {
	return bindingKey(endpointID, "", ip, mac)
}

// A continuously present binding must be able to extend its stored window. The head
// horizon used to be measured from time.Now() while the extend test measures from the
// observation, and observations always lag now, so no head could ever satisfy both and
// every window re-inserted a row instead of extending it.
func TestBindingHeadCutoffKeepsHeadOneWindowOld(t *testing.T) {
	window := 30 * time.Minute
	observed := time.Date(2026, 10, 14, 20, 0, 0, 0, time.UTC)
	rows := []IdentityIPMACHistory{
		{LastSeen: observed.Format(time.RFC3339Nano)},
		{LastSeen: observed.Add(-5 * time.Minute).Format(time.RFC3339Nano)},
	}
	if anchor := bindingAnchor(rows, func(row IdentityIPMACHistory) string { return row.LastSeen }); !anchor.Equal(observed) {
		t.Fatalf("anchor=%s, want the newest observation %s", anchor, observed)
	}
	cutoff := bindingHeadCutoff(observed, window)
	head := storedWindow{EventID: "window-a", LastSeen: observed.Add(-window)}
	stored := map[string]storedWindow{}
	if !head.LastSeen.Before(cutoff) {
		stored[observationKey("mac:aa", "10.0.0.1", "aa")] = head
	}
	plan := planBindingWindows(stored, []bindingObservation{
		{Key: observationKey("mac:aa", "10.0.0.1", "aa"), LastSeen: observed.Format(time.RFC3339Nano)},
	}, window)
	if len(plan.ExtendEventID) != 1 || plan.ExtendEventID[0] != "window-a" || len(plan.InsertIndexes) != 0 {
		t.Fatalf("continuous binding did not extend its window: %+v", plan)
	}
	// A gap wider than the head horizon still opens a new row, which is what makes the
	// history readable as a sequence of presence windows.
	gap := map[string]storedWindow{}
	old := storedWindow{EventID: "window-old", LastSeen: observed.Add(-identityBindingGapFactor*window - time.Minute)}
	if !old.LastSeen.Before(cutoff) {
		gap[observationKey("mac:bb", "10.0.0.2", "bb")] = old
	}
	plan = planBindingWindows(gap, []bindingObservation{
		{Key: observationKey("mac:bb", "10.0.0.2", "bb"), LastSeen: observed.Format(time.RFC3339Nano)},
	}, window)
	if len(plan.InsertIndexes) != 1 || len(plan.ExtendEventID) != 0 {
		t.Fatalf("gap did not open a new window: %+v", plan)
	}
}

func TestPlanBindingWindowsSplitsNewExtendAndUnchanged(t *testing.T) {
	window := 30 * time.Minute
	now := time.Now().UTC()
	stored := map[string]storedWindow{
		// Continuously present binding: the stored window is recent and the new observation
		// is only inside the following window, so it must not rewrite the row.
		observationKey("mac:aa", "10.0.0.1", "aa"): {EventID: "window-a", LastSeen: now.Add(-20 * time.Minute)},
		// Roaming binding: the stored window has not been extended for more than a window,
		// so the new observation extends it.
		observationKey("mac:bb", "10.0.0.2", "bb"): {EventID: "window-b", LastSeen: now.Add(-45 * time.Minute)},
	}
	plan := planBindingWindows(stored, []bindingObservation{
		{Key: observationKey("mac:aa", "10.0.0.1", "aa"), LastSeen: now.Format(time.RFC3339Nano)},
		{Key: observationKey("mac:bb", "10.0.0.2", "bb"), LastSeen: now.Format(time.RFC3339Nano)},
		{Key: observationKey("mac:cc", "10.0.0.3", "cc"), LastSeen: now.Format(time.RFC3339Nano)},
		{Key: observationKey("mac:dd", "10.0.0.4", "dd"), LastSeen: "not-a-timestamp"},
	}, window)
	if len(plan.InsertIndexes) != 2 || plan.InsertIndexes[0] != 2 || plan.InsertIndexes[1] != 3 {
		t.Fatalf("inserts=%v, want the unknown binding and the unparseable observation", plan.InsertIndexes)
	}
	if len(plan.ExtendEventID) != 1 || plan.ExtendEventID[0] != "window-b" {
		t.Fatalf("extends=%v, want the stored window of the roaming binding", plan.ExtendEventID)
	}
	if plan.Unchanged != 1 {
		t.Fatalf("unchanged=%d, want the continuously present binding to be skipped", plan.Unchanged)
	}
}

func TestPlanBindingWindowsWithoutStoredWindowInserts(t *testing.T) {
	plan := planBindingWindows(nil, []bindingObservation{
		{Key: observationKey("mac:aa", "10.0.0.1", "aa"), LastSeen: time.Now().UTC().Format(time.RFC3339Nano)},
	}, time.Hour)
	if len(plan.InsertIndexes) != 1 || len(plan.ExtendEventID) != 0 || plan.Unchanged != 0 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
}

func TestCollapseIPMACHistoryMergesBindings(t *testing.T) {
	base := time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC)
	items := []IdentityIPMACHistory{
		{EventID: "event-2", EndpointID: "mac:aa", IP: "10.0.0.1", MAC: "aa", Source: "dhcp", FirstSeen: base.Add(time.Minute).Format(time.RFC3339Nano), LastSeen: base.Add(time.Minute).Format(time.RFC3339Nano), IdentityConfidence: .5},
		{EventID: "event-1", EndpointID: "mac:aa", IP: "10.0.0.1", MAC: "aa", Source: "dhcp", FirstSeen: base.Format(time.RFC3339Nano), LastSeen: base.Format(time.RFC3339Nano), IdentityConfidence: .9},
		{EventID: "event-3", EndpointID: "mac:aa", IP: "10.0.0.9", MAC: "aa", Source: "dhcp", FirstSeen: base.Format(time.RFC3339Nano), LastSeen: base.Format(time.RFC3339Nano)},
		{EventID: "event-4", EndpointID: "", AccountID: "", IP: "10.0.0.4", MAC: "dd", Source: "dhcp", FirstSeen: base.Format(time.RFC3339Nano), LastSeen: base.Format(time.RFC3339Nano)},
		{EventID: "", EndpointID: "mac:ee", IP: "10.0.0.5", MAC: "ee", Source: "dhcp", FirstSeen: base.Format(time.RFC3339Nano), LastSeen: base.Format(time.RFC3339Nano)},
	}
	rows := collapseIPMACHistory(items)
	if len(rows) != 2 {
		t.Fatalf("collapsed rows=%d, want one row per binding and no unreadable row: %+v", len(rows), rows)
	}
	if rows[0].EventID != "event-1" || rows[1].EventID != "event-3" {
		t.Fatalf("rows must be ordered by event id, got %q and %q", rows[0].EventID, rows[1].EventID)
	}
	merged := rows[0]
	if merged.FirstSeen != base.Format(time.RFC3339Nano) {
		t.Fatalf("merged first_seen=%s, want the earliest observation", merged.FirstSeen)
	}
	if merged.LastSeen != base.Add(time.Minute).Format(time.RFC3339Nano) {
		t.Fatalf("merged last_seen=%s, want the latest observation", merged.LastSeen)
	}
	if merged.IdentityConfidence != .9 {
		t.Fatalf("merged confidence=%v, want the strongest observation", merged.IdentityConfidence)
	}
}

func TestCollapseAccessHistoryMergesByAccessID(t *testing.T) {
	base := time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC)
	rows := collapseAccessHistory([]IdentityAccessHistory{
		{EventID: "event-1", EndpointID: "mac:aa", AccessID: "ap-1", FirstSeen: base.Format(time.RFC3339Nano), LastSeen: base.Format(time.RFC3339Nano)},
		{EventID: "event-2", EndpointID: "mac:aa", AccessID: "ap-1", FirstSeen: base.Add(time.Minute).Format(time.RFC3339Nano), LastSeen: base.Add(2 * time.Minute).Format(time.RFC3339Nano)},
		{EventID: "event-3", EndpointID: "mac:aa", AccessID: "", FirstSeen: base.Format(time.RFC3339Nano), LastSeen: base.Format(time.RFC3339Nano)},
	})
	if len(rows) != 1 || rows[0].LastSeen != base.Add(2*time.Minute).Format(time.RFC3339Nano) {
		t.Fatalf("unexpected collapse result: %+v", rows)
	}
}

// The identity write path must not go back to one statement per event: that shape is what
// the field could not keep up with. These guards fail loudly if a per-item loop returns.
func TestIdentityWritePathUsesBatchedStatements(t *testing.T) {
	source, err := os.ReadFile("postgresstore.go")
	if err != nil {
		t.Fatal(err)
	}
	code := string(source)
	for _, removed := range []string{"upsertIdentityIPMACHistory(", "upsertIdentityAccessHistory(", "upsertEndpointEntity(", "upsertInfrastructureEntity(", "upsertAccountSession(", "upsertDeviceSignalFact("} {
		if strings.Contains(code, removed) {
			t.Fatalf("identity write path must stay batched; %s reappeared", removed)
		}
	}
	state := functionBody(t, code, "writeIdentityState")
	if strings.Contains(state, "for ") {
		t.Fatalf("writeIdentityState must delegate to batched helpers, not loop:\n%s", state)
	}
	for _, fragment := range []string{"attachEndpointAttributes(", "upsertEndpointDeviceProfilesBatch("} {
		if body := functionBody(t, code, "writeEndpointDeviceProfiles"); !strings.Contains(body, fragment) {
			t.Fatalf("writeEndpointDeviceProfiles must call %s", fragment)
		}
	}
}

func TestIdentityBatchWriteCoversEveryHotTable(t *testing.T) {
	source, err := os.ReadFile("identity_batch_write.go")
	if err != nil {
		t.Fatal(err)
	}
	code := string(source)
	for _, table := range []string{
		"identity_ip_mac_history",
		"identity_access_history",
		"endpoint_entities",
		"infrastructure_entities",
		"account_sessions",
		"device_address_leases",
		"endpoint_device_profiles",
		"policy_identity_observations",
		"device_signal_facts",
		"device_signal_events",
	} {
		if !strings.Contains(code, table) {
			t.Fatalf("batched write layer does not cover %s", table)
		}
	}
	if count := strings.Count(code, "FROM unnest("); count < 8 {
		t.Fatalf("expected the batched layer to use unnest for every table, found %d", count)
	}
}

func TestQueueWritersDelegateToBatches(t *testing.T) {
	policy, err := os.ReadFile("policy_identity.go")
	if err != nil {
		t.Fatal(err)
	}
	leases, err := os.ReadFile("device_lease.go")
	if err != nil {
		t.Fatal(err)
	}
	if body := functionBody(t, string(policy), "writePolicyIdentityEvents"); strings.Contains(body, "ExecContext(") {
		t.Fatalf("writePolicyIdentityEvents must delegate to the batched insert:\n%s", body)
	}
	if body := functionBody(t, string(leases), "writeDeviceLeases"); strings.Contains(body, "ExecContext(") {
		t.Fatalf("writeDeviceLeases must delegate to the batched insert:\n%s", body)
	}
}

// functionBody returns the source of a top-level function, up to the closing brace.
func functionBody(t *testing.T, source, name string) string {
	t.Helper()
	marker := "func " + name + "("
	start := strings.Index(source, marker)
	if start < 0 {
		source = strings.TrimPrefix(source, "")
		marker = "func (s *DBStore) " + name + "("
		start = strings.Index(source, marker)
	}
	if start < 0 {
		marker = "func (s *PostgresStore) " + name + "("
		start = strings.Index(source, marker)
	}
	if start < 0 {
		t.Fatalf("function %s not found", name)
	}
	rest := source[start:]
	if end := strings.Index(rest, "\n}\n"); end >= 0 {
		return rest[:end]
	}
	return rest
}
