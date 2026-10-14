package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// PROXY_SENTINEL_IDENTITY_HISTORY_WINDOW collapses repeated observations of the same
// identity binding into one history window.
//
// The field showed why this is required: a single sensor observed 57,408,048 identity
// events in 24 hours that mapped to only 59,962 MACs and 282,757 (ip, mac) bindings, about
// 203 observations per binding. Writing one identity_ip_mac_history row per observation put
// ~57M rows/day into a table that already held 11.7M rows across 6.8 GB of indexes, and the
// materializer could not write even 1% of that.
//
// Semantics with a window (default 30m):
//   - observations of the same binding inside the window extend the stored window, and only
//     once the extension spans a whole window, so a continuously present binding costs about
//     one row update per window instead of one per observation;
//   - an observation after a gap longer than the window opens a new row, which is what makes
//     a binding history readable as a sequence of presence windows.
//
// Setting the value to 0 or "off" restores one row per observation (the pre-window
// behaviour) without a redeploy.
const (
	identityHistoryWindowEnv = "PROXY_SENTINEL_IDENTITY_HISTORY_WINDOW"
	// defaultIdentityHistoryWindow matches the device list's "historical addresses" horizon:
	// readers ask for recently used addresses and the newest bindings per endpoint.
	defaultIdentityHistoryWindow = 30 * time.Minute
)

var identityHistoryWindowCache struct {
	sync.Mutex
	loaded bool
	value  time.Duration
}

// parseIdentityHistoryWindow is the pure form of the environment contract. An unset or
// empty value means the default window; only an explicit 0/off/false turns collapsing off.
func parseIdentityHistoryWindow(raw string) (time.Duration, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return defaultIdentityHistoryWindow, nil
	}
	if trimmed == "0" || trimmed == "off" || trimmed == "false" {
		return 0, nil
	}
	value, err := time.ParseDuration(trimmed)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", identityHistoryWindowEnv, raw, err)
	}
	if value < 0 {
		return 0, fmt.Errorf("%s %q must not be negative", identityHistoryWindowEnv, raw)
	}
	return value, nil
}

// identityHistoryWindow reads the configured window once per process. An invalid value is
// reported and leaves the default window in place.
func identityHistoryWindow() time.Duration {
	identityHistoryWindowCache.Lock()
	defer identityHistoryWindowCache.Unlock()
	if identityHistoryWindowCache.loaded {
		return identityHistoryWindowCache.value
	}
	raw := os.Getenv(identityHistoryWindowEnv)
	value, err := parseIdentityHistoryWindow(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "identity history window: %v; using default %s\n", err, defaultIdentityHistoryWindow)
		value = defaultIdentityHistoryWindow
	}
	if value > 0 {
		fmt.Fprintf(os.Stderr, "identity history windows enabled: %s (%s=%s)\n", value, identityHistoryWindowEnv, value)
	} else {
		fmt.Fprintf(os.Stderr, "identity history windows disabled: one row per observation (%s=%q)\n", identityHistoryWindowEnv, raw)
	}
	identityHistoryWindowCache.loaded, identityHistoryWindowCache.value = true, value
	return value
}

func resetIdentityHistoryWindowForTest() {
	identityHistoryWindowCache.Lock()
	defer identityHistoryWindowCache.Unlock()
	identityHistoryWindowCache.loaded, identityHistoryWindowCache.value = false, 0
}

// identityHistoryStats reports what a batch did to the history tables.
type identityHistoryStats struct {
	HistoryRows     int
	WindowInserts   int
	WindowExtends   int
	WindowUnchanged int
}

// bindingKey identifies one presence window. The address parts are canonicalized the same
// way PostgreSQL stores them (an inet column holds the parsed form, a MAC is stored as the
// text the fact carries), so a stored window is found again for IPv6 or mixed-case input.
// Rows without any identity are unreadable by every reader (they all filter on endpoint_id
// or account_id), so windows are only opened for rows that carry one.
func bindingKey(endpointID, accountID, ip, mac string) string {
	if address, err := netip.ParseAddr(strings.TrimSpace(ip)); err == nil {
		ip = address.Unmap().String()
	}
	return endpointID + "\x00" + accountID + "\x00" + ip + "\x00" + strings.ToLower(strings.TrimSpace(mac))
}

func bindingHasIdentity(endpointID, accountID string) bool {
	return endpointID != "" || accountID != ""
}

// collapseIPMACHistory merges the batch's observations into binding windows. The returned
// rows carry the union of the observed interval, which is what a window row means.
func collapseIPMACHistory(items []IdentityIPMACHistory) []IdentityIPMACHistory {
	merged := map[string]int{}
	out := make([]IdentityIPMACHistory, 0, len(items))
	for _, item := range items {
		if item.EventID == "" || !bindingHasIdentity(item.EndpointID, item.AccountID) {
			continue
		}
		key := bindingKey(item.EndpointID, item.AccountID, item.IP, item.MAC)
		index, ok := merged[key]
		if !ok {
			merged[key] = len(out)
			out = append(out, item)
			continue
		}
		current := &out[index]
		// The earliest observation names the window, so the merged row is the same
		// whichever order the batch happened to arrive in.
		if item.FirstSeen != "" && (current.FirstSeen == "" || item.FirstSeen < current.FirstSeen) {
			current.EventID = item.EventID
			current.FirstSeen = item.FirstSeen
			current.EntityRole = item.EntityRole
			current.Source = item.Source
		}
		if item.LastSeen > current.LastSeen {
			current.LastSeen = item.LastSeen
		}
		if item.IdentityConfidence > current.IdentityConfidence {
			current.IdentityConfidence = item.IdentityConfidence
		}
		if current.Source == "" {
			current.Source = item.Source
		}
	}
	// Deterministic statement order: the conflict keys are written in sorted order so
	// concurrent writers take row locks in the same sequence.
	sort.SliceStable(out, func(i, j int) bool { return out[i].EventID < out[j].EventID })
	return out
}

func collapseAccessHistory(items []IdentityAccessHistory) []IdentityAccessHistory {
	merged := map[string]int{}
	out := make([]IdentityAccessHistory, 0, len(items))
	for _, item := range items {
		if item.EventID == "" || item.AccessID == "" || !bindingHasIdentity(item.EndpointID, item.AccountID) {
			continue
		}
		key := bindingKey(item.EndpointID, item.AccountID, item.AccessID, "")
		index, ok := merged[key]
		if !ok {
			merged[key] = len(out)
			out = append(out, item)
			continue
		}
		current := &out[index]
		if item.FirstSeen != "" && (current.FirstSeen == "" || item.FirstSeen < current.FirstSeen) {
			current.EventID = item.EventID
			current.FirstSeen = item.FirstSeen
			current.EntityRole = item.EntityRole
			current.Source = item.Source
		}
		if item.LastSeen > current.LastSeen {
			current.LastSeen = item.LastSeen
		}
		if item.IdentityConfidence > current.IdentityConfidence {
			current.IdentityConfidence = item.IdentityConfidence
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].EventID < out[j].EventID })
	return out
}

// storedWindow is the newest stored window for one binding key.
type storedWindow struct {
	EventID  string
	LastSeen time.Time
}

// writeIdentityIPMACHistory writes the batch's binding windows.
func writeIdentityIPMACHistory(ctx context.Context, tx *sql.Tx, items []IdentityIPMACHistory) (identityHistoryStats, error) {
	return writeBindingWindows(ctx, tx, items, identityHistoryWindow())
}

func writeIdentityAccessHistory(ctx context.Context, tx *sql.Tx, items []IdentityAccessHistory) (identityHistoryStats, error) {
	return writeAccessBindingWindows(ctx, tx, items, identityHistoryWindow())
}

// writeBindingWindows applies the window policy for one history table.
func writeBindingWindows(ctx context.Context, tx *sql.Tx, items []IdentityIPMACHistory, window time.Duration) (identityHistoryStats, error) {
	stats := identityHistoryStats{}
	rows := items
	if window > 0 {
		rows = collapseIPMACHistory(items)
	} else {
		rows = append([]IdentityIPMACHistory(nil), items...)
	}
	if len(rows) == 0 {
		return stats, nil
	}
	stats.HistoryRows = len(rows)
	if window <= 0 {
		stats.WindowInserts = len(rows)
		return stats, insertIPMACHistoryBatch(ctx, tx, rows)
	}
	stored, err := storedIPMACWindows(ctx, tx, rows, window)
	if err != nil {
		return stats, err
	}
	observations := make([]bindingObservation, 0, len(rows))
	for _, row := range rows {
		observations = append(observations, bindingObservation{
			Key:      bindingKey(row.EndpointID, row.AccountID, row.IP, row.MAC),
			LastSeen: row.LastSeen,
		})
	}
	plan := planBindingWindows(stored, observations, window)
	stats.WindowExtends = len(plan.ExtendEventID)
	stats.WindowUnchanged = plan.Unchanged
	stats.WindowInserts = len(plan.InsertIndexes)
	if err = insertIPMACHistoryBatch(ctx, tx, pickIPMACRows(rows, plan.InsertIndexes)); err != nil {
		return stats, err
	}
	if err = extendIPMACHistoryWindows(ctx, tx, plan.ExtendEventID, plan.ExtendLastSeen); err != nil {
		return stats, err
	}
	ids := make([]string, len(rows))
	for i, row := range rows {
		ids[i] = row.EventID
	}
	return stats, saveBindingHeads(ctx, tx, "ip_mac", observations, ids, stored, plan)
}

func writeAccessBindingWindows(ctx context.Context, tx *sql.Tx, items []IdentityAccessHistory, window time.Duration) (identityHistoryStats, error) {
	stats := identityHistoryStats{}
	rows := items
	if window > 0 {
		rows = collapseAccessHistory(items)
	} else {
		rows = append([]IdentityAccessHistory(nil), items...)
	}
	if len(rows) == 0 {
		return stats, nil
	}
	stats.HistoryRows = len(rows)
	if window <= 0 {
		stats.WindowInserts = len(rows)
		return stats, insertAccessHistoryBatch(ctx, tx, rows)
	}
	stored, err := storedAccessWindows(ctx, tx, rows, window)
	if err != nil {
		return stats, err
	}
	observations := make([]bindingObservation, 0, len(rows))
	for _, row := range rows {
		observations = append(observations, bindingObservation{
			Key:      bindingKey(row.EndpointID, row.AccountID, row.AccessID, ""),
			LastSeen: row.LastSeen,
		})
	}
	plan := planBindingWindows(stored, observations, window)
	stats.WindowExtends = len(plan.ExtendEventID)
	stats.WindowUnchanged = plan.Unchanged
	stats.WindowInserts = len(plan.InsertIndexes)
	if err = insertAccessHistoryBatch(ctx, tx, pickAccessRows(rows, plan.InsertIndexes)); err != nil {
		return stats, err
	}
	if err = extendAccessHistoryWindows(ctx, tx, plan.ExtendEventID, plan.ExtendLastSeen); err != nil {
		return stats, err
	}
	ids := make([]string, len(rows))
	for i, row := range rows {
		ids[i] = row.EventID
	}
	return stats, saveBindingHeads(ctx, tx, "access", observations, ids, stored, plan)
}

// bindingObservation is one batch observation reduced to what the window policy needs.
type bindingObservation struct {
	Key      string
	LastSeen string
}

// bindingPlan splits a batch into rows that open a new window and windows to extend.
type bindingPlan struct {
	InsertIndexes  []int
	ExtendEventID  []string
	ExtendLastSeen []time.Time
	Unchanged      int
}

// planBindingWindows applies the window policy. A row whose observation is newer than the
// stored window by at least one window extends it; an observation inside the same window is
// left alone so a continuously present binding does not rewrite the last_seen indexes on
// every observation; a binding with no stored window, or one whose stored window is old
// enough to count as a gap (storedIPMACWindows only returns windows inside the horizon),
// opens a new row.
func planBindingWindows(stored map[string]storedWindow, observations []bindingObservation, window time.Duration) bindingPlan {
	plan := bindingPlan{}
	for index, observation := range observations {
		observed, ok := parseTime(observation.LastSeen)
		if !ok {
			plan.InsertIndexes = append(plan.InsertIndexes, index)
			continue
		}
		current, found := stored[observation.Key]
		if !found {
			plan.InsertIndexes = append(plan.InsertIndexes, index)
			continue
		}
		if observed.UTC().Sub(current.LastSeen) >= window {
			plan.ExtendEventID = append(plan.ExtendEventID, current.EventID)
			plan.ExtendLastSeen = append(plan.ExtendLastSeen, observed.UTC())
			continue
		}
		plan.Unchanged++
	}
	return plan
}

func pickIPMACRows(rows []IdentityIPMACHistory, indexes []int) []IdentityIPMACHistory {
	out := make([]IdentityIPMACHistory, 0, len(indexes))
	for _, index := range indexes {
		if index >= 0 && index < len(rows) {
			out = append(out, rows[index])
		}
	}
	return out
}

func pickAccessRows(rows []IdentityAccessHistory, indexes []int) []IdentityAccessHistory {
	out := make([]IdentityAccessHistory, 0, len(indexes))
	for _, index := range indexes {
		if index >= 0 && index < len(rows) {
			out = append(out, rows[index])
		}
	}
	return out
}

// bindingAnchor 是批内最新的观测时间，作为窗口判定与头部有效期的共同基准。
// 观测总是滞后 now，用 now 作基准会与“延长一个窗口”的条件互斥，详见 bindingHeadCutoff。
func bindingAnchor[T any](rows []T, lastSeen func(T) string) time.Time {
	anchor := time.Time{}
	for _, row := range rows {
		at, ok := parseTime(lastSeen(row))
		if !ok {
			continue
		}
		if at.UTC().After(anchor) {
			anchor = at.UTC()
		}
	}
	if anchor.IsZero() {
		return time.Now().UTC()
	}
	return anchor
}

// storedIPMACWindows probes one compact head per complete binding key. It never
// scans the evidence history while an entity write lock is held. History remains
// available for evidence and detail pages; heads only drive window coalescing.
func storedIPMACWindows(ctx context.Context, tx *sql.Tx, rows []IdentityIPMACHistory, window time.Duration) (map[string]storedWindow, error) {
	keys := make([]string, 0, len(rows))
	for _, row := range rows {
		keys = append(keys, bindingKey(row.EndpointID, row.AccountID, row.IP, row.MAC))
	}
	anchor := bindingAnchor(rows, func(row IdentityIPMACHistory) string { return row.LastSeen })
	return readBindingHeads(ctx, tx, "ip_mac", keys, window, anchor)
}

// distinctValues collects the non-empty values of one key part, without duplicates.
func distinctValues[T any](rows []T, value func(T) string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		item := value(row)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

// collectStoredWindows folds candidate rows into the newest window per binding key.
func collectStoredWindows(rows *sql.Rows, stored map[string]storedWindow) error {
	defer rows.Close()
	for rows.Next() {
		var eventID, endpointID, accountID, ip, mac string
		var lastSeen time.Time
		if err := rows.Scan(&eventID, &endpointID, &accountID, &ip, &mac, &lastSeen); err != nil {
			return err
		}
		key := bindingKey(endpointID, accountID, ip, mac)
		current, found := stored[key]
		if found && !lastSeen.UTC().After(current.LastSeen) {
			continue
		}
		stored[key] = storedWindow{EventID: eventID, LastSeen: lastSeen.UTC()}
	}
	return rows.Err()
}

func storedAccessWindows(ctx context.Context, tx *sql.Tx, rows []IdentityAccessHistory, window time.Duration) (map[string]storedWindow, error) {
	keys := make([]string, 0, len(rows))
	for _, row := range rows {
		keys = append(keys, bindingKey(row.EndpointID, row.AccountID, row.AccessID, ""))
	}
	anchor := bindingAnchor(rows, func(row IdentityAccessHistory) string { return row.LastSeen })
	return readBindingHeads(ctx, tx, "access", keys, window, anchor)
}

func collectStoredAccessWindows(rows *sql.Rows, stored map[string]storedWindow) error {
	defer rows.Close()
	for rows.Next() {
		var eventID, endpointID, accountID, accessID string
		var lastSeen time.Time
		if err := rows.Scan(&eventID, &endpointID, &accountID, &accessID, &lastSeen); err != nil {
			return err
		}
		key := bindingKey(endpointID, accountID, accessID, "")
		current, found := stored[key]
		if found && !lastSeen.UTC().After(current.LastSeen) {
			continue
		}
		stored[key] = storedWindow{EventID: eventID, LastSeen: lastSeen.UTC()}
	}
	return rows.Err()
}
