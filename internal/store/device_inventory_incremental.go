package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"time"

	"proxy-sentinel/internal/risk"
)

// Current device inventory, refreshed incrementally.
//
// The previous refresh rebuilt every IP of three windows from device_signal_facts every 30 seconds:
// on 184 that held ~360 MB of signals and inventories in memory, pushed the identity materializer past
// its 1 GiB limit into swap, and stalled snapshot projection in the same process. An IP's inventory
// depends only on its own facts inside the window (BuildDeviceInventoryFromSignals reads no clock), so
// it changes only when one of its facts is written, a future-dated fact becomes due, or a fact ages
// out of the window. Each round rebuilds exactly those IPs.

var deviceInventoryWindows = []string{"10m", "1h", "24h"}

// deviceInventoryBatch bounds the IPs rebuilt per statement and per bootstrap round.
var deviceInventoryBatch = 2000

// deviceInventoryChangeOverlap re-reads recent changes: updated_at is the writer's transaction start,
// so a fact written by a long transaction commits after later ones. Identity writes are bounded well
// below this.
const deviceInventoryChangeOverlap = 10 * time.Minute

type deviceInventoryRefreshState struct {
	// Bootstrapped is false until one controlled pass has rebuilt every IP in IP order.
	Bootstrapped   bool      `json:"bootstrapped"`
	BootstrapAfter string    `json:"bootstrap_after,omitempty"`
	StartedAt      time.Time `json:"started_at,omitempty"`
	// ChangedThrough and PreviousRun are the start of the last completed round.
	ChangedThrough time.Time `json:"changed_through,omitempty"`
	PreviousRun    time.Time `json:"previous_run,omitempty"`
}

type deviceFactSource interface {
	ChangedIPs(ctx context.Context, since time.Time) ([]string, error)
	IPsWithLastSeen(ctx context.Context, after, through time.Time) ([]string, error)
	WindowIPs(ctx context.Context, from, through time.Time) ([]string, error)
	FactsForIPs(ctx context.Context, ips []string, from, through time.Time) (map[string][]DeviceSignal, error)
}

type deviceInventoryStore interface {
	Upsert(ctx context.Context, window string, item IPDeviceInventory) error
	Delete(ctx context.Context, window string, ips []string) error
	IPs(ctx context.Context, window string) ([]string, error)
}

func windowDuration(window string) time.Duration {
	_, duration, _ := NormalizeActivityWindow(window)
	return duration
}

// refreshDeviceInventoryIncrementally runs one round and returns the state to persist.
func refreshDeviceInventoryIncrementally(ctx context.Context, src deviceFactSource, dst deviceInventoryStore, state deviceInventoryRefreshState, now time.Time) (deviceInventoryRefreshState, error) {
	if !state.Bootstrapped {
		var err error
		if state, err = bootstrapDeviceInventory(ctx, src, dst, state, now); err != nil || !state.Bootstrapped {
			return state, err
		}
		// IPs the bootstrap passed may have changed since it started; catch up in the same round.
	}
	changed, err := src.ChangedIPs(ctx, state.ChangedThrough.Add(-deviceInventoryChangeOverlap))
	if err != nil {
		return state, err
	}
	// Future-dated facts that became due since the previous round enter every window.
	entered, err := src.IPsWithLastSeen(ctx, state.PreviousRun.Add(-deviceInventoryChangeOverlap), now)
	if err != nil {
		return state, err
	}
	for _, window := range deviceInventoryWindows {
		duration := windowDuration(window)
		// Facts whose last_seen fell behind the moving cutoff left this window.
		crossed, err := src.IPsWithLastSeen(ctx, state.PreviousRun.Add(-duration-deviceInventoryChangeOverlap), now.Add(-duration))
		if err != nil {
			return state, err
		}
		if err = rebuildDeviceInventoryIPs(ctx, src, dst, window, unionIPs(changed, entered, crossed), now); err != nil {
			return state, err
		}
	}
	state.ChangedThrough, state.PreviousRun = now, now
	return state, nil
}

// bootstrapDeviceInventory rebuilds one IP-ordered batch per round: every IP with facts in the widest
// window and every IP already stored. Changes made meanwhile are picked up after it completes, because
// the incremental phase starts from the bootstrap's start time.
func bootstrapDeviceInventory(ctx context.Context, src deviceFactSource, dst deviceInventoryStore, state deviceInventoryRefreshState, now time.Time) (deviceInventoryRefreshState, error) {
	if state.StartedAt.IsZero() {
		state.StartedAt = now
	}
	widest := windowDuration(deviceInventoryWindows[len(deviceInventoryWindows)-1])
	candidates, err := src.WindowIPs(ctx, now.Add(-widest), now)
	if err != nil {
		return state, err
	}
	for _, window := range deviceInventoryWindows {
		stored, err := dst.IPs(ctx, window)
		if err != nil {
			return state, err
		}
		candidates = unionIPs(candidates, stored)
	}
	batch := []string{}
	for _, ip := range candidates {
		if ip > state.BootstrapAfter {
			batch = append(batch, ip)
			if len(batch) == deviceInventoryBatch {
				break
			}
		}
	}
	for _, window := range deviceInventoryWindows {
		if err = rebuildDeviceInventoryIPs(ctx, src, dst, window, batch, now); err != nil {
			return state, err
		}
	}
	if len(batch) == deviceInventoryBatch {
		state.BootstrapAfter = batch[len(batch)-1]
		return state, nil
	}
	return deviceInventoryRefreshState{Bootstrapped: true, ChangedThrough: state.StartedAt, PreviousRun: state.StartedAt}, nil
}

// rebuildDeviceInventoryIPs recomputes the given IPs for one window exactly as the full rebuild did,
// and removes those that no longer have facts in the window.
func rebuildDeviceInventoryIPs(ctx context.Context, src deviceFactSource, dst deviceInventoryStore, window string, ips []string, now time.Time) error {
	from := now.Add(-windowDuration(window))
	for start := 0; start < len(ips); start += deviceInventoryBatch {
		batch := ips[start:min(start+deviceInventoryBatch, len(ips))]
		facts, err := src.FactsForIPs(ctx, batch, from, now)
		if err != nil {
			return err
		}
		missing := []string{}
		for _, ip := range batch {
			signals := facts[ip]
			if len(signals) == 0 {
				missing = append(missing, ip)
				continue
			}
			if err = dst.Upsert(ctx, window, BuildDeviceInventoryFromSignals(ip, window, signals, risk.Snapshot{})); err != nil {
				return err
			}
		}
		if len(missing) > 0 {
			if err = dst.Delete(ctx, window, missing); err != nil {
				return err
			}
		}
	}
	return nil
}

func unionIPs(lists ...[]string) []string {
	set := map[string]bool{}
	for _, list := range lists {
		for _, ip := range list {
			set[ip] = true
		}
	}
	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

// sortSignalsLikeQuery orders one IP's signals as the full rebuild's query returned them.
func sortSignalsLikeQuery(signals []DeviceSignal) {
	sort.SliceStable(signals, func(i, j int) bool {
		if signals[i].LastSeen != signals[j].LastSeen {
			a, _ := time.Parse(time.RFC3339Nano, signals[i].LastSeen)
			b, _ := time.Parse(time.RFC3339Nano, signals[j].LastSeen)
			return a.After(b)
		}
		return signals[i].SignalID < signals[j].SignalID
	})
}

const deviceFactsChangedSQL = `SELECT DISTINCT host(ip) FROM device_signal_facts WHERE sensor_id=$1 AND updated_at>$2`
const deviceFactsCrossedSQL = `SELECT DISTINCT host(ip) FROM device_signal_facts WHERE sensor_id=$1 AND last_seen>$2 AND last_seen<=$3`
const deviceFactsWindowIPsSQL = `SELECT DISTINCT host(ip) FROM device_signal_facts WHERE sensor_id=$1 AND last_seen>=$2 AND last_seen<=$3`
const deviceFactsForIPsSQL = `SELECT signal_id, host(ip), source, kind, value, normalized_value, strength, confidence, weight, first_seen, last_seen, seen_count, event_ids_sample
FROM device_signal_facts WHERE sensor_id=$1 AND ip=ANY($2::inet[]) AND last_seen>=$3 AND last_seen<=$4
ORDER BY ip ASC, last_seen DESC, signal_id ASC`
const deviceInventoryDeleteSQL = `DELETE FROM device_inventory_current WHERE sensor_id=$1 AND "window"=$2 AND host(ip)=ANY($3::text[])`
const deviceInventoryIPsSQL = `SELECT host(ip) FROM device_inventory_current WHERE sensor_id=$1 AND "window"=$2`

type sqlDeviceFacts struct {
	tx     *sql.Tx
	sensor string
}

func (f sqlDeviceFacts) strings(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := f.tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var v string
		if err = rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (f sqlDeviceFacts) ChangedIPs(ctx context.Context, since time.Time) ([]string, error) {
	return f.strings(ctx, deviceFactsChangedSQL, f.sensor, since)
}

func (f sqlDeviceFacts) IPsWithLastSeen(ctx context.Context, after, through time.Time) ([]string, error) {
	return f.strings(ctx, deviceFactsCrossedSQL, f.sensor, after, through)
}

func (f sqlDeviceFacts) WindowIPs(ctx context.Context, from, through time.Time) ([]string, error) {
	return f.strings(ctx, deviceFactsWindowIPsSQL, f.sensor, from, through)
}

func (f sqlDeviceFacts) FactsForIPs(ctx context.Context, ips []string, from, through time.Time) (map[string][]DeviceSignal, error) {
	rows, err := f.tx.QueryContext(ctx, deviceFactsForIPsSQL, f.sensor, ips, from, through)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]DeviceSignal{}
	for rows.Next() {
		signal, err := scanDeviceSignal(rows)
		if err != nil {
			return nil, err
		}
		out[signal.IP] = append(out[signal.IP], signal)
	}
	return out, rows.Err()
}

type sqlDeviceInventory struct {
	tx     *sql.Tx
	sensor string
	run    Run
}

func (d sqlDeviceInventory) Upsert(ctx context.Context, window string, item IPDeviceInventory) error {
	return upsertCurrentDeviceInventory(ctx, d.tx, d.run, window, item)
}

func (d sqlDeviceInventory) Delete(ctx context.Context, window string, ips []string) error {
	_, err := d.tx.ExecContext(ctx, deviceInventoryDeleteSQL, d.sensor, window, ips)
	return err
}

func (d sqlDeviceInventory) IPs(ctx context.Context, window string) ([]string, error) {
	return sqlDeviceFacts{tx: d.tx, sensor: d.sensor}.strings(ctx, deviceInventoryIPsSQL, d.sensor, window)
}

func deviceInventoryStateName(sensor string) string { return "device-inventory-current:" + sensor }

func loadDeviceInventoryState(ctx context.Context, tx *sql.Tx, sensor string) (deviceInventoryRefreshState, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT state FROM read_model_runtime_state WHERE name=$1`, deviceInventoryStateName(sensor)).Scan(&raw)
	if err == sql.ErrNoRows {
		return deviceInventoryRefreshState{}, nil
	}
	if err != nil {
		return deviceInventoryRefreshState{}, err
	}
	var state deviceInventoryRefreshState
	err = json.Unmarshal(raw, &state)
	return state, err
}

func saveDeviceInventoryState(ctx context.Context, tx *sql.Tx, sensor string, state deviceInventoryRefreshState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO read_model_runtime_state(name,state,updated_at) VALUES($1,$2,now()) ON CONFLICT(name) DO UPDATE SET state=EXCLUDED.state,updated_at=now()`, deviceInventoryStateName(sensor), raw)
	return err
}
