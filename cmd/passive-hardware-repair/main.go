// passive-hardware-repair is an explicit one-off retained-latest repair. It
// never installs an application, changes gates, advances the bootstrap cursor,
// modifies source observations, or claims to recover overwritten/late history.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/store"
)

const checkpointSchema = "passive-hardware-retained-latest-checkpoint/v1"

type repairCheckpoint struct {
	SchemaVersion  string                        `json:"schema_version"`
	ManifestSHA256 string                        `json:"manifest_sha256"`
	Total          int                           `json:"total"`
	Next           int                           `json:"next"`
	Complete       bool                          `json:"complete"`
	UpdatedAt      time.Time                     `json:"updated_at"`
	Outcomes       []store.HardwareRepairOutcome `json:"outcomes"`
}
type repairApply func(context.Context, int, int) ([]store.HardwareRepairOutcome, error)

func advanceRepair(ctx context.Context, state *repairCheckpoint, limit int, apply repairApply, publish func(repairCheckpoint) error) error {
	rows, err := apply(ctx, state.Next, limit)
	if err != nil {
		return err
	}
	if len(rows) == 0 || len(rows) > limit || state.Next+len(rows) > state.Total {
		return fmt.Errorf("repair batch returned no progress or exceeded its bound")
	}
	for i, row := range rows {
		if row.Index != state.Next+i || (row.Status != "admitted" && row.Status != "excluded") {
			return fmt.Errorf("repair batch audit is not contiguous")
		}
	}
	next := *state
	next.Outcomes = append(append([]store.HardwareRepairOutcome(nil), state.Outcomes...), rows...)
	next.Next += len(rows)
	next.Complete = next.Next == next.Total
	next.UpdatedAt = time.Now().UTC()
	// A transaction has committed, but a failed durable checkpoint is uncertain
	// progress. Keep the previous offset and retry idempotently on the next run.
	if err = publish(next); err != nil {
		return fmt.Errorf("database batch committed; checkpoint failed, rerun the same manifest: %w", err)
	}
	*state = next
	return nil
}
func readRepairJSON(path string, v any) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > 2*store.HardwareRepairMaxSnapshotBytes {
		return fmt.Errorf("repair artifact is not a bounded regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 2*store.HardwareRepairMaxSnapshotBytes+1))
	dec.DisallowUnknownFields()
	if err = dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if err = dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("repair artifact has trailing content")
	}
	return nil
}
func writeRepairJSON(path string, value any, exclusive bool) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if len(raw) > 2*store.HardwareRepairMaxSnapshotBytes {
		return fmt.Errorf("repair artifact exceeds 32 MiB")
	}
	if st, e := os.Lstat(path); e == nil && !st.Mode().IsRegular() {
		return fmt.Errorf("repair artifact target is not a regular file")
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".hardware-repair-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if exclusive {
		err = os.Link(name, path)
	} else {
		err = os.Rename(name, path)
	}
	if err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func manifestHash(m store.HardwareRepairManifest) string {
	raw, _ := json.Marshal(m)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func validateCheckpoint(s repairCheckpoint, m store.HardwareRepairManifest) error {
	if s.SchemaVersion != checkpointSchema || s.ManifestSHA256 != manifestHash(m) || s.Total != len(m.Entries) || s.Next < 0 || s.Next > s.Total || len(s.Outcomes) != s.Next || s.Complete != (s.Next == s.Total) {
		return fmt.Errorf("checkpoint does not match the frozen manifest")
	}
	for i, r := range s.Outcomes {
		e := m.Entries[i]
		if r.Index != i || r.ObservationID != e.ObservationID || r.EventID != e.EventID || r.SourceSHA256 != e.SourceSHA256 || (r.Status != "admitted" && r.Status != "excluded") {
			return fmt.Errorf("checkpoint audit mismatch at entry %d", i)
		}
	}
	return nil
}
func run(ctx context.Context) error {
	mode := flag.String("mode", "", "snapshot (read-only) or apply (facts/dirty only)")
	sensor := flag.String("sensor", "", "exact sensor for snapshot")
	from := flag.String("from", "", "inclusive event-time RFC3339")
	until := flag.String("until", "", "exclusive event-time RFC3339")
	manifestPath := flag.String("manifest", "", "immutable local manifest path")
	checkpointPath := flag.String("checkpoint", "", "durable progress and per-row audit path (apply)")
	batch := flag.Int("batch-size", 25, "apply batch rows, 1..50")
	pause := flag.Duration("pause", 500*time.Millisecond, "minimum pause between batches, at least 250ms")
	flag.Parse()
	if (*mode != "snapshot" && *mode != "apply") || *manifestPath == "" || *batch < 1 || *batch > 50 || *pause < 250*time.Millisecond {
		return fmt.Errorf("specify mode, manifest and bounded batch/pause")
	}
	dsn := os.Getenv("PROXY_SENTINEL_POSTGRES_DSN")
	if dsn == "" {
		return fmt.Errorf("PROXY_SENTINEL_POSTGRES_DSN is required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("invalid PostgreSQL connection configuration")
	}
	cfg.RuntimeParams["application_name"] = "passive-hardware-repair"
	db := stdlib.OpenDB(*cfg)
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if *mode == "snapshot" {
		start, e := time.Parse(time.RFC3339Nano, *from)
		if e != nil {
			return fmt.Errorf("invalid --from")
		}
		end, e := time.Parse(time.RFC3339Nano, *until)
		if e != nil {
			return fmt.Errorf("invalid --until")
		}
		work, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		manifest, e := store.SnapshotHardwareRepair(work, db, store.HardwareRepairWindow{Sensor: *sensor, From: start, Until: end})
		if e != nil {
			return e
		}
		if e = writeRepairJSON(*manifestPath, manifest, true); e != nil {
			return e
		}
		excluded := 0
		for _, r := range manifest.Entries {
			if r.Observation == nil {
				excluded++
			}
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": "read_only_snapshot", "rows": len(manifest.Entries), "eligible": len(manifest.Entries) - excluded, "excluded": excluded, "manifest_sha256": manifestHash(manifest), "coverage": "retained_latest_in_event_time_window_only"})
	}
	if *checkpointPath == "" || filepath.Clean(*checkpointPath) == filepath.Clean(*manifestPath) {
		return fmt.Errorf("apply requires a distinct checkpoint path")
	}
	if !discovery.HardwareProjectionEnabled() {
		return fmt.Errorf("apply requires an already enabled hardware shadow or V2 gate; this command never changes gates")
	}
	var manifest store.HardwareRepairManifest
	if err = readRepairJSON(*manifestPath, &manifest); err != nil {
		return err
	}
	if err = manifest.Validate(); err != nil {
		return err
	}
	work, cancel := context.WithTimeout(ctx, 5*time.Second)
	conn, err := db.Conn(work)
	cancel()
	if err != nil {
		return err
	}
	defer conn.Close()
	work, cancel = context.WithTimeout(ctx, 5*time.Second)
	var acquired bool
	err = conn.QueryRowContext(work, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, "passive-hardware-repair:"+manifest.Window.Sensor).Scan(&acquired)
	cancel()
	if err != nil {
		return err
	}
	if !acquired {
		return fmt.Errorf("another repair owns this sensor; retry later")
	}
	defer func() {
		unlock, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(unlock, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, "passive-hardware-repair:"+manifest.Window.Sensor)
	}()
	state := repairCheckpoint{SchemaVersion: checkpointSchema, ManifestSHA256: manifestHash(manifest), Total: len(manifest.Entries), Complete: len(manifest.Entries) == 0, Outcomes: []store.HardwareRepairOutcome{}, UpdatedAt: time.Now().UTC()}
	if err = readRepairJSON(*checkpointPath, &state); errors.Is(err, os.ErrNotExist) {
		err = writeRepairJSON(*checkpointPath, state, true)
	}
	if err != nil {
		return err
	}
	if err = validateCheckpoint(state, manifest); err != nil {
		return err
	}
	save := func(s repairCheckpoint) error { return writeRepairJSON(*checkpointPath, s, false) }
	apply := func(c context.Context, start, limit int) ([]store.HardwareRepairOutcome, error) {
		return store.ApplyHardwareRepairBatch(c, conn, manifest, start, limit)
	}
	for !state.Complete {
		// Leave an already backlogged worker to real-time observations. The local
		// checkpoint remains resumable; this is not completion or cancellation.
		work, cancel = context.WithTimeout(ctx, time.Second)
		var busy bool
		err = conn.QueryRowContext(work, `SELECT EXISTS(SELECT 1 FROM passive_hardware_dirty WHERE sensor_id=$1 OFFSET 100 LIMIT 1)`, manifest.Window.Sensor).Scan(&busy)
		cancel()
		if err != nil {
			return err
		}
		if busy {
			return fmt.Errorf("hardware queue exceeds 100 identities; repair yields with checkpoint %d/%d, rerun later", state.Next, state.Total)
		}
		if err = advanceRepair(ctx, &state, *batch, apply, save); err != nil {
			return err
		}
		if !state.Complete {
			timer := time.NewTimer(*pause)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	admitted := 0
	for _, r := range state.Outcomes {
		if r.Status == "admitted" {
			admitted++
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": "repair_enqueue_complete", "processed": state.Next, "admitted_or_already_present": admitted, "excluded": state.Next - admitted, "manifest_sha256": state.ManifestSHA256, "coverage": "retained_latest_in_event_time_window_only", "projection_completion": "verify independently; enqueue completion is not projection completion"})
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "hardware repair:", err)
		os.Exit(1)
	}
}
