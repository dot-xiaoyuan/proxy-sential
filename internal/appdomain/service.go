package appdomain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type Job struct {
	ScanFrom         time.Time `json:"scan_from,omitempty"`
	ScanTo           time.Time `json:"scan_to,omitempty"`
	ScanSeconds      int       `json:"scan_seconds,omitempty"`
	DeduplicateUntil time.Time `json:"deduplicate_until,omitempty"`
	ID               string    `json:"id,omitempty"`
	Revision         int64     `json:"revision,omitempty"`
	RequestedControl string    `json:"requested_control,omitempty"`
	LastSuccess      string    `json:"last_success,omitempty"`
	BatchMillis      int64     `json:"batch_millis"`
	Retries          int       `json:"retries"`
	LagSeconds       float64   `json:"lag_seconds,omitempty"`
	AvailableFrom    string    `json:"available_from,omitempty"`
	AvailableTo      string    `json:"available_to,omitempty"`
	Status           string    `json:"status"`
	Version          string    `json:"version"`
	From             time.Time `json:"from"`
	To               time.Time `json:"to"`
	After            Cursor    `json:"after"`
	Processed        int       `json:"processed"`
	Error            string    `json:"error,omitempty"`
}
type ServiceStatus struct {
	Processing                *ProcessingStatus `json:"processing,omitempty"`
	RetainedObservationsKnown bool              `json:"retained_observations_known"`
	Enabled                   bool              `json:"enabled"`
	Config                    RuntimeConfig     `json:"config"`
	Library                   LibraryStatus     `json:"library"`
	Job                       Job               `json:"job"`
	LastScan                  string            `json:"last_scan"`
	Error                     string            `json:"error,omitempty"`
	RetainedObservations      int               `json:"retained_observations"`
}
type serviceState struct {
	Job      Job    `json:"job"`
	Scan     Job    `json:"scan"`
	LastScan string `json:"last_scan"`
}
type Service struct {
	historyDisabled bool
	backend         DatabaseBackend
	mu              sync.RWMutex
	pull            sync.Mutex
	config          RuntimeConfig
	work            sync.Mutex
	dir             string
	Library         *Manager
	source          EventSource
	rows            map[string]Observation
	state           serviceState
	lastError       string
	wake            chan struct{}
}

func OpenService(dir string, source EventSource) (*Service, error) {
	m, err := OpenManager(filepath.Join(dir, "library"))
	if err != nil {
		return nil, err
	}
	s := &Service{historyDisabled: os.Getenv("PROXY_SENTINEL_APPLICATION_HISTORY_DISABLED") == "true", config: RuntimeConfig{Enabled: true}, dir: dir, Library: m, source: source, rows: map[string]Observation{}, wake: make(chan struct{}, 1)}
	if provider, ok := source.(DatabaseProvider); ok {
		s.backend = provider.ApplicationBackend()
		return s, nil
	}
	if data, err := os.ReadFile(filepath.Join(dir, "state.json")); err == nil {
		if err = json.Unmarshal(data, &s.state); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	files, err := filepath.Glob(filepath.Join(dir, "observations", "*.json"))
	if err != nil {
		return nil, err
	}
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	for _, p := range files {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var rows []Observation
		if err = json.Unmarshal(data, &rows); err != nil {
			return nil, err
		}
		for _, o := range rows {
			t, err := time.Parse(time.RFC3339Nano, o.Timestamp)
			if err == nil && !t.Before(cutoff) {
				o.Timestamp = t.UTC().Format(time.RFC3339Nano)
				s.rows[o.Key()] = o
			}
		}
	}
	return s, nil
}
func (s *Service) Status() ServiceStatus {
	s.mu.RLock()
	status := ServiceStatus{Enabled: s.config.Enabled, Config: s.config, Library: s.Library.Status(), Job: s.state.Job, LastScan: s.state.LastScan, Error: s.lastError, RetainedObservations: len(s.rows), RetainedObservationsKnown: s.backend == nil}
	s.mu.RUnlock()
	if s.backend != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		state, err := s.backend.State(ctx)
		if err != nil {
			status.Error = err.Error()
		} else {
			status.Processing = &state
			status.Job = state.History
			status.LastScan = state.Realtime.LastSuccess
		}
	}
	return status
}
func (s *Service) Snapshot() []Observation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Observation, 0, len(s.rows))
	for _, o := range s.rows {
		out = append(out, o)
	}
	return out
}
func (s *Service) saveState() error {
	data, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	return atomicJSONBytes(filepath.Join(s.dir, "state.json"), data)
}
func (s *Service) notify() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (s *Service) ChangeLibrary(raw []byte, rollback string) error {
	return s.ChangeLibraryWithGuard(raw, rollback, nil)
}

func (s *Service) ChangeLibraryWithGuard(raw []byte, rollback string, check func() error) error {
	s.work.Lock()
	defer s.work.Unlock()
	if check != nil && rollback == "" && s.Library.matchesCurrentBundle(raw) {
		return check()
	}
	if s.backend != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		st, err := s.backend.State(ctx)
		if err != nil {
			return err
		}
		if st.History.Status == "running" || st.History.Status == "paused" || st.History.RequestedControl != "" {
			return fmt.Errorf("finish or cancel reclassification before changing library")
		}
	}
	defer s.notify()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Job.Status == "running" || s.state.Job.Status == "paused" || s.state.Job.Status == "failed" {
		return fmt.Errorf("finish or retry reclassification before changing library")
	}
	if rollback != "" {
		return s.Library.Rollback(rollback)
	}
	return s.Library.ImportWithGuard(raw, check)
}
func (s *Service) StartReclassification(now time.Time) error {
	if s.historyDisabled {
		return fmt.Errorf("historical application processing is disabled by deployment configuration")
	}
	if s.backend != nil {
		s.work.Lock()
		defer s.work.Unlock()
		b, _ := s.Library.Snapshot()
		if b == nil {
			return fmt.Errorf("import a library first")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.backend.Start(ctx, now, b.Manifest.Version)
	}
	defer s.notify()
	s.work.Lock()
	defer s.work.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := s.Library.Snapshot()
	if b == nil {
		return fmt.Errorf("import a library first")
	}
	if s.state.Job.Status == "running" || s.state.Job.Status == "paused" {
		return fmt.Errorf("reclassification already running or paused")
	}
	old := s.state.Job
	if s.state.Job.Status == "failed" && s.state.Job.Version == b.Manifest.Version {
		s.state.Job.Status = "running"
		s.state.Job.Error = ""
	} else {
		s.state.Job = Job{Status: "running", Version: b.Manifest.Version, From: now.Add(-7 * 24 * time.Hour), To: now}
	}
	if err := s.saveState(); err != nil {
		s.state.Job = old
		return err
	}
	return nil
}
func shard(k string) string { h := sha256.Sum256([]byte(k)); return hex.EncodeToString(h[:1]) }
func (s *Service) persistRows(changed map[string]Observation, cutoff time.Time) error {
	touched := map[string]bool{}
	for k := range changed {
		touched[shard(k)] = true
	}
	for k, o := range s.rows {
		t, _ := time.Parse(time.RFC3339Nano, o.Timestamp)
		if t.Before(cutoff) {
			touched[shard(k)] = true
		}
	}
	// Partition once per page instead of rescanning all retained history for
	// each touched shard (up to 256 full scans and hashes per record).
	grouped := make(map[string][]Observation, len(touched))
	for k, o := range s.rows {
		sh := shard(k)
		if !touched[sh] {
			continue
		}
		t, _ := time.Parse(time.RFC3339Nano, o.Timestamp)
		if _, replaced := changed[k]; !replaced && !t.Before(cutoff) {
			grouped[sh] = append(grouped[sh], o)
		}
	}
	for k, o := range changed {
		sh := shard(k)
		grouped[sh] = append(grouped[sh], o)
	}
	for sh := range touched {
		rows := grouped[sh]
		if rows == nil {
			rows = []Observation{}
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Key() < rows[j].Key() })
		data, err := json.Marshal(rows)
		if err != nil {
			return err
		}
		if err = atomicJSONBytes(filepath.Join(s.dir, "observations", sh+".json"), data); err != nil {
			return err
		}
	}
	for k, o := range s.rows {
		t, _ := time.Parse(time.RFC3339Nano, o.Timestamp)
		if t.Before(cutoff) {
			delete(s.rows, k)
		}
	}
	for k, o := range changed {
		s.rows[k] = o
	}
	return nil
}

// Step processes one keyset page off the ingest hot path. Shards are committed before
// the cursor; an interrupted page is safe to replay, including reclassification.
func (s *Service) Step(ctx context.Context, now time.Time) (bool, error) {
	if s.backend != nil {
		return s.databaseStep(ctx, "realtime", now)
	}
	s.work.Lock()
	defer s.work.Unlock()
	s.mu.RLock()
	state := s.state
	enabled := s.config.Enabled
	s.mu.RUnlock()
	if !enabled {
		return false, nil
	}
	backfill := state.Job.Status == "running"
	job := state.Scan
	if backfill {
		job = state.Job
	}
	if job.Status != "running" {
		job = Job{Status: "running", From: now.Add(-7 * 24 * time.Hour), To: now}
	}
	events, err := s.source.ScanApplicationEvents(ctx, Scan{job.From, job.To, job.After, 1000})
	if err != nil {
		s.mu.Lock()
		s.lastError = err.Error()
		if backfill {
			s.state.Job.Error = err.Error()
		}
		s.mu.Unlock()
		return false, err
	}
	b, _ := s.Library.Snapshot()
	if backfill && (b == nil || b.Manifest.Version != job.Version) {
		return false, fmt.Errorf("reclassification library version unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := map[string]Observation{}
	for _, e := range events {
		if e.EventID == "" {
			return false, fmt.Errorf("source event lacks event ID")
		}
		o := Observe(e, b)
		if _, ok := s.rows[o.Key()]; !ok || backfill {
			changed[o.Key()] = o
		}
		job.After = EventCursor(e)
		job.Processed++
		job.Error = ""
	}
	if err := s.persistRows(changed, now.Add(-7*24*time.Hour)); err != nil {
		s.lastError = err.Error()
		return false, err
	}
	more := len(events) > 0
	if !more {
		job.Status = "completed"
		if !backfill {
			state.LastScan = now.UTC().Format(time.RFC3339Nano)
		}
	}
	if backfill {
		state.Job = job
	} else {
		state.Scan = job
	}
	old := s.state
	s.state = state
	if err := s.saveState(); err != nil {
		s.state = old
		s.lastError = err.Error()
		return false, err
	}
	s.lastError = ""
	return more, nil
}
func (s *Service) Run(ctx context.Context) {
	if s.backend != nil {
		s.runDatabase(ctx)
		return
	}
	delay := time.Duration(0)
	for {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-s.wake:
			timer.Stop()
		case <-timer.C:
		}
		runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		more, err := s.Step(runCtx, time.Now().UTC())
		cancel()
		delay = 5 * time.Minute
		if more && err == nil {
			delay = 100 * time.Millisecond
		}
		if err != nil {
			delay = 30 * time.Second
		}
	}
}

// ControlJob takes effect between committed pages. Previously committed rows and
// the durable cursor are retained for both pause and cancellation.
func (s *Service) ControlJob(operation string) error {
	if s.historyDisabled && operation == "resume" {
		return fmt.Errorf("historical application processing is disabled by deployment configuration")
	}
	if s.backend != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.backend.Control(ctx, operation)
	}
	s.work.Lock()
	defer s.work.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.state.Job
	switch operation {
	case "pause":
		if old.Status != "running" {
			return fmt.Errorf("only running jobs can pause")
		}
		s.state.Job.Status = "paused"
	case "resume":
		if old.Status != "paused" && old.Status != "failed" {
			return fmt.Errorf("only paused or failed jobs can resume")
		}
		s.state.Job.Status = "running"
		s.state.Job.Error = ""
	case "cancel":
		if old.Status != "running" && old.Status != "paused" && old.Status != "failed" {
			return fmt.Errorf("job is not active")
		}
		s.state.Job.Status = "cancelled"
	default:
		return fmt.Errorf("unknown job operation")
	}
	if err := s.saveState(); err != nil {
		s.state.Job = old
		return err
	}
	s.notify()
	return nil
}
