package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"proxy-sentinel/internal/appdomain"
	"sort"
	"time"
)

var errExportTerminal = errors.New("export is already completed or failed")

func (m *exportManager) cancel(id string) (ExportJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job := m.jobs[id]
	if job.Status == "cancelled" {
		return job, nil
	}
	if job.Status != "queued" && job.Status != "running" {
		return job, errExportTerminal
	}
	job.Status = "cancelled"
	job.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := m.persistLocked(job); err != nil {
		return ExportJob{}, err
	}
	m.jobs[id] = job
	if cancel := m.cancels[id]; cancel != nil {
		cancel()
	}
	return job, nil
}

// Private task metadata is persisted independently of public API fields.
type persistedExport struct {
	Query          *appdomain.Query `json:"application_query,omitempty"`
	Job            ExportJob        `json:"job"`
	IdempotencyKey string           `json:"idempotency_key,omitempty"`
}

func (m *exportManager) persistLocked(job ExportJob) error {
	raw, err := json.Marshal(persistedExport{Job: job, IdempotencyKey: job.IdempotencyKey, Query: job.ApplicationQuery})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(m.dir, ".job-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, filepath.Join(m.dir, job.ExportID+".job.json")); err != nil {
		return err
	}
	dir, err := os.Open(m.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (m *exportManager) restore() error {
	paths, err := filepath.Glob(filepath.Join(m.dir, "*.job.json"))
	if err != nil {
		return err
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var persisted persistedExport
		if err = json.Unmarshal(raw, &persisted); err != nil {
			return fmt.Errorf("restore export metadata: %w", err)
		}
		job := persisted.Job
		if filepath.Base(job.ExportID) != job.ExportID || job.ExportID == "" || !validExportKind(job.Kind) {
			return fmt.Errorf("invalid export metadata")
		}
		job.IdempotencyKey = persisted.IdempotencyKey
		job.ApplicationQuery = persisted.Query
		job.FilePath = exportFilePath(m.dir, job)
		if job.Status == "running" {
			job.Status = "queued"
			if err = os.Remove(job.FilePath + ".tmp"); err != nil && !os.IsNotExist(err) {
				return err
			}
			if err = m.persistLocked(job); err != nil {
				return err
			}
		}
		m.jobs[job.ExportID] = job
	}
	return nil
}

func (m *exportManager) put(job ExportJob) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.persistLocked(job); err != nil {
		return err
	}
	m.jobs[job.ExportID] = job
	return nil
}

func (m *exportManager) submit(job ExportJob) (ExportJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pending := 0
	for _, existing := range m.jobs {
		if job.IdempotencyKey != "" && existing.CreatedBy == job.CreatedBy && existing.IdempotencyKey == job.IdempotencyKey {
			if existing.Kind != job.Kind || existing.From != job.From || existing.To != job.To || approvalJSON(existing.ApplicationQuery) != approvalJSON(job.ApplicationQuery) {
				return ExportJob{}, fmt.Errorf("idempotency key reused with different parameters")
			}
			return existing, nil
		}
		if existing.Status == "queued" || existing.Status == "running" {
			pending++
		}
	}
	if pending >= 1000 {
		return ExportJob{}, fmt.Errorf("export queue is full")
	}
	if err := m.persistLocked(job); err != nil {
		return ExportJob{}, err
	}
	m.jobs[job.ExportID] = job
	select {
	case m.wake <- struct{}{}:
	default:
	}
	return job, nil
}

func (m *exportManager) claim() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := []string{}
	for id, job := range m.jobs {
		if job.Status == "queued" {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := m.jobs[ids[i]], m.jobs[ids[j]]
		if a.CreatedAt == b.CreatedAt {
			return ids[i] < ids[j]
		}
		return a.CreatedAt < b.CreatedAt
	})
	if len(ids) == 0 {
		return "", nil
	}
	job := m.jobs[ids[0]]
	job.Status = "running"
	if err := m.persistLocked(job); err != nil {
		return "", err
	}
	m.jobs[job.ExportID] = job
	return job.ExportID, nil
}

func (m *exportManager) startWorkers(s *Server) {
	m.start.Do(func() {
		for i := 0; i < 2; i++ {
			go func() {
				for {
					id, err := m.claim()
					if err == nil && id != "" {
						s.runExport(id)
						continue
					}
					select {
					case <-m.wake:
					case <-time.After(time.Second):
					}
				}
			}()
		}
	})
}
