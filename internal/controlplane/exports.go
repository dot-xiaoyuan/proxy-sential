package controlplane

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"proxy-sentinel/internal/appdomain"
	"proxy-sentinel/internal/store"
)

const maxExportRows = 100000

type exportManager struct {
	mu      sync.Mutex
	dir     string
	jobs    map[string]ExportJob
	wake    chan struct{}
	start   sync.Once
	cancels map[string]context.CancelFunc
}

type ExportJob struct {
	ExportID         string           `json:"export_id"`
	Kind             string           `json:"kind"`
	Status           string           `json:"status"`
	CreatedBy        string           `json:"created_by"`
	CreatedAt        string           `json:"created_at"`
	CompletedAt      string           `json:"completed_at,omitempty"`
	RowCount         int              `json:"row_count"`
	Error            string           `json:"error,omitempty"`
	FilePath         string           `json:"-"`
	IdempotencyKey   string           `json:"-"`
	From             string           `json:"from,omitempty"`
	To               string           `json:"to,omitempty"`
	ApplicationQuery *appdomain.Query `json:"-"`
}

type createExportRequest struct {
	Kind string `json:"kind"`
	From string `json:"from"`
	To   string `json:"to"`
}

func newExportManager(dir string) (*exportManager, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create export directory: %w", err)
	}
	m := &exportManager{dir: dir, jobs: map[string]ExportJob{}, wake: make(chan struct{}, 1), cancels: map[string]context.CancelFunc{}}
	if err := m.restore(); err != nil {
		return nil, err
	}
	return m, nil
}

func (s *Server) handleExports(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/exports"), "/")
	if r.Method == http.MethodPost && rest == "" {
		var request createExportRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "bad_export_request", err.Error())
			return
		}
		if !validExportKind(request.Kind) || request.Kind == "unknown-domains" {
			writeError(w, http.StatusBadRequest, "bad_export_kind", "kind must be risks, evidence, cases, actions or audit")
			return
		}
		if _, _, err := exportWindow(request.From, request.To); err != nil {
			writeError(w, http.StatusBadRequest, "bad_export_window", err.Error())
			return
		}
		session := sessionFromContext(r.Context())
		job := ExportJob{ExportID: "export-" + shortToken(12), Kind: request.Kind, Status: "queued", CreatedBy: session.User.ID, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), From: request.From, To: request.To}
		job.IdempotencyKey = r.Header.Get("Idempotency-Key")
		job, err := s.exports.submit(job)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "export_storage_failed", err.Error())
			return
		}
		s.exports.startWorkers(s)
		s.appendAudit(r.Context(), "export.create", job.ExportID, "accepted")
		writeJSON(w, http.StatusAccepted, job)
		return
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 1 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "export_not_found", "export not found")
		return
	}
	job, ok := s.exports.get(parts[0])
	if !ok {
		writeError(w, http.StatusNotFound, "export_not_found", "export not found")
		return
	}
	session := sessionFromContext(r.Context())
	if job.CreatedBy != session.User.ID && session.Role != "admin" {
		writeError(w, http.StatusForbidden, "export_forbidden", "export belongs to another user")
		return
	}
	if r.Method == http.MethodGet && len(parts) == 1 {
		writeJSON(w, http.StatusOK, job)
		return
	}
	if r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "cancel" {
		job, err := s.exports.cancel(parts[0])
		if err == errExportTerminal {
			writeError(w, 409, "export_terminal", err.Error())
			return
		}
		if err != nil {
			writeError(w, 503, "export_storage_failed", err.Error())
			return
		}
		s.appendAudit(r.Context(), "export.cancel", job.ExportID, "cancelled")
		writeJSON(w, 200, job)
		return
	}
	if r.Method == http.MethodGet && len(parts) == 2 && parts[1] == "download" {
		if job.Status != "completed" {
			writeError(w, http.StatusConflict, "export_not_ready", "export is not completed")
			return
		}
		ext := "csv"
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		if job.Kind == "unknown-domains" {
			ext = "jsonl"
			w.Header().Set("Content-Type", "application/x-ndjson")
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.%s"`, job.Kind, job.ExportID, ext))
		http.ServeFile(w, r, job.FilePath)
		return
	}
	writeError(w, http.StatusNotFound, "export_endpoint_not_found", "export endpoint not found")
}

func (s *Server) runExport(id string) {
	job, ok := s.exports.get(id)
	if !ok {
		return
	}
	if job.Status != "running" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	s.exports.mu.Lock()
	if current := s.exports.jobs[id]; current.Status != "running" {
		s.exports.mu.Unlock()
		return
	}
	s.exports.cancels[id] = cancel
	s.exports.mu.Unlock()
	defer func() { s.exports.mu.Lock(); delete(s.exports.cancels, id); s.exports.mu.Unlock() }()
	path := exportFilePath(s.exports.dir, job)
	temporary := path + ".tmp"
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err == nil {
		if job.Kind == "unknown-domains" {
			if s.applications == nil || job.ApplicationQuery == nil {
				err = errors.New("application export parameters unavailable")
			} else {
				counter := &exportLineWriter{Writer: file}
				err = s.applications.Export(ctx, *job.ApplicationQuery, counter)
				job.RowCount = counter.rows
			}
		} else {
			writer := csv.NewWriter(file)
			err = writer.Write([]string{"record_type", "id", "subject", "level", "status", "score", "confidence", "occurred_at", "data_json"})
			if err == nil {
				job.RowCount, err = s.writeExportRows(ctx, writer, job)
			}
			writer.Flush()
			if err == nil {
				err = writer.Error()
			}
		}
		if err == nil {
			err = ctx.Err()
		}
		if err == nil {
			err = file.Sync()
		}
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
	}
	s.exports.mu.Lock()
	if current := s.exports.jobs[id]; current.Status == "cancelled" {
		s.exports.mu.Unlock()
		_ = os.Remove(temporary)
		return
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = os.Rename(temporary, path)
	}
	job.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err != nil {
		_ = os.Remove(temporary)
		job.Status, job.Error = "failed", err.Error()
	} else {
		job.Status, job.FilePath = "completed", path
	}
	if err := s.exports.persistLocked(job); err != nil {
		s.exports.mu.Unlock()
		s.appendAudit(context.Background(), "export.persist_failed", job.ExportID, "failed")
		return
	}
	s.exports.jobs[id] = job
	s.exports.mu.Unlock()
	s.appendAudit(context.Background(), "export.complete", job.ExportID, job.Status)
}

func (s *Server) writeExportRows(ctx context.Context, writer *csv.Writer, job ExportJob) (int, error) {
	from, to, _ := exportWindow(job.From, job.To)
	count := 0
	write := func(kind, id, subject, level, status, score, confidence, occurred string, value any) error {
		if !withinExportWindow(occurred, from, to) || count >= maxExportRows {
			return nil
		}
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		row := []string{kind, id, subject, level, status, score, confidence, occurred, string(data)}
		for index := range row {
			row[index] = safeCSVCell(row[index])
		}
		if err := writer.Write(row); err != nil {
			return err
		}
		count++
		return nil
	}
	switch job.Kind {
	case "risks", "evidence":
		limit := maxExportRows
		if job.Kind == "evidence" {
			limit = 5000
		}
		page, err := s.reader.ListRisks(ctx, store.Query{SensorID: s.sensorID, From: job.From, To: job.To, Limit: limit})
		if err != nil {
			return count, err
		}
		for _, item := range page.Items {
			if job.Kind == "risks" {
				if err := write("risk", item.IP, item.IP, item.Level, "", fmt.Sprint(item.Score), fmt.Sprint(item.Confidence), item.UpdatedAt, item); err != nil {
					return count, err
				}
				continue
			}
			evidenceItems, err := s.reader.GetIPEvidence(ctx, item.IP, 1000)
			if err != nil {
				return count, err
			}
			for _, evidenceItem := range evidenceItems {
				if err := write("evidence", evidenceItem.EvidenceID, item.IP, "", "", fmt.Sprint(evidenceItem.Score), fmt.Sprint(evidenceItem.Confidence), evidenceItem.CreatedAt, evidenceItem); err != nil {
					return count, err
				}
			}
		}
	case "cases", "actions":
		s.operations.mu.Lock()
		if job.Kind == "cases" {
			items := make([]RiskCase, 0, len(s.operations.doc.Cases))
			for _, item := range s.operations.doc.Cases {
				items = append(items, item)
			}
			s.operations.mu.Unlock()
			sort.Slice(items, func(i, j int) bool { return items[i].UpdatedAt < items[j].UpdatedAt })
			for _, item := range items {
				if err := write("case", item.CaseID, item.SubjectID, item.AssessmentLevel, item.Status, fmt.Sprint(item.RiskScore), fmt.Sprint(item.RiskConfidence), item.UpdatedAt, item); err != nil {
					return count, err
				}
			}
		} else {
			items := make([]EnforcementAction, 0, len(s.operations.doc.Actions))
			for _, item := range s.operations.doc.Actions {
				items = append(items, item)
			}
			s.operations.mu.Unlock()
			sort.Slice(items, func(i, j int) bool { return items[i].UpdatedAt < items[j].UpdatedAt })
			for _, item := range items {
				if err := write("action", item.ActionID, item.SubjectID, "", item.Status, "", "", item.UpdatedAt, item); err != nil {
					return count, err
				}
			}
		}
	case "audit":
		items, err := s.reader.ListAuditLogs(ctx, maxExportRows)
		if err != nil {
			return count, err
		}
		for _, item := range items {
			if err := write("audit", item.AuditID, item.Target, "", item.Outcome, "", "", item.CreatedAt, item); err != nil {
				return count, err
			}
		}
	}
	return count, nil
}

func validExportKind(kind string) bool {
	switch kind {
	case "risks", "evidence", "cases", "actions", "audit", "unknown-domains":
		return true
	}
	return false
}

func exportWindow(fromRaw, toRaw string) (time.Time, time.Time, error) {
	var from, to time.Time
	var err error
	if fromRaw != "" {
		from, err = time.Parse(time.RFC3339, fromRaw)
		if err != nil {
			return from, to, errors.New("from must be RFC3339")
		}
	}
	if toRaw != "" {
		to, err = time.Parse(time.RFC3339, toRaw)
		if err != nil {
			return from, to, errors.New("to must be RFC3339")
		}
	}
	if !from.IsZero() && !to.IsZero() && !from.Before(to) {
		return from, to, errors.New("from must be earlier than to")
	}
	return from, to, nil
}

func withinExportWindow(raw string, from, to time.Time) bool {
	if from.IsZero() && to.IsZero() {
		return true
	}
	value, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return false
	}
	return (from.IsZero() || !value.Before(from)) && (to.IsZero() || value.Before(to))
}

func safeCSVCell(value string) string {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + value
	}
	return value
}

func (m *exportManager) get(id string) (ExportJob, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.jobs[id]
	return job, ok
}
