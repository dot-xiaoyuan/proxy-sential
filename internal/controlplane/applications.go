package controlplane

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"proxy-sentinel/internal/appdomain"
	"proxy-sentinel/internal/store"
	"strings"
	"time"
)

func (s *Server) handleApplications(w http.ResponseWriter, r *http.Request, path string) {
	if s.applications == nil {
		if path == "/application-library" && r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, appdomain.ServiceStatus{Enabled: false})
			return
		}
		writeError(w, http.StatusServiceUnavailable, "applications_disabled", "应用观测尚未启用")
		return
	}
	if path == "/application-library" && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, s.applications.Status())
		return
	}
	if r.Method == http.MethodPost {
		var err error
		switch path {
		case "/application-library/config":
			var config struct {
				appdomain.RuntimeConfig
				Token string `json:"token"`
			}
			err = json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&config)
			if err == nil {
				err = s.applications.Configure(config.RuntimeConfig)
			}
			if err == nil && config.Token != "" {
				err = s.applications.SaveCredential(config.Token)
			}
		case "/application-library/pull":
			var body struct {
				Token string `json:"token"`
			}
			err = json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&body)
			if err == nil {
				err = s.applications.PullWithGuard(r.Context(), body.Token, s.operationCommitGuard(r.Context()))
			}
		case "/application-library/import":
			r.Body = http.MaxBytesReader(w, r.Body, appdomain.MaxBundleBytes)
			var data []byte
			data, err = io.ReadAll(r.Body)
			if err == nil {
				err = s.applications.ChangeLibraryWithGuard(data, "", s.operationCommitGuard(r.Context()))
			}
		case "/application-library/rollback":
			var body struct {
				Version string `json:"version"`
			}
			err = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body)
			if err == nil && body.Version == "" {
				err = fmt.Errorf("version required")
			}
			if err == nil {
				err = s.applications.ChangeLibrary(nil, body.Version)
			}
		case "/application-library/jobs/pause", "/application-library/jobs/resume", "/application-library/jobs/cancel":
			err = s.applications.ControlJob(strings.TrimPrefix(path, "/application-library/jobs/"))
		case "/application-library/reclassify":
			err = s.applications.StartReclassification(time.Now().UTC())
		default:
			writeError(w, 404, "not_found", "unknown application operation")
			return
		}
		if err != nil {
			s.appendAudit(r.Context(), "applications.update", path, "failed: "+err.Error())
			writeError(w, 400, "application_update_failed", err.Error())
			return
		}
		s.appendAudit(r.Context(), "applications.update", path, "success")
		writeJSON(w, 200, s.applications.Status())
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, 405, "method_not_allowed", "GET or POST required")
		return
	}
	if !s.applications.Status().Enabled {
		writeError(w, 503, "applications_disabled", "应用观测尚未启用")
		return
	}
	q, err := applicationQuery(r)
	if err != nil {
		writeError(w, 400, "invalid_query", err.Error())
		return
	}
	switch path {
	case "/application-activity":
		result, err := s.applications.Report(r.Context(), q)
		if err != nil {
			writeError(w, 503, "application_query_failed", err.Error())
			return
		}
		writeJSON(w, 200, result)
	case "/application-activity/observations":
		limit, err := boundedInt(r.URL.Query().Get("limit"), 50, 1, 200)
		if err != nil {
			writeError(w, 400, "invalid_limit", err.Error())
			return
		}
		offset, err := boundedInt(r.URL.Query().Get("offset"), 0, 0, 10000000)
		if err != nil {
			writeError(w, 400, "invalid_offset", err.Error())
			return
		}
		cursor := r.URL.Query().Get("cursor")
		if _, err = appdomain.DecodePageCursor(cursor); err != nil || cursor != "" && offset != 0 {
			writeError(w, 400, "invalid_cursor", "use a valid cursor without offset")
			return
		}
		page, err := s.applications.Page(r.Context(), q, appdomain.PageRequest{Limit: limit, Offset: offset, Cursor: cursor})
		if err != nil {
			writeError(w, 503, "application_query_failed", err.Error())
			return
		}
		writeJSON(w, 200, page)
	case "/application-activity/unknown-domains":
		session := sessionFromContext(r.Context())
		job := ExportJob{ExportID: "export-" + shortToken(12), Kind: "unknown-domains", Status: "queued", CreatedBy: session.User.ID, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), ApplicationQuery: &q, IdempotencyKey: r.Header.Get("Idempotency-Key")}
		job, err = s.exports.submit(job)
		if err != nil {
			writeError(w, 503, "export_storage_failed", err.Error())
			return
		}
		s.exports.startWorkers(s)
		s.appendAudit(r.Context(), "export.create", job.ExportID, "accepted")
		writeJSON(w, http.StatusAccepted, job)

	default:
		writeError(w, 404, "not_found", "unknown application resource")
	}
}
func applicationQuery(r *http.Request) (appdomain.Query, error) {
	v := r.URL.Query()
	q := appdomain.Query{To: time.Now().UTC(), SensorID: v.Get("sensor_id"), CampusID: v.Get("campus_id"), IP: v.Get("ip"), ApplicationID: v.Get("application_id")}
	window := v.Get("window")
	if window == "" {
		window = "24h"
	}
	_, duration, err := store.NormalizeActivityWindow(window)
	if err != nil {
		return q, err
	}
	if q.IP != "" {
		if _, err := netip.ParseAddr(q.IP); err != nil {
			return q, fmt.Errorf("invalid IP")
		}
	}
	if v.Get("to") != "" {
		q.To, err = time.Parse(time.RFC3339Nano, v.Get("to"))
		if err != nil {
			return q, err
		}
	}
	q.From = q.To.Add(-duration)
	if v.Get("from") != "" {
		q.From, err = time.Parse(time.RFC3339Nano, v.Get("from"))
		if err != nil {
			return q, err
		}
	}
	if !q.From.Before(q.To) || q.To.Sub(q.From) > 7*24*time.Hour || q.To.After(time.Now().Add(time.Minute)) || q.From.Before(time.Now().Add(-7*24*time.Hour-time.Minute)) {
		return q, fmt.Errorf("query must be inside the retained seven days")
	}
	if strings.ContainsAny(q.SensorID+q.CampusID+q.ApplicationID, "\x00\n") {
		return q, fmt.Errorf("invalid filter")
	}
	return q, nil
}

type applicationExportWriter struct {
	http.ResponseWriter
	started bool
}

func (w *applicationExportWriter) Write(b []byte) (int, error) {
	w.started = true
	return w.ResponseWriter.Write(b)
}
