package controlplane

import (
	"context"
	"net/http"
	"strings"

	"proxy-sentinel/internal/store"
)

type auditSeekReader interface {
	ListAuditLogsSeek(context.Context, int, string, string) (store.AuditSeekPage, error)
}

type auditDetailReader interface {
	GetAuditLog(context.Context, string) (store.AuditLog, bool, error)
}

func (s *Server) handleAuditLogsSeek(w http.ResponseWriter, r *http.Request, reader auditSeekReader) {
	limit, err := boundedInt(r.URL.Query().Get("limit"), 20, 1, 50)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_limit", err.Error())
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	page, err := reader.ListAuditLogsSeek(ctx, limit, r.URL.Query().Get("cursor"), strings.TrimSpace(r.URL.Query().Get("q")))
	if err != nil {
		code := http.StatusServiceUnavailable
		label := "read_audit_logs_failed"
		if strings.Contains(err.Error(), "invalid audit cursor") {
			code, label = http.StatusBadRequest, "bad_cursor"
		}
		writeError(w, code, label, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) handleAuditLogDirect(w http.ResponseWriter, r *http.Request, rawAuditID string, reader auditDetailReader) {
	auditID, err := store.DecodePathIP(rawAuditID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_audit_id", err.Error())
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	item, ok, err := reader.GetAuditLog(ctx, auditID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "read_audit_logs_failed", err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "audit log not found")
		return
	}
	writeJSON(w, http.StatusOK, AuditLog{AuditID: item.AuditID, Actor: item.Actor, Action: item.Action, Target: item.Target, Outcome: item.Outcome, CreatedAt: item.CreatedAt})
}
