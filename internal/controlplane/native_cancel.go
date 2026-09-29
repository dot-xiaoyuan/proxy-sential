package controlplane

import (
	"context"
	"net/http"
	"time"

	"proxy-sentinel/internal/srunapi"
)

// Cancellation stops future dispatch; it cannot undo an already sent disconnect.
// Persist the action gate first, then the journal tombstone. A failed tombstone
// remains retryable through the same endpoint while the action stays blocked.
func (s *Server) handleNativeCancel(w http.ResponseWriter, r *http.Request, id string) bool {
	s.operations.mu.Lock()
	a, ok := s.operations.doc.Actions[id]
	_, configured := s.nativeActions[a.ConnectorID]
	if !ok || (!configured && !a.PolicyParameters.NativeSelected && a.PolicyParameters.NativeIntent == nil) {
		s.operations.mu.Unlock()
		return false
	}
	if a.Status == "succeeded" {
		s.operations.mu.Unlock()
		writeError(w, http.StatusConflict, "disconnect_not_reversible", "已完成的下线无法恢复原会话；一次性下线不禁止重新登录")
		return true
	}
	if s.operations.lockErr != nil || s.operations.db == nil {
		s.operations.mu.Unlock()
		writeError(w, http.StatusServiceUnavailable, "native_cancel_unavailable", "原生动作持久化不可用")
		return true
	}
	a.PolicyParameters.NativeSelected = true
	a.Status = "blocked"
	a.NextAttemptAt = ""
	a.ExpiresAt = ""
	a.UpdatedAt = formatDBTime(time.Now().UTC())
	a.LastError = "已请求停止原生下线；已发出的请求无法撤回，请核对执行记录和在线会话"
	s.operations.doc.Actions[id] = a
	err := s.operations.saveLocked()
	db := s.operations.db
	s.operations.mu.Unlock()
	if err != nil {
		writeError(w, 500, "native_cancel_save_failed", "停止请求保存失败")
		return true
	}
	if a.PolicyParameters.NativeIntent != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		err = (srunapi.Journal{DB: db}).Cancel(ctx, *a.PolicyParameters.NativeIntent)
		cancel()
		if err != nil {
			writeError(w, 503, "native_cancel_journal_failed", "动作已停止调度，但取消登记尚未完成，请重试")
			return true
		}
	}
	s.appendAudit(r.Context(), "enforcement.native_cancel", id, "dispatch stopped; sent request may still take effect")
	writeJSON(w, http.StatusAccepted, a)
	return true
}
