package controlplane

import (
	"net/http"
	"strconv"
	"strings"

	"proxy-sentinel/internal/store"
)

func (s *Server) handleSharedBehavior(w http.ResponseWriter, r *http.Request, path string) {
	reader, ok := s.reader.(store.SharedBehaviorReader)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "shared_behavior_unavailable", "共享行为观察存储不可用")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	parts := strings.Split(strings.Trim(strings.TrimPrefix(path, "/shared-access/observations"), "/"), "/")
	if len(parts) == 1 && parts[0] != "" {
		item, found, err := reader.GetSharedBehavior(ctx, parts[0])
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "shared_behavior_unavailable", "共享行为观察读取失败")
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, "shared_behavior_not_found", "共享行为观察不存在")
			return
		}
		writeJSON(w, http.StatusOK, item)
		return
	}
	if parts[0] != "" {
		writeError(w, http.StatusNotFound, "shared_behavior_not_found", "共享行为观察不存在")
		return
	}
	query := store.SharedBehaviorQuery{
		Keyword: r.URL.Query().Get("keyword"), IP: r.URL.Query().Get("ip"), Status: r.URL.Query().Get("status"),
		CoverageState: r.URL.Query().Get("coverage_state"), View: r.URL.Query().Get("view"), HistoryBasis: r.URL.Query().Get("history_basis"), Limit: 20,
	}
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_pagination", "limit 必须为整数")
			return
		}
		query.Limit = parsed
	}
	if value := r.URL.Query().Get("cursor"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_pagination", "cursor 必须为整数")
			return
		}
		query.Cursor = parsed
	}
	if value := r.URL.Query().Get("confidence_min"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_confidence", "confidence_min 必须为整数")
			return
		}
		query.ConfidenceMin = &parsed
	}
	page, err := reader.ListSharedBehavior(ctx, query)
	if err != nil {
		writeError(w, http.StatusBadRequest, "shared_behavior_query_invalid", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) handleSharedDeviceProfiles(w http.ResponseWriter, r *http.Request) {
	reader, ok := s.reader.(store.SharedDeviceProfileReader)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "shared_device_profiles_unavailable", "设备档案存储不可用")
		return
	}
	q := store.SharedDeviceProfileQuery{Keyword: r.URL.Query().Get("keyword"), Limit: 20}
	for _, param := range []string{"limit", "cursor"} {
		if value := r.URL.Query().Get(param); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil {
				writeError(w, http.StatusBadRequest, "bad_pagination", "分页参数必须为整数")
				return
			}
			if param == "limit" {
				q.Limit = n
			} else {
				q.Cursor = n
			}
		}
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	page, err := reader.ListSharedDeviceProfiles(ctx, q)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "shared_device_profiles_unavailable", "设备档案读取失败")
		return
	}
	writeJSON(w, http.StatusOK, page)
}
