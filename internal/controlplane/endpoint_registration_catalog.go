package controlplane

import (
	"net/http"
	"strconv"

	"proxy-sentinel/internal/store"
)

func (s *Server) handleEndpointRegistrationCatalog(w http.ResponseWriter, r *http.Request, metadata bool) {
	values := r.URL.Query()
	if values.Has("offset") {
		writeError(w, 400, "bad_registration_query", "登记台账使用游标分页")
		return
	}
	q := store.EndpointRegistrationQuery{Search: values.Get("search"), Status: values.Get("status"), DeviceType: values.Get("type"), OwnershipClass: values.Get("ownership_class"), MAC: values.Get("mac"), Cursor: values.Get("cursor")}
	if raw := values.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, 400, "bad_registration_query", "分页数量无效")
			return
		}
		q.Limit = n
		if n == 0 {
			writeError(w, 400, "bad_registration_query", "分页数量无效")
			return
		}
	}
	if metadata {
		q.Cursor = ""
	}
	var err error
	if q, err = store.NormalizeEndpointRegistrationQuery(q); err != nil {
		writeError(w, 400, "bad_registration_query", err.Error())
		return
	}
	reader, ok := s.reader.(store.EndpointRegistrationCatalogReader)
	if !ok {
		writeError(w, 503, "registration_catalog_unavailable", "登记台账存储不可用")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	if metadata {
		result, err := reader.EndpointRegistrationMetadata(ctx, q)
		if err != nil {
			writeError(w, 500, "registration_metadata_failed", "读取登记统计失败")
			return
		}
		writeJSON(w, 200, result)
		return
	}
	result, err := reader.ListEndpointRegistrations(ctx, q)
	if err != nil {
		writeError(w, 500, "registration_catalog_failed", "读取登记台账失败")
		return
	}
	writeJSON(w, 200, result)
}
