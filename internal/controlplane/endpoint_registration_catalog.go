package controlplane

import (
	"errors"
	"net/http"
	"proxy-sentinel/internal/pagination"
	"strconv"

	"proxy-sentinel/internal/store"
)

func (s *Server) handleEndpointRegistrationCatalog(w http.ResponseWriter, r *http.Request, metadata bool) {
	s.handleEndpointRegistrationCatalogMode(w, r, metadata, false)
}

func (s *Server) handleEndpointRegistrationCatalogMode(w http.ResponseWriter, r *http.Request, metadata, position bool) {
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
	if metadata || position {
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
	if position {
		page, size, err := pagePositionParameters(r)
		if err != nil {
			writeError(w, 400, "bad_page", "页码或页长无效")
			return
		}
		q.Limit = size
		locator, ok := s.reader.(store.EndpointRegistrationPositionReader)
		if !ok {
			writeError(w, 503, "registration_position_unavailable", "登记台账页码定位不可用")
			return
		}
		result, err := locator.EndpointRegistrationPosition(ctx, q, page)
		if errors.Is(err, pagination.ErrPageOutOfRange) {
			writeError(w, 400, "page_out_of_range", "目标页已不存在，请刷新列表")
			return
		}
		if err != nil {
			writeError(w, 500, "registration_position_failed", "读取登记台账页码位置失败")
			return
		}
		writeJSON(w, 200, result)
		return
	}
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
