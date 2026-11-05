package controlplane

import (
	"net/http"
	"strconv"

	"proxy-sentinel/internal/pagination"
)

func pagePositionParameters(r *http.Request) (page, limit int, err error) {
	page, limit = 1, 20
	if raw := r.URL.Query().Get("page"); raw != "" {
		page, err = strconv.Atoi(raw)
		if err != nil {
			return
		}
	}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil {
			return
		}
	}
	_, err = pagination.BoundaryOffset(page, limit)
	return
}
