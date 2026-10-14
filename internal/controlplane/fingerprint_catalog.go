package controlplane

import (
	"context"
	"net/http"
	"proxy-sentinel/internal/fingerprint"
	"slices"
	"strconv"
	"strings"
)

type fingerprintCoverageReader interface {
	FingerprintSourceCoverage(context.Context) (map[string]any, error)
}

func (s *Server) handleFingerprintCatalog(w http.ResponseWriter, r *http.Request, path string) {
	c := fingerprint.Default().Catalog()
	sources := fingerprint.SourceDirectory(s.fingerprints.Status())
	switch {
	case path == "/device-fingerprint-library/sources":
		q := r.URL.Query()
		page, size := 1, 100
		if value := q.Get("page"); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 || n > 1000000 {
				writeError(w, 400, "invalid_pagination", "分页参数无效")
				return
			}
			page = n
		}
		if value := q.Get("page_size"); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 {
				writeError(w, 400, "invalid_pagination", "分页参数无效")
				return
			}
			size = min(n, 100)
		}
		items := []fingerprint.FingerprintSource{}
		for _, src := range sources {
			if q.Get("status") != "" && src.Status != q.Get("status") {
				continue
			}
			if q.Get("protocol") != "" && !slices.Contains(src.Protocols, q.Get("protocol")) {
				continue
			}
			if q.Get("role") != "" && !slices.Contains(src.Categories, q.Get("role")) {
				continue
			}
			items = append(items, src)
		}
		total := len(items)
		start := min((page-1)*size, total)
		end := min(start+size, total)
		writeJSON(w, 200, map[string]any{"items": items[start:end], "version": c.Version, "total": total, "page": page, "page_size": size})
	case strings.HasPrefix(path, "/device-fingerprint-library/sources/"):
		id := strings.TrimPrefix(path, "/device-fingerprint-library/sources/")
		for _, src := range sources {
			if src.ID == id {
				writeJSON(w, 200, src)
				return
			}
		}
		writeError(w, 404, "source_not_found", "指纹来源不存在")
	case path == "/device-fingerprint-library/rules":
		q := r.URL.Query()
		page, _ := strconv.Atoi(q.Get("page"))
		size, _ := strconv.Atoi(q.Get("page_size"))
		if page > 1000000 || page < 0 || size < 0 {
			writeError(w, 400, "invalid_pagination", "分页参数无效")
			return
		}
		writeJSON(w, 200, c.Search(fingerprint.CatalogQuery{Source: q.Get("source"), Search: q.Get("q"), Protocol: q.Get("protocol"), Role: q.Get("role"), Status: q.Get("status"), Page: page, PageSize: size}))
	case path == "/device-fingerprint-library/coverage":
		if reader, ok := s.reader.(fingerprintCoverageReader); ok {
			data, err := reader.FingerprintSourceCoverage(r.Context())
			if err != nil {
				writeError(w, 503, "coverage_unavailable", "指纹覆盖统计暂不可用")
				return
			}
			writeJSON(w, 200, data)
			return
		}
		writeJSON(w, 200, map[string]any{"status": "unavailable", "items": []any{}, "window": "24h"})
	default:
		writeError(w, 404, "not_found", "接口不存在")
	}
}
