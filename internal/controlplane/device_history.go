package controlplane

import (
	"net/http"
	"proxy-sentinel/internal/devicehistory"
	"proxy-sentinel/internal/discovery"
	"strings"
	"time"
)

func (s *Server) handleDeviceHistory(w http.ResponseWriter, r *http.Request, path string) {
	parts := strings.Split(strings.TrimPrefix(path, "/device-history/"), "/")
	if len(parts) != 2 || parts[1] == "" {
		writeError(w, 400, "bad_history", "历史对象无效")
		return
	}
	limit, e := boundedInt(r.URL.Query().Get("limit"), 20, 1, 100)
	if e != nil {
		writeError(w, 400, "bad_page", "分页参数无效")
		return
	}
	offset, e := boundedInt(r.URL.Query().Get("offset"), 0, 0, 1000000)
	if e != nil {
		writeError(w, 400, "bad_page", "分页参数无效")
		return
	}
	switch parts[0] {
	case "router", "router_evidence", "profile", "shared", "discovery", "endpoint", "access", "endpoint_discovery":
	default:
		writeError(w, 400, "bad_history", "历史类型无效")
		return
	}
	q := devicehistory.Query{Kind: parts[0], ID: parts[1], Limit: limit, Offset: offset, Group: r.URL.Query().Get("group")}
	if v := r.URL.Query().Get("as_of"); v != "" {
		q.AsOf, e = time.Parse(time.RFC3339Nano, v)
		if e != nil || q.AsOf.After(time.Now().Add(time.Minute)) {
			writeError(w, 400, "bad_time", "时间无效")
			return
		}
	}
	if s.operations == nil || s.operations.db == nil {
		writeError(w, 503, "history_storage", "历史存储不可用")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	if q.Kind == "discovery" {
		repo := discovery.Repository{DB: s.operations.db, DeviceCache: s.discoveryDevices}
		q.Keys, e = repo.HistoryKeys(ctx, q.ID)
		if e != nil {
			writeError(w, 500, "history_identity", "读取设备身份失败")
			return
		}
	}
	page, e := devicehistory.Read(ctx, s.operations.db, q)
	if e != nil {
		writeError(w, 500, "history_read", "读取历史失败")
		return
	}
	writeJSON(w, 200, page)
}
