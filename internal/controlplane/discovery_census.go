package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/census"
)

func (s *Server) censusQuery(r *http.Request) (census.Query, error) {
	v := r.URL.Query()
	q := census.Query{SensorID: s.sensorID, CampusID: strings.TrimSpace(v.Get("campus_id")), AccessDomain: strings.TrimSpace(v.Get("access_domain")), VLAN: strings.TrimSpace(v.Get("vlan")), VRF: strings.TrimSpace(v.Get("vrf")), Kind: v.Get("kind"), TerminalStatus: v.Get("terminal_status"), Cursor: v.Get("cursor")}
	if v.Get("sensor_id") != "" && v.Get("sensor_id") != s.sensorID {
		return q, errors.New("sensor_id does not match this sensor")
	}
	if q.Kind != "" && q.Kind != "ip" && q.Kind != "mac" && q.Kind != "binding" && q.Kind != "terminal" {
		return q, errors.New("invalid census kind")
	}
	if q.TerminalStatus != "" && (q.Kind != "terminal" || q.TerminalStatus != "identified" && q.TerminalStatus != "candidate" && q.TerminalStatus != "conflict" && q.TerminalStatus != "expired") {
		return q, errors.New("invalid census terminal status")
	}
	switch v.Get("window") {
	case "", "24h":
		q.Window = 24 * time.Hour
	case "7d":
		q.Window = 7 * 24 * time.Hour
	case "30d":
		q.Window = 30 * 24 * time.Hour
	default:
		return q, errors.New("invalid census window")
	}
	if raw := v.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 200 {
			return q, errors.New("invalid census page size")
		}
		q.Limit = limit
	}
	for _, value := range []string{q.CampusID, q.AccessDomain, q.VLAN, q.VRF} {
		if len(value) > 128 {
			return q, errors.New("census scope filter is too long")
		}
	}
	return q, nil
}

func (s *Server) handleDiscoveryCensus(w http.ResponseWriter, r *http.Request, path string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "仅支持只读查询")
		return
	}
	q, err := s.censusQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_census_query", err.Error())
		return
	}
	budget := 2 * time.Second
	if path == "/discovery/census/compare-stream" {
		budget = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(r.Context(), budget)
	defer cancel()
	repo := census.Repository{DB: s.operations.db, HardwareV2: discoveryHardwareReadEnabled()}
	switch path {
	case "/discovery/census/summary":
		result, err := repo.GetSummary(ctx, q)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "census_summary", "读取镜像标识统计失败")
			return
		}
		writeJSON(w, http.StatusOK, result)
	case "/discovery/census/identifiers":
		result, err := repo.GetPage(ctx, q)
		if err != nil {
			if strings.Contains(err.Error(), "cursor") {
				writeError(w, http.StatusBadRequest, "bad_census_cursor", err.Error())
			} else {
				writeError(w, http.StatusInternalServerError, "census_page", "读取镜像标识清单失败")
			}
			return
		}
		writeJSON(w, http.StatusOK, result)
	case "/discovery/census/compare-stream":
		s.streamDiscoveryCensus(w, ctx, q)
	default:
		writeError(w, http.StatusNotFound, "not_found", "接口不存在")
	}
}

// A repeatable-read transaction pins every count and row to one read-only
// snapshot. Each bounded page is emitted before the next one is requested.
func (s *Server) streamDiscoveryCensus(w http.ResponseWriter, ctx context.Context, q census.Query) {
	tx, err := s.operations.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "census_snapshot", "创建只读快照失败")
		return
	}
	defer tx.Rollback()
	repo := census.Repository{DB: tx, HardwareV2: discoveryHardwareReadEnabled()}
	summary, err := repo.GetSummary(ctx, q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "census_snapshot", "读取只读快照失败")
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="passive-census.ndjson"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	flush, _ := w.(http.Flusher)
	emit := func(value any) bool {
		return enc.Encode(value) == nil
	}
	if !emit(map[string]any{"record": "manifest", "summary": summary}) {
		return
	}
	if flush != nil {
		flush.Flush()
	}
	counts := map[string]int64{"ip": 0, "ipv4": 0, "ipv6": 0, "mac": 0, "random_mac": 0, "binding": 0, "terminal": 0, "identified_terminal": 0, "candidate_terminal": 0, "conflict_terminal": 0, "expired_terminal": 0}
	const maxRows = 2_000_000
	var total int64
	for _, kind := range []string{"ip", "mac", "binding", "terminal"} {
		pageQuery := q
		pageQuery.Kind, pageQuery.TerminalStatus, pageQuery.Limit, pageQuery.Cursor = kind, "", 200, ""
		for {
			page, pageErr := repo.GetPage(ctx, pageQuery)
			if pageErr != nil {
				_ = emit(map[string]any{"record": "error", "code": "census_page", "message": pageErr.Error()})
				if flush != nil {
					flush.Flush()
				}
				return
			}
			for _, row := range page.Items {
				if total >= maxRows {
					_ = emit(map[string]any{"record": "error", "code": "census_limit", "message": "比较导出超过 2,000,000 行"})
					if flush != nil {
						flush.Flush()
					}
					return
				}
				if !emit(map[string]any{"record": "item", "item": row}) {
					return
				}
				counts[kind]++
				if kind == "ip" {
					if row.IPFamily == 4 {
						counts["ipv4"]++
					} else if row.IPFamily == 6 {
						counts["ipv6"]++
					}
				} else if kind == "mac" && row.RandomMAC {
					counts["random_mac"]++
				} else if kind == "terminal" {
					switch row.ClassificationStatus {
					case "identified":
						counts["identified_terminal"]++
					case "candidate":
						counts["candidate_terminal"]++
					case "conflict":
						counts["conflict_terminal"]++
					case "expired":
						counts["expired_terminal"]++
					}
				}
				total++
			}
			if flush != nil {
				flush.Flush()
			}
			if !page.HasMore {
				break
			}
			pageQuery.Cursor = page.NextCursor
		}
	}
	if err = tx.Commit(); err != nil {
		_ = emit(map[string]any{"record": "error", "code": "census_commit", "message": "只读快照结束失败"})
		if flush != nil {
			flush.Flush()
		}
		return
	}
	_ = emit(map[string]any{"record": "end", "counts": counts, "complete": true})
	if flush != nil {
		flush.Flush()
	}
}
