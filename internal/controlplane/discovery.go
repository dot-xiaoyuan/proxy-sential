package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/fingerprint"
	"proxy-sentinel/internal/pagination"
	"proxy-sentinel/internal/store"
	"sort"
	"strconv"
	"strings"
	"time"
)

func snmpCandidateReason(ip, manufacturer, fallback string) string {
	if strings.HasSuffix(ip, ".254") {
		return "网段网关候选"
	}
	vendor := strings.ToLower(manufacturer)
	for _, name := range []string{"h3c", "huawei", "ruijie", "cisco", "juniper", "aruba", "hp", "dell", "zyxel", "tp-link"} {
		if strings.Contains(vendor, name) {
			return "网络设备厂商候选"
		}
	}
	return fallback
}

func snmpCandidateScore(item map[string]any) int {
	reason, _ := item["reason"].(string)
	score := 0
	if reason == "网段网关候选" {
		score += 100
	}
	if reason == "网络设备厂商候选" {
		score += 30
	}
	if observations, ok := item["observations"].(int); ok {
		score += observations * 3
	}
	name, _ := item["name"].(string)
	if name == "" {
		score += 20
	}
	lower := strings.ToLower(name)
	for _, client := range []string{"vivo", "oppo", "redmi", "honor", "huawei", "nova", "xiaomi", "iphone", "ipad", "laptop", "desktop", "iqoo", "realme"} {
		if strings.Contains(lower, client) {
			score -= 40
			break
		}
	}
	return score
}

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request, path string) {
	if strings.HasPrefix(path, "/discovery/scan-profiles") {
		s.handleDiscoveryActive(w, r, path)
		return
	}
	if s.operations == nil || s.operations.db == nil {
		writeError(w, 503, "discovery_storage", "网络设备发现需要 PostgreSQL")
		return
	}
	if r.Method != "GET" && s.readOnly {
		writeError(w, 403, "read_only", "只读模式不允许配置发现任务")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	repo := discovery.Repository{DB: s.operations.db, DeviceCache: s.discoveryDevices, PipelineV2: os.Getenv("PROXY_SENTINEL_DISCOVERY_V2") == "true", ActiveStreamOnly: discoveryStreamCurrentReadEnabled()}
	limit, offset := 50, 0
	if v := r.URL.Query().Get("limit"); v != "" && path != "/discovery/devices/metadata" {
		n, e := strconv.Atoi(v)
		if e != nil || n < 1 || n > 200 {
			writeError(w, 400, "bad_page", "分页参数无效")
			return
		}
		limit = n
	}
	if v := r.URL.Query().Get("offset"); v != "" && path != "/discovery/devices/metadata" {
		if path == "/discovery/devices" {
			writeError(w, 400, "bad_cursor", "发现记录已改用游标分页，请删除 offset 参数")
			return
		}
		n, e := strconv.Atoi(v)
		if e != nil || n < 0 {
			writeError(w, 400, "bad_page", "分页参数无效")
			return
		}
		offset = n
	}
	switch {
	case path == "/discovery/chassis-candidates" && r.Method == "GET":
		window := 24 * time.Hour
		if value := r.URL.Query().Get("window"); value != "" {
			_, duration, e := store.NormalizeActivityWindow(value)
			if e != nil {
				writeError(w, 400, "bad_window", "时间窗口无效")
				return
			}
			window = duration
		}
		items, e := repo.ChassisCandidates(ctx, window)
		if e != nil {
			writeError(w, 500, "chassis_candidates", "读取同机箱候选失败")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case path == "/discovery/types" && r.Method == "GET":
		writeJSON(w, 200, map[string]any{"version": discovery.IoTRuleVersion, "items": discovery.DeviceTypes})
	case path == "/discovery/statistics" && r.Method == "GET":
		if !repo.PipelineV2 {
			// The indexed read path has no legacy statistics summary. Return an
			// empty result instead of an error so the diagnostics section does
			// not show a permanent failure on deployments that read the index.
			writeJSON(w, 200, map[string]any{"items": []any{}, "pending_updates": 0})
			return
		}
		result, e := repo.DiscoveryStatistics(ctx)
		if e != nil {
			writeError(w, 500, "statistics_read", "读取发现统计失败")
			return
		}
		writeJSON(w, 200, result)
	case path == "/discovery/coverage" && r.Method == "GET":
		s.handleDiscoveryCoverage(w, r, repo)
	case (path == "/discovery/history" || path == "/discovery/history/metadata" || path == "/discovery/history/position") && r.Method == "GET":
		key := r.URL.Query().Get("device_id")
		if strings.TrimSpace(key) == "" || len(key) > 1024 {
			writeError(w, 400, "bad_cursor", "设备和历史游标无效")
			return
		}
		snapshot, e := readPaginationSnapshot(r)
		if e != nil {
			writeError(w, 400, "bad_snapshot", e.Error())
			return
		}
		var result any
		switch path {
		case "/discovery/history/metadata":
			result, e = repo.DiscoveryHistoryMetadata(ctx, key, snapshot)
		case "/discovery/history/position":
			var number int
			number, e = boundedInt(r.URL.Query().Get("page"), 1, 1, 1_000_000_000)
			if e != nil {
				writeError(w, 400, "bad_page", e.Error())
				return
			}
			limit, e = boundedInt(r.URL.Query().Get("limit"), 20, 1, 100)
			if e != nil {
				writeError(w, 400, "bad_page", e.Error())
				return
			}
			result, e = repo.DiscoveryHistoryPosition(ctx, key, snapshot, number, limit)
		default:
			if limit > 100 {
				writeError(w, 400, "bad_page", "历史页大小必须为 1 至 100")
				return
			}
			result, e = repo.DiscoveryHistoryAt(ctx, key, r.URL.Query().Get("cursor"), limit, snapshot)
		}
		if e != nil {
			if errors.Is(e, pagination.ErrPageOutOfRange) {
				writeError(w, 400, "page_out_of_range", e.Error())
				return
			}
			if strings.Contains(e.Error(), "cursor") {
				writeError(w, 400, "bad_cursor", e.Error())
				return
			}
			writeError(w, 500, "history_read", "读取设备历史失败")
			return
		}
		writeJSON(w, 200, result)
	case path == "/discovery/nodes" && r.Method == "GET":
		rows, err := repo.DB.QueryContext(ctx, `SELECT node,last_seen,last_seen>now()-interval '30 seconds' FROM discovery_nodes ORDER BY node`)
		if err != nil {
			writeError(w, 500, "node_read", "读取采集节点失败")
			return
		}
		defer rows.Close()
		items := []map[string]any{}
		for rows.Next() {
			var node string
			var at time.Time
			var online bool
			if err = rows.Scan(&node, &at, &online); err != nil {
				writeError(w, 500, "node_read", "读取采集节点失败")
				return
			}
			items = append(items, map[string]any{"node": node, "last_seen": at, "available": online})
		}
		if rows.Err() != nil {
			writeError(w, 500, "node_read", "读取采集节点失败")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case path == "/discovery/endpoint-evidence" && r.Method == "GET":
		page, err := repo.EndpointEvidence(ctx, r.URL.Query().Get("endpoint_id"), limit, offset)
		if err != nil {
			writeError(w, 500, "discovery_read", "读取发现证据失败")
			return
		}
		writeJSON(w, 200, page)
	case path == "/discovery/passive-signals" && r.Method == "GET":
		s.handleDiscoveryPassiveSignals(w, r, repo)
	case path == "/discovery/handshake-clues" && r.Method == "GET":
		reader, ok := s.reader.(store.DiscoveryHandshakeClueReader)
		if !ok {
			writeJSON(w, 200, map[string]any{"items": []store.DiscoveryHandshakeClue{}})
			return
		}
		scope := store.SharedObservationScope{
			SensorID:     r.URL.Query().Get("sensor_id"),
			CampusID:     r.URL.Query().Get("campus_id"),
			AccessDomain: r.URL.Query().Get("access_domain"),
			IP:           r.URL.Query().Get("ip"),
		}
		if scope.SensorID == "" || scope.CampusID == "" || scope.AccessDomain == "" || scope.IP == "" || len(scope.SensorID) > 128 || len(scope.CampusID) > 128 || len(scope.AccessDomain) > 128 {
			writeError(w, 400, "invalid_scope", "缺少有效的设备观测范围")
			return
		}
		mapped, matched, err := mappedDiscoveryHandshakeScope(os.Getenv("PROXY_SENTINEL_DISCOVERY_HANDSHAKE_SCOPE_MAP"), scope)
		if err != nil {
			writeError(w, 500, "discovery_scope_map", "握手观测范围配置无效")
			return
		}
		if !matched {
			writeJSON(w, 200, map[string]any{"items": []store.DiscoveryHandshakeClue{}})
			return
		}
		readCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		items, err := reader.DiscoveryHandshakeClues(readCtx, mapped, time.Now().UTC())
		cancel()
		if err != nil {
			writeError(w, 500, "discovery_read", "读取握手弱线索失败")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case path == "/discovery/service-clues" && r.Method == "GET":
		reader, ok := s.reader.(store.DiscoveryServiceClueReader)
		if !ok {
			writeJSON(w, 200, map[string]any{"items": map[string]any{}})
			return
		}
		targets := splitList(r.URL.Query().Get("targets"), 50)
		readCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		items, err := reader.DiscoveryServiceClues(readCtx, targets, time.Now().UTC().Add(-2*time.Hour))
		cancel()
		if err != nil {
			writeError(w, 500, "discovery_read", "读取被动服务线索失败")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case path == "/discovery/observed-ports" && r.Method == "GET":
		reader, ok := s.reader.(store.DiscoveryObservedFlowPortReader)
		if !ok {
			writeJSON(w, 200, map[string]any{"items": map[string]any{}})
			return
		}
		targets := splitList(r.URL.Query().Get("targets"), 50)
		readCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		items, err := reader.DiscoveryObservedFlowPorts(readCtx, targets, time.Now().UTC().Add(-2*time.Hour))
		cancel()
		if err != nil {
			writeError(w, 500, "discovery_read", "读取目标端口线索失败")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case path == "/discovery/snmp-candidates" && r.Method == "GET":
		currentRelation := "discovery_device_current_shadow"
		if repo.ActiveStreamOnly {
			currentRelation = discovery.StreamCurrentRelation
		}
		rows, err := repo.DB.QueryContext(ctx, `WITH frequent AS (
 SELECT document->>'mac' AS mac
 FROM `+currentRelation+`
 WHERE coalesce(document->>'last_observed_ip','')<>'' AND coalesce(document->>'mac','')<>''
 GROUP BY 1 HAVING count(DISTINCT document->>'last_observed_ip')>3
), candidates AS (
 SELECT document->>'last_observed_ip' AS ip,
        max(document->>'name') AS name,
        max(document->>'mac') AS mac,
        max(document->>'manufacturer') AS manufacturer,
        max(document->>'vlan') AS vlan,
        max(document->>'domain') AS domain,
        max(document->>'sensor_id') AS sensor_id,
        max(document->>'site') AS site,
        max(last_seen) AS last_seen,
        count(*) AS observations,
        CASE WHEN split_part(document->>'last_observed_ip','.',4) IN ('1','254') THEN '网段网关候选' ELSE '高频基础设施 MAC' END AS reason
 FROM `+currentRelation+`
 WHERE coalesce(document->>'last_observed_ip','')<>''
   AND (split_part(document->>'last_observed_ip','.',4) IN ('1','254') OR document->>'mac' IN (SELECT mac FROM frequent))
 GROUP BY document->>'last_observed_ip',
          CASE WHEN split_part(document->>'last_observed_ip','.',4) IN ('1','254') THEN '网段网关候选' ELSE '高频基础设施 MAC' END
)
SELECT ip,coalesce(name,''),coalesce(mac,''),coalesce(manufacturer,''),coalesce(vlan,''),coalesce(domain,''),coalesce(sensor_id,''),coalesce(site,''),last_seen,observations,reason
FROM candidates ORDER BY observations DESC,last_seen DESC LIMIT 100`)
		if err != nil {
			writeError(w, 500, "discovery_read", "读取 SNMP 候选失败")
			return
		}
		defer rows.Close()
		items := []map[string]any{}
		for rows.Next() {
			var ip, name, mac, manufacturer, vlan, domain, sensor, site, reason string
			var lastSeen time.Time
			var observations int
			if err = rows.Scan(&ip, &name, &mac, &manufacturer, &vlan, &domain, &sensor, &site, &lastSeen, &observations, &reason); err != nil {
				writeError(w, 500, "discovery_read", "读取 SNMP 候选失败")
				return
			}
			if strings.TrimSpace(manufacturer) == "" {
				manufacturer = fingerprint.Default().Identify(mac).Vendor
			}
			reason = snmpCandidateReason(ip, manufacturer, reason)
			items = append(items, map[string]any{"ip": ip, "name": name, "mac": mac, "manufacturer": manufacturer, "vlan": vlan, "domain": domain, "sensor_id": sensor, "site": site, "last_seen": lastSeen, "observations": observations, "reason": reason})
		}
		if rows.Err() != nil {
			writeError(w, 500, "discovery_read", "读取 SNMP 候选失败")
			return
		}
		sort.SliceStable(items, func(i, j int) bool {
			return snmpCandidateScore(items[i]) > snmpCandidateScore(items[j])
		})
		writeJSON(w, 200, map[string]any{"items": items})
	case path == "/discovery/sources" && r.Method == "GET":
		rows, err := repo.DB.QueryContext(ctx, `SELECT config FROM discovery_sources ORDER BY id`)
		if err != nil {
			writeError(w, 500, "discovery_read", "读取接入源失败")
			return
		}
		defer rows.Close()
		items := []json.RawMessage{}
		for rows.Next() {
			var b json.RawMessage
			if err = rows.Scan(&b); err != nil {
				writeError(w, 500, "discovery_read", "读取接入源失败")
				return
			}
			items = append(items, b)
		}
		if rows.Err() != nil {
			writeError(w, 500, "discovery_read", "读取接入源失败")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case path == "/discovery/sources" && r.Method == "POST":
		var req struct {
			Source          discovery.Source `json:"source"`
			Secret          discovery.Secret `json:"secret"`
			ExpectedVersion int              `json:"expected_version"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
		dec.DisallowUnknownFields()
		if dec.Decode(&req) != nil {
			writeError(w, 400, "bad_source", "接入源配置无效")
			return
		}
		if err := req.Source.Validate(); err != nil {
			writeError(w, 400, "bad_source", err.Error())
			return
		}
		tx, err := repo.DB.BeginTx(ctx, nil)
		if err != nil {
			writeError(w, 500, "source_save", "保存失败")
			return
		}
		defer tx.Rollback()
		if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "discovery-source:"+req.Source.ID); err != nil {
			writeError(w, 500, "source_save", "保存失败")
			return
		}
		var version int
		var encrypted string
		err = tx.QueryRowContext(ctx, `SELECT config_version,encrypted_secret FROM discovery_sources WHERE id=$1`, req.Source.ID).Scan(&version, &encrypted)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			writeError(w, 500, "source_save", "保存失败")
			return
		}
		if version != req.ExpectedVersion {
			writeError(w, 409, "version_conflict", "配置已变化，请刷新后重试")
			return
		}
		if req.Secret.Community != "" || req.Secret.Auth != "" || req.Secret.Privacy != "" {
			b, _ := json.Marshal(req.Secret)
			encrypted, err = s.encryptConnectorSecret(string(b))
			if err != nil {
				writeError(w, 503, "encryption_unavailable", "凭据加密不可用")
				return
			}
		}
		if encrypted == "" {
			writeError(w, 400, "secret_required", "需要 SNMP 只读凭据")
			return
		}
		req.Source.ConfigVersion = version + 1
		b, _ := json.Marshal(req.Source)
		_, err = tx.ExecContext(ctx, `INSERT INTO discovery_sources(id,config,encrypted_secret,config_version,node,enabled) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO UPDATE SET config=EXCLUDED.config,encrypted_secret=EXCLUDED.encrypted_secret,config_version=EXCLUDED.config_version,node=EXCLUDED.node,enabled=EXCLUDED.enabled,updated_at=now(),next_poll=now()`, req.Source.ID, b, encrypted, req.Source.ConfigVersion, req.Source.Node, req.Source.Enabled)
		if err == nil {
			_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(audit_id,actor,action,target,outcome,created_at) VALUES($1,$2,'discovery.source.configure',$3,'saved',now())`, "discovery-"+shortToken(16), sessionFromContext(ctx).User.ID, req.Source.ID)
		}
		if err != nil {
			writeError(w, 500, "source_save", "保存失败")
			return
		}
		if tx.Commit() != nil {
			writeError(w, 500, "source_save", "保存失败")
			return
		}
		writeJSON(w, 200, req.Source)
	case strings.HasPrefix(path, "/discovery/sources/") && strings.HasSuffix(path, "/poll") && r.Method == "POST":
		source := strings.TrimSuffix(strings.TrimPrefix(path, "/discovery/sources/"), "/poll")
		id := "poll-" + shortToken(24)
		if err := repo.EnqueuePoll(ctx, id, source); err != nil {
			writeError(w, 409, "poll_pending", err.Error())
			return
		}
		s.appendAudit(ctx, "discovery.poll", source, "queued")
		writeJSON(w, 202, map[string]string{"id": id, "status": "pending"})
	case path == "/discovery/receipt" && r.Method == "GET":
		epoch, scope, eventKey := r.URL.Query().Get("epoch"), r.URL.Query().Get("scope_id"), r.URL.Query().Get("event_key")
		if epoch == "" || scope == "" || eventKey == "" || len(epoch) > 128 || len(scope) > 256 || len(eventKey) > 512 {
			writeError(w, 400, "bad_receipt_key", "事件回执定位信息无效")
			return
		}
		receipt, found, err := repo.StreamDiscoveryReceipt(ctx, epoch, scope, eventKey)
		if err != nil {
			writeError(w, 500, "receipt_read", "读取事件回执失败")
			return
		}
		if !found {
			writeError(w, 404, "receipt_not_found", "事件回执不存在")
			return
		}
		writeJSON(w, 200, receipt)
	case path == "/discovery/receipts" && r.Method == "GET":
		epoch, scope := r.URL.Query().Get("epoch"), r.URL.Query().Get("scope_id")
		keys := r.URL.Query()["event_key"]
		if len(r.URL.RawQuery) > 8192 || len(keys) == 0 || len(keys) > 50 {
			writeError(w, 400, "bad_receipt_key", "事件回执定位信息无效")
			return
		}
		items, missing, err := repo.StreamDiscoveryReceipts(ctx, epoch, scope, keys)
		if err != nil {
			if strings.Contains(err.Error(), "invalid") {
				writeError(w, 400, "bad_receipt_key", "事件回执定位信息无效")
			} else {
				writeError(w, 500, "receipt_read", "读取事件回执失败")
			}
			return
		}
		// A missing exact key remains an explicit gap. The check time lets an
		// external audit pair it with the immutable journal acceptance time.
		writeJSON(w, 200, map[string]any{"items": items, "missing_keys": missing, "checked_at": time.Now().UTC()})
	case (path == "/discovery/devices" || path == "/discovery/devices/metadata" || path == "/discovery/devices/position") && r.Method == "GET":
		if r.URL.Query().Get("offset") != "" && path == "/discovery/devices" {
			writeError(w, 400, "bad_cursor", "发现记录已改用游标分页，请删除 offset 参数")
			return
		}
		window := 24 * time.Hour
		if repo.PipelineV2 {
			window = 0
		}
		if value := r.URL.Query().Get("window"); value != "" {
			if value == "all" {
				window = -1
			} else {
				parsed, parseErr := time.ParseDuration(value)
				if parseErr != nil || parsed < 10*time.Minute || parsed > 30*24*time.Hour {
					writeError(w, 400, "bad_window", "时间窗口无效")
					return
				}
				window = parsed
			}
		}
		query := discovery.DeviceQuery{View: r.URL.Query().Get("view"), Mode: r.URL.Query().Get("mode"), Window: window, Search: r.URL.Query().Get("search"), DeviceType: r.URL.Query().Get("type"), Category: r.URL.Query().Get("category"), Capability: r.URL.Query().Get("capability"), RandomMAC: r.URL.Query().Get("random_mac") == "true", Limit: limit, Offset: offset, Cursor: r.URL.Query().Get("cursor"), Protocol: r.URL.Query().Get("protocol"), State: r.URL.Query().Get("state"), Domain: r.URL.Query().Get("domain"), VLAN: r.URL.Query().Get("vlan")}

		if path == "/discovery/devices/position" {
			if repo.ActiveStreamOnly || repo.PipelineV2 || os.Getenv("PROXY_SENTINEL_DISCOVERY_EVENTBUS_READ") == "true" {
				writeError(w, 409, "position_read_path", "当前发现读取路径不支持页码定位")
				return
			}
			page, size, parseErr := pagePositionParameters(r)
			if parseErr != nil {
				writeError(w, 400, "bad_page", "页码或页长无效")
				return
			}
			query.Limit = size
			result, err := repo.DevicesIndexedPosition(ctx, query, page)
			if errors.Is(err, pagination.ErrPageOutOfRange) {
				writeError(w, 400, "page_out_of_range", "目标页已不存在，请刷新列表")
				return
			}
			if err != nil {
				if strings.Contains(err.Error(), "mode") || strings.Contains(err.Error(), "view") || strings.Contains(err.Error(), "state") {
					writeError(w, 400, "bad_filter", err.Error())
					return
				}
				writeError(w, 500, "discovery_position_failed", "读取发现页码位置失败")
				return
			}
			writeJSON(w, 200, result)
			return
		}
		if path == "/discovery/devices/metadata" {
			if repo.ActiveStreamOnly || repo.PipelineV2 || os.Getenv("PROXY_SENTINEL_DISCOVERY_EVENTBUS_READ") == "true" {
				writeError(w, 409, "metadata_read_path", "当前发现读取路径不支持此统计接口")
				return
			}
			result, err := repo.DevicesIndexedMetadata(ctx, query)
			if err != nil {
				if strings.Contains(err.Error(), "mode") || strings.Contains(err.Error(), "view") || strings.Contains(err.Error(), "state") {
					writeError(w, 400, "bad_filter", err.Error())
				} else {
					writeError(w, 500, "discovery_metadata_read", "读取发现设备总数失败")
				}
				return
			}
			writeJSON(w, 200, result)
			return
		}
		var page map[string]any
		var err error
		if repo.ActiveStreamOnly {
			page, err = repo.DevicesState(ctx, query)
		} else if os.Getenv("PROXY_SENTINEL_DISCOVERY_EVENTBUS_READ") == "true" {
			page, err = repo.DevicesEventBus(ctx, query)
		} else if repo.PipelineV2 {
			page, err = repo.DevicesState(ctx, query)
		} else {
			page, err = repo.DevicesIndexed(ctx, query)
		}
		if err != nil {
			if strings.Contains(err.Error(), "cursor") {
				writeError(w, 400, "bad_cursor", err.Error())
			} else if strings.Contains(err.Error(), "mode") || strings.Contains(err.Error(), "view") || strings.Contains(err.Error(), "state") {
				writeError(w, 400, "bad_filter", err.Error())
			} else {
				writeError(w, 500, "discovery_read", "读取发现结果失败")
			}
			return
		}
		enrichDiscoveryRecognition(ctx, repo.DB, page)
		writeJSON(w, 200, page)
	case path == "/discovery/tasks" && r.Method == "GET":
		rows, err := repo.DB.QueryContext(ctx, `SELECT id,coalesce(source_id,''),node,kind,status,config_version,created_at,result,error,cancel_requested FROM discovery_tasks ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
		if err != nil {
			writeError(w, 500, "task_read", "读取任务失败")
			return
		}
		defer rows.Close()
		items := []discovery.Task{}
		for rows.Next() {
			var t discovery.Task
			if err = rows.Scan(&t.ID, &t.SourceID, &t.Node, &t.Kind, &t.Status, &t.Version, &t.CreatedAt, &t.Result, &t.Error, &t.CancelRequested); err != nil {
				writeError(w, 500, "task_read", "读取任务失败")
				return
			}
			items = append(items, t)
		}
		if rows.Err() != nil {
			writeError(w, 500, "task_read", "读取任务失败")
			return
		}
		writeJSON(w, 200, map[string]any{"items": items})
	case strings.HasPrefix(path, "/discovery/tasks/") && strings.HasSuffix(path, "/stop") && r.Method == "POST":
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/discovery/tasks/"), "/stop")
		_, err := repo.DB.ExecContext(ctx, `UPDATE discovery_tasks SET cancel_requested=true,status=CASE WHEN status='pending' THEN 'cancelled' ELSE status END WHERE id=$1 AND status IN ('pending','running')`, id)
		if err != nil {
			writeError(w, 500, "task_stop", "停止任务失败")
			return
		}
		s.appendAudit(ctx, "discovery.stop", id, "requested")
		writeJSON(w, 200, map[string]bool{"stopping": true})
	case path == "/discovery/preview" && r.Method == "POST":
		var cfg discovery.ScanConfig
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
		dec.DisallowUnknownFields()
		if dec.Decode(&cfg) != nil {
			writeError(w, 400, "bad_scan", "探测配置无效")
			return
		}
		if err := cfg.Validate(); err != nil {
			writeError(w, 400, "bad_scan", err.Error())
			return
		}
		targets, err := cfg.Targets(nil)
		if err != nil {
			writeError(w, 400, "bad_scan", err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"targets": targets, "total": len(targets), "active_enabled": false})
	case path == "/discovery/summary" && r.Method == "GET":
		var infrastructure, active, pending, passive, services, linked int
		err := repo.DB.QueryRowContext(ctx, `SELECT
 count(DISTINCT device_key) FILTER(WHERE origin IN ('fdb','neighbor','lldp','cdp')),
 count(DISTINCT device_key) FILTER(WHERE origin='active'),
	count(DISTINCT device_key) FILTER(WHERE NOT EXISTS(SELECT 1 FROM discovery_identity_links l WHERE l.observation_id=discovery_observations.id))
 FROM discovery_observations WHERE observed_at<=now() AND observed_at>=now()-interval '24 hours' AND NOT withdrawn`).Scan(&infrastructure, &active, &pending)
		if err != nil {
			writeError(w, 500, "summary_read", "读取汇总失败")
			return
		}
		passivePage, err := repo.DevicesFiltered(ctx, discovery.DeviceQuery{Mode: "passive", Window: 24 * time.Hour, Limit: 1})
		if err != nil {
			writeError(w, 500, "summary_read", "读取汇总失败")
			return
		}
		passive, _ = passivePage["total"].(int)
		services, _ = passivePage["service_devices"].(int)
		linked, _ = passivePage["linked_endpoints"].(int)
		var enabled bool
		if err = repo.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM discovery_scan_profiles WHERE enabled)`).Scan(&enabled); err != nil {
			writeError(w, 500, "summary_read", "读取汇总失败")
			return
		}
		var lastSuccess sql.NullTime
		var materializerStatus, materializerError string
		var protocolCounts, skipCounts json.RawMessage
		var processed, emitted, skipped int64
		_ = repo.DB.QueryRowContext(ctx, `SELECT last_success_at,CASE WHEN last_error<>'' THEN 'error' WHEN last_success_at IS NULL THEN 'waiting' WHEN last_success_at<now()-interval '2 minutes' THEN 'lagging' ELSE 'ready' END,last_error,protocol_counts,skip_counts,processed_events,emitted_observations,skipped_events FROM passive_discovery_state ORDER BY updated_at DESC LIMIT 1`).Scan(&lastSuccess, &materializerStatus, &materializerError, &protocolCounts, &skipCounts, &processed, &emitted, &skipped)
		response := map[string]any{"window": "24h", "infrastructure": infrastructure, "active_responses": active, "pending_association": pending, "passive_devices": passive, "service_devices": services, "linked_endpoints": linked, "active_enabled": enabled, "materializer_status": materializerStatus, "materializer_error": materializerError}
		if len(protocolCounts) > 0 {
			response["protocol_counts"] = protocolCounts
		}
		if len(skipCounts) > 0 {
			response["skip_counts"] = skipCounts
		}
		response["processed_events"], response["emitted_observations"], response["skipped_events"] = processed, emitted, skipped
		if lastSuccess.Valid {
			response["last_materialized_at"] = lastSuccess.Time
		}
		writeJSON(w, 200, response)
	default:
		writeError(w, 404, "not_found", "发现接口不存在")
	}
}

func firstQueryValue(r *http.Request, key, fallback string) string {
	if v := r.URL.Query().Get(key); v != "" {
		return v
	}
	return fallback
}

func discoveryStreamCurrentReadEnabled() bool {
	return os.Getenv("PROXY_SENTINEL_DISCOVERY_CURRENT_SOURCE") == "stream"
}
