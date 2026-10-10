package controlplane

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"proxy-sentinel/internal/legacy4k"
	"proxy-sentinel/internal/productpolicy"
	"proxy-sentinel/internal/srunapi"
	"proxy-sentinel/internal/store"
)

type SRun4KDefaults struct {
	DatabasePort      int
	DatabaseName      string
	DatabaseUsername  string
	DatabasePassword  string
	DatabaseTLS       bool
	RedisPort         int
	RedisCatalogPort  int
	EventRedisPort    int
	RedisPassword     string
	RedisTLS          bool
	APIScheme         string
	APIPort           int
	APICertificatePEM string
	MaxSessions       int
	PageSize          int
}

func (c SRun4KDefaults) normalized() SRun4KDefaults {
	if c.DatabasePort == 0 {
		c.DatabasePort = 3506
	}
	if c.DatabaseName == "" {
		c.DatabaseName = "srun4k"
	}
	if c.RedisPort == 0 {
		c.RedisPort = 16380
	}
	if c.RedisCatalogPort == 0 {
		c.RedisCatalogPort = 16382
	}
	if c.EventRedisPort == 0 {
		c.EventRedisPort = 16384
	}
	if c.APIScheme == "" {
		c.APIScheme = "https"
	}
	if c.APIPort == 0 {
		c.APIPort = 8001
	}
	if c.MaxSessions == 0 {
		c.MaxSessions = 100000
	}
	if c.PageSize == 0 {
		c.PageSize = 1000
	}
	return c
}

type srun4KIntegration struct {
	ConnectorID                string            `json:"connector_id"`
	Host                       string            `json:"host"`
	AuthorizationDatabaseHost  string            `json:"authorization_database_host"`
	OnlineRedisHost            string            `json:"online_redis_host"`
	CatalogRedisHost           string            `json:"catalog_redis_host"`
	EventRedisHost             string            `json:"event_redis_host,omitempty"`
	NorthboundAPIHost          string            `json:"northbound_api_host"`
	AuthorizationReady         bool              `json:"authorization_ready"`
	Source                     string            `json:"source"`
	SensorID                   string            `json:"sensor_id"`
	ReconcileIntervalHours     int               `json:"reconcile_interval_hours"`
	EventChannelState          string            `json:"event_channel_state"`
	ConnectionState            string            `json:"connection_state"`
	Channels                   map[string]string `json:"channels"`
	LastError                  string            `json:"last_error,omitempty"`
	LastTestedAt               *time.Time        `json:"last_tested_at,omitempty"`
	LastSyncedAt               *time.Time        `json:"last_synced_at,omitempty"`
	LastIdentityPollAt         *time.Time        `json:"last_identity_poll_at,omitempty"`
	LastIdentityEventAt        *time.Time        `json:"last_identity_event_at,omitempty"`
	AuthorizationRefreshedAt   *time.Time        `json:"authorization_refreshed_at,omitempty"`
	AuthorizationDatabaseState string            `json:"-"`
	OnlineRedisState           string            `json:"-"`
	CatalogRedisState          string            `json:"-"`
	EventRedisState            string            `json:"-"`
	NorthboundAPIState         string            `json:"-"`
	IdentityAccounts           int               `json:"identity_accounts"`
	IdentitySessions           int               `json:"identity_sessions"`
	Products                   int               `json:"products"`
	Groups                     int               `json:"groups"`
	Controls                   int               `json:"controls"`
}

type srun4KConnectionRequest struct {
	Host                      string `json:"host,omitempty"`
	AuthorizationDatabaseHost string `json:"authorization_database_host,omitempty"`
	OnlineRedisHost           string `json:"online_redis_host,omitempty"`
	CatalogRedisHost          string `json:"catalog_redis_host,omitempty"`
	EventRedisHost            string `json:"event_redis_host,omitempty"`
	NorthboundAPIHost         string `json:"northbound_api_host,omitempty"`
	ReconcileIntervalHours    int    `json:"reconcile_interval_hours,omitempty"`
}

func srun4KPath(path string) (id, operation string, collection bool, ok bool) {
	path = strings.Trim(strings.TrimPrefix(path, "/api/v1"), "/")
	parts := strings.Split(path, "/")
	if len(parts) == 2 && parts[0] == "integrations" && parts[1] == "srun4k" {
		return "", "", true, true
	}
	if len(parts) == 3 && parts[0] == "integrations" && parts[1] == "srun4k" && parts[2] != "" {
		return parts[2], "", false, true
	}
	if len(parts) == 4 && parts[0] == "integrations" && parts[1] == "srun4k" && parts[2] != "" && (parts[3] == "test" || parts[3] == "sync" || parts[3] == "status" || parts[3] == "authorization") {
		return parts[2], parts[3], false, true
	}
	return "", "", false, false
}

// The global read-only switch blocks enforcement and general configuration
// writes, but administrators may still configure and synchronize the 4K
// reference-data integration. These operations never dispatch enforcement.
func srun4KReadOnlyMutationAllowed(method, path string) bool {
	_, operation, collection, ok := srun4KPath(path)
	if !ok {
		return false
	}
	if collection && method == http.MethodPost {
		return true
	}
	if !collection && operation == "" && method == http.MethodPut {
		return true
	}
	return method == http.MethodPost && (operation == "test" || operation == "sync" || operation == "authorization")
}

func validSRunHost(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 253 || strings.ContainsAny(value, "/\\@?# \t\r\n") {
		return false
	}
	if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
		return true
	}
	if strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func stableSRunID(host string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(host)))
	return "srun4k-" + hex.EncodeToString(digest[:])[:16]
}

var errSRunHostConflict = errors.New("该4K地址已绑定其他接入，请打开已有接入进行配置")

func resolveSRunConnectorID(ctx context.Context, tx *sql.Tx, host, requestedID string) (string, error) {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 7140))`, "srun4k-host:"+host); err != nil {
		return "", err
	}
	var existing string
	err := tx.QueryRowContext(ctx, `SELECT connector_id FROM srun4k_integrations WHERE host=$1`, host).Scan(&existing)
	if err == nil {
		if requestedID != "" && requestedID != existing {
			return "", errSRunHostConflict
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if requestedID == "" {
		requestedID = stableSRunID(host)
	}
	return requestedID, nil
}

func (s *Server) handleSRun4K(w http.ResponseWriter, r *http.Request, path string) {
	if s.operations == nil || s.operations.db == nil {
		writeError(w, http.StatusServiceUnavailable, "srun4k_storage_unavailable", "深澜4K接入需要PostgreSQL存储")
		return
	}
	id, operation, collection, ok := srun4KPath(path)
	if !ok {
		writeError(w, http.StatusNotFound, "srun4k_endpoint_not_found", "深澜4K接入接口不存在")
		return
	}
	if collection && r.Method == http.MethodGet {
		items, err := s.listSRun4K(r.Context())
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "srun4k_list_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
		return
	}
	if collection && r.Method == http.MethodPost {
		s.saveSRun4K(w, r, "")
		return
	}
	if operation == "" && r.Method == http.MethodPut {
		s.saveSRun4K(w, r, id)
		return
	}
	if operation == "" && r.Method == http.MethodGet {
		item, err := s.loadSRun4K(r.Context(), id)
		if err == sql.ErrNoRows {
			writeError(w, http.StatusNotFound, "srun4k_not_found", "深澜4K接入不存在")
			return
		}
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "srun4k_read_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, item)
		return
	}
	if operation == "status" && r.Method == http.MethodGet {
		item, err := s.loadSRun4K(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusNotFound, "srun4k_not_found", "深澜4K接入不存在")
			return
		}
		writeJSON(w, http.StatusOK, item)
		return
	}
	if operation == "test" && r.Method == http.MethodPost {
		result, err := s.testSRun4K(r.Context(), id)
		if err != nil {
			status := srunOperationFailureStatus(err)
			writeError(w, status, "srun4k_test_failed", srunOperationFailureMessage(err))
			return
		}
		writeJSON(w, http.StatusOK, result)
		return
	}
	if operation == "authorization" && r.Method == http.MethodPost {
		if err := s.refreshSRun4KAuthorization(r.Context(), id); err != nil {
			writeError(w, srunOperationFailureStatus(err), "srun4k_authorization_refresh_failed", srunOperationFailureMessage(err))
			return
		}
		item, err := s.loadSRun4K(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "srun4k_authorization_refresh_failed", "4K授权状态读取失败")
			return
		}
		writeJSON(w, http.StatusOK, item)
		return
	}
	if operation == "sync" && r.Method == http.MethodPost {
		result, err := s.syncSRun4K(r.Context(), id)
		if err != nil {
			status := srunOperationFailureStatus(err)
			writeError(w, status, "srun4k_sync_failed", srunOperationFailureMessage(err))
			return
		}
		writeJSON(w, http.StatusOK, result)
		return
	}
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "不支持此操作")
}

func decodeSRunRequest(w http.ResponseWriter, r *http.Request) (srun4KConnectionRequest, error) {
	var request srun4KConnectionRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return request, fmt.Errorf("请求体只能包含一个JSON对象")
	}
	request.Host = strings.TrimSpace(request.Host)
	request.AuthorizationDatabaseHost = strings.TrimSpace(request.AuthorizationDatabaseHost)
	request.OnlineRedisHost = strings.TrimSpace(request.OnlineRedisHost)
	request.CatalogRedisHost = strings.TrimSpace(request.CatalogRedisHost)
	request.EventRedisHost = strings.TrimSpace(request.EventRedisHost)
	request.NorthboundAPIHost = strings.TrimSpace(request.NorthboundAPIHost)
	// Compatibility for the former single-host API: all data/API endpoints
	// inherit the old address, while the event Redis keeps its deployment value.
	if request.AuthorizationDatabaseHost == "" && request.OnlineRedisHost == "" && request.CatalogRedisHost == "" && request.NorthboundAPIHost == "" && request.Host != "" {
		request.AuthorizationDatabaseHost = request.Host
		request.OnlineRedisHost = request.Host
		request.CatalogRedisHost = request.Host
		request.NorthboundAPIHost = request.Host
	}
	request.Host = request.OnlineRedisHost
	if request.ReconcileIntervalHours == 0 {
		request.ReconcileIntervalHours = 6
	}
	if !validSRunHost(request.AuthorizationDatabaseHost) || !validSRunHost(request.OnlineRedisHost) || !validSRunHost(request.CatalogRedisHost) || !validSRunHost(request.NorthboundAPIHost) || request.EventRedisHost != "" && !validSRunHost(request.EventRedisHost) || request.ReconcileIntervalHours < 1 || request.ReconcileIntervalHours > 168 {
		return request, fmt.Errorf("请分别填写有效的授权数据库、在线Redis、目录Redis、北向API地址和1至168小时的校准周期")
	}
	return request, nil
}

func (s *Server) saveSRun4K(w http.ResponseWriter, r *http.Request, id string) {
	request, err := decodeSRunRequest(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_srun4k_configuration", err.Error())
		return
	}
	tx, err := s.operations.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "srun4k_save_failed", "4K接入保存暂不可用")
		return
	}
	defer tx.Rollback()
	id, err = resolveSRunConnectorID(r.Context(), tx, request.Host, id)
	if err != nil {
		if errors.Is(err, errSRunHostConflict) {
			writeError(w, http.StatusConflict, "srun4k_host_conflict", err.Error())
		} else {
			writeError(w, http.StatusServiceUnavailable, "srun4k_save_failed", "4K接入保存暂不可用")
		}
		return
	}
	// Host locks deduplicate registrations; this lock also serializes edits of
	// the same connector when competing requests specify different hosts.
	_, err = tx.ExecContext(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1,7141))`, id)
	var previousHost, previousAuthHost, previousCatalogHost, previousEventHost, previousAPIHost, source, sensor string
	if err == nil {
		err = tx.QueryRowContext(r.Context(), `SELECT host,authorization_database_host,catalog_redis_host,event_redis_host,northbound_api_host,source,sensor_id FROM srun4k_integrations WHERE connector_id=$1 FOR UPDATE`, id).Scan(&previousHost, &previousAuthHost, &previousCatalogHost, &previousEventHost, &previousAPIHost, &source, &sensor)
		if errors.Is(err, sql.ErrNoRows) {
			source, sensor, err = "srun4k:"+id, "srun4k-direct:"+id, nil
		}
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "srun4k_save_failed", "4K接入保存暂不可用")
		return
	}
	onlineChanged := previousHost != "" && previousHost != request.OnlineRedisHost
	authorizationChanged := previousAuthHost != "" && previousAuthHost != request.AuthorizationDatabaseHost
	if onlineChanged {
		// A new epoch on every address transition, including A -> B -> A,
		// prevents historical sessions from becoming current again.
		key := id
		if len(key) > 140 {
			digest := sha256.Sum256([]byte(key))
			key = hex.EncodeToString(digest[:16])
		}
		epoch := shortToken(16)
		source, sensor = "srun4k:"+key+":"+epoch, "srun4k-direct:"+key+":"+epoch
	}
	defaults := s.srun4KDefaults.normalized()
	apiEndpoint := (&url.URL{Scheme: defaults.APIScheme, Host: net.JoinHostPort(request.NorthboundAPIHost, strconv.Itoa(defaults.APIPort))}).String()
	eventHost := request.EventRedisHost
	if eventHost == "" {
		eventHost = previousEventHost
	}
	if eventHost == "" {
		eventHost = redisHostFromAddress(s.identityBridge.normalized().EventRedisAddr)
	}
	if !validSRunHost(eventHost) {
		writeError(w, http.StatusBadRequest, "bad_srun4k_configuration", "请填写有效的上下线事件Redis地址")
		return
	}
	endpointChanged := previousHost != "" && (onlineChanged || authorizationChanged || previousCatalogHost != request.CatalogRedisHost || previousEventHost != eventHost || previousAPIHost != request.NorthboundAPIHost)
	actionMapping, _ := json.Marshal(map[string]string{
		"account_policy_v1":       "supported",
		"session.disconnect":      "online-drop",
		"account.notify":          "notification-outbox",
		"account.disable_account": "safe-disable",
	})
	_, err = tx.ExecContext(r.Context(), `INSERT INTO enforcement_connectors(connector_id,connector_type,name,endpoint_url,action_mapping,encrypted_secret,mode,enabled,shadow_ready,updated_by) VALUES($1,'srun4k',$2,$3,$4,''::bytea,'active',true,false,$5) ON CONFLICT(connector_id) DO UPDATE SET name=EXCLUDED.name,endpoint_url=EXCLUDED.endpoint_url,action_mapping=EXCLUDED.action_mapping,connector_type='srun4k',enabled=true,updated_by=EXCLUDED.updated_by,updated_at=now()`, id, "深澜4K（"+request.NorthboundAPIHost+"）", apiEndpoint, actionMapping, sessionFromContext(r.Context()).User.ID)
	if err == nil {
		_, err = tx.ExecContext(r.Context(), `INSERT INTO srun4k_integrations(connector_id,host,authorization_database_host,online_redis_host,catalog_redis_host,event_redis_host,northbound_api_host,source,sensor_id,reconcile_interval_hours,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(connector_id) DO UPDATE SET host=EXCLUDED.host,authorization_database_host=EXCLUDED.authorization_database_host,online_redis_host=EXCLUDED.online_redis_host,catalog_redis_host=EXCLUDED.catalog_redis_host,event_redis_host=EXCLUDED.event_redis_host,northbound_api_host=EXCLUDED.northbound_api_host,source=EXCLUDED.source,sensor_id=EXCLUDED.sensor_id,reconcile_interval_hours=EXCLUDED.reconcile_interval_hours,northbound_app_id=CASE WHEN srun4k_integrations.authorization_database_host<>EXCLUDED.authorization_database_host THEN '' ELSE srun4k_integrations.northbound_app_id END,encrypted_northbound_app_secret=CASE WHEN srun4k_integrations.authorization_database_host<>EXCLUDED.authorization_database_host THEN ''::bytea ELSE srun4k_integrations.encrypted_northbound_app_secret END,authorization_refreshed_at=CASE WHEN srun4k_integrations.authorization_database_host<>EXCLUDED.authorization_database_host THEN NULL ELSE srun4k_integrations.authorization_refreshed_at END,event_channel_state=CASE WHEN srun4k_integrations.event_redis_host<>EXCLUDED.event_redis_host THEN 'waiting' ELSE srun4k_integrations.event_channel_state END,connection_state=CASE WHEN srun4k_integrations.host<>EXCLUDED.host OR srun4k_integrations.authorization_database_host<>EXCLUDED.authorization_database_host OR srun4k_integrations.catalog_redis_host<>EXCLUDED.catalog_redis_host OR srun4k_integrations.event_redis_host<>EXCLUDED.event_redis_host OR srun4k_integrations.northbound_api_host<>EXCLUDED.northbound_api_host THEN 'pending' ELSE srun4k_integrations.connection_state END,last_tested_at=CASE WHEN srun4k_integrations.host<>EXCLUDED.host OR srun4k_integrations.authorization_database_host<>EXCLUDED.authorization_database_host OR srun4k_integrations.catalog_redis_host<>EXCLUDED.catalog_redis_host OR srun4k_integrations.event_redis_host<>EXCLUDED.event_redis_host OR srun4k_integrations.northbound_api_host<>EXCLUDED.northbound_api_host THEN NULL ELSE srun4k_integrations.last_tested_at END,last_error=CASE WHEN srun4k_integrations.host<>EXCLUDED.host OR srun4k_integrations.authorization_database_host<>EXCLUDED.authorization_database_host OR srun4k_integrations.catalog_redis_host<>EXCLUDED.catalog_redis_host OR srun4k_integrations.event_redis_host<>EXCLUDED.event_redis_host OR srun4k_integrations.northbound_api_host<>EXCLUDED.northbound_api_host THEN '' ELSE srun4k_integrations.last_error END,updated_by=EXCLUDED.updated_by,updated_at=now()`, id, request.OnlineRedisHost, request.AuthorizationDatabaseHost, request.OnlineRedisHost, request.CatalogRedisHost, eventHost, request.NorthboundAPIHost, source, sensor, request.ReconcileIntervalHours, sessionFromContext(r.Context()).User.ID)
	}
	if err == nil {
		if endpointChanged && !onlineChanged {
			_, err = tx.ExecContext(r.Context(), `UPDATE srun4k_integrations SET last_tested_at=NULL,last_error='',connection_state='pending',authorization_database_state=CASE WHEN $2 THEN 'pending' ELSE authorization_database_state END,catalog_redis_state=CASE WHEN $3 THEN 'pending' ELSE catalog_redis_state END,event_redis_state=CASE WHEN $4 THEN 'pending' ELSE event_redis_state END,northbound_api_state=CASE WHEN $5 THEN 'pending' ELSE northbound_api_state END WHERE connector_id=$1`, id, authorizationChanged, previousCatalogHost != request.CatalogRedisHost, previousEventHost != eventHost, previousAPIHost != request.NorthboundAPIHost)
		}
	}
	if err == nil {
		// The identity bridge consumes the online and event Redis endpoints from
		// this same managed configuration. Only the online endpoint advances its
		// identity epoch; event-only changes are picked up without re-keying users.
		_, err = tx.ExecContext(r.Context(), `UPDATE identity_bridge_configs SET desired_host=$2,config_version=CASE WHEN desired_host<>$2 THEN config_version+1 ELSE config_version END,desired_event_redis_addr=$3,updated_by=$4,updated_at=CASE WHEN desired_host<>$2 OR desired_event_redis_addr<>$3 THEN now() ELSE updated_at END WHERE bridge_id=$1`, s.identityBridge.normalized().BridgeID, request.OnlineRedisHost, net.JoinHostPort(eventHost, strconv.Itoa(defaults.EventRedisPort)), sessionFromContext(r.Context()).User.ID)
	}
	if err == nil && onlineChanged {
		_, err = tx.ExecContext(r.Context(), `UPDATE srun4k_integrations SET event_channel_state='waiting',authorization_database_state='pending',online_redis_state='pending',catalog_redis_state='pending',event_redis_state='pending',northbound_api_state='pending',last_tested_at=NULL,last_synced_at=NULL,last_test_result_order=0,last_sync_result_order=0,last_health_result_order=0,identity_accounts=0,identity_sessions=0,products=0,groups_count=0,controls=0 WHERE connector_id=$1`, id)
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `UPDATE enforcement_connectors SET mode='shadow',shadow_ready=false,shadow_started_at=NULL,shadow_validation_since=NULL,shadow_candidate_count=0,shadow_reviewed_count=0,shadow_accuracy=0,circuit_open_until=NULL,consecutive_failures=0 WHERE connector_id=$1`, id)
		}
		if err == nil {
			// Keep the old inventory configuration as history, but do not let it
			// re-authorize the old scope against a newly selected controller.
			_, err = tx.ExecContext(r.Context(), `UPDATE enforcement_identity_sources SET public_config=jsonb_set(public_config,'{enabled}','false'::jsonb),config_version=config_version+1,state='pending',blocker='connector_host_changed',observed_at=NULL,updated_at=now() WHERE connector_id=$1`, id)
		}
	}
	if err == nil {
		outcome := "saved"
		if onlineChanged {
			outcome = "saved_new_identity_source"
		} else if authorizationChanged {
			outcome = "saved_authorization_source_changed"
		}
		_, err = tx.ExecContext(r.Context(), `INSERT INTO audit_logs(audit_id,actor,action,target,outcome,created_at) VALUES($1,$2,'integration.srun4k.save',$3,$4,now())`, "audit-srun4k-save-"+shortToken(16), sessionFromContext(r.Context()).User.ID, id, outcome)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "srun4k_save_failed", "4K接入保存暂不可用")
		return
	}
	s.refreshSRunConnector(r.Context(), id)
	item, err := s.loadSRun4K(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "srun4k_save_failed", "4K接入已保存，暂时无法读取结果，请刷新")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) loadSRun4K(ctx context.Context, id string) (srun4KIntegration, error) {
	var item srun4KIntegration
	var tested, synced, polled, eventAt, authAt sql.NullTime
	err := s.operations.db.QueryRowContext(ctx, `SELECT connector_id,host,authorization_database_host,online_redis_host,catalog_redis_host,event_redis_host,northbound_api_host,source,sensor_id,reconcile_interval_hours,event_channel_state,connection_state,last_error,last_tested_at,last_synced_at,identity_accounts,identity_sessions,products,groups_count,controls,last_identity_poll_at,last_identity_event_at,authorization_refreshed_at,northbound_app_id<>'' AND octet_length(encrypted_northbound_app_secret)>0,authorization_database_state,online_redis_state,catalog_redis_state,event_redis_state,northbound_api_state FROM srun4k_integrations WHERE connector_id=$1`, id).Scan(&item.ConnectorID, &item.Host, &item.AuthorizationDatabaseHost, &item.OnlineRedisHost, &item.CatalogRedisHost, &item.EventRedisHost, &item.NorthboundAPIHost, &item.Source, &item.SensorID, &item.ReconcileIntervalHours, &item.EventChannelState, &item.ConnectionState, &item.LastError, &tested, &synced, &item.IdentityAccounts, &item.IdentitySessions, &item.Products, &item.Groups, &item.Controls, &polled, &eventAt, &authAt, &item.AuthorizationReady, &item.AuthorizationDatabaseState, &item.OnlineRedisState, &item.CatalogRedisState, &item.EventRedisState, &item.NorthboundAPIState)
	if item.AuthorizationDatabaseHost == "" {
		item.AuthorizationDatabaseHost = item.Host
	}
	if item.OnlineRedisHost == "" {
		item.OnlineRedisHost = item.Host
	}
	if item.CatalogRedisHost == "" {
		item.CatalogRedisHost = item.Host
	}
	if item.NorthboundAPIHost == "" {
		item.NorthboundAPIHost = item.Host
	}
	if item.EventRedisHost == "" {
		item.EventRedisHost = redisHostFromAddress(s.identityBridge.normalized().EventRedisAddr)
	}
	if tested.Valid {
		item.LastTestedAt = &tested.Time
	}
	if synced.Valid {
		item.LastSyncedAt = &synced.Time
	}
	if polled.Valid {
		item.LastIdentityPollAt = &polled.Time
	}
	if eventAt.Valid {
		item.LastIdentityEventAt = &eventAt.Time
	}
	if authAt.Valid {
		item.AuthorizationRefreshedAt = &authAt.Time
	}
	item.Channels = map[string]string{
		"authorization_database": item.AuthorizationDatabaseState,
		"online_redis":           item.OnlineRedisState,
		"catalog_redis":          item.CatalogRedisState,
		"event_redis":            item.EventRedisState,
		"northbound_api":         item.NorthboundAPIState,
		"event_channel":          item.EventChannelState,
	}
	return item, err
}

func srun4KChannelStates(connectionState, eventState, lastError string) map[string]string {
	channels := map[string]string{
		"authorization_database": "pending",
		"online_redis":           "pending",
		"catalog_redis":          "pending",
		"event_redis":            eventState,
		"northbound_api":         "pending",
		"event_channel":          eventState,
	}
	switch connectionState {
	case "healthy":
		channels["authorization_database"] = "healthy"
		channels["online_redis"] = "healthy"
		channels["catalog_redis"] = "healthy"
		channels["northbound_api"] = "healthy"
	case "failed":
		switch {
		case strings.HasPrefix(lastError, "authorization_database:"):
			channels["authorization_database"] = "failed"
		case strings.HasPrefix(lastError, "online_redis:"):
			channels["authorization_database"] = "healthy"
			channels["online_redis"] = "failed"
		case strings.HasPrefix(lastError, "catalog_redis:"):
			channels["authorization_database"] = "healthy"
			channels["online_redis"] = "healthy"
			channels["catalog_redis"] = "failed"
		case strings.HasPrefix(lastError, "northbound_api:"):
			channels["authorization_database"] = "healthy"
			channels["online_redis"] = "healthy"
			channels["catalog_redis"] = "healthy"
			channels["northbound_api"] = "failed"
		}
	}
	return channels
}

func (s *Server) listSRun4K(ctx context.Context) ([]srun4KIntegration, error) {
	rows, err := s.operations.db.QueryContext(ctx, `SELECT connector_id FROM srun4k_integrations ORDER BY updated_at DESC,connector_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	items := make([]srun4KIntegration, 0, len(ids))
	for _, id := range ids {
		item, readErr := s.loadSRun4K(ctx, id)
		if readErr != nil {
			return nil, readErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Server) srunDatabase(ctx context.Context, item srun4KIntegration) (srunapi.AuthorizationDatabase, error) {
	defaults := s.srun4KDefaults.normalized()
	databaseHost := item.AuthorizationDatabaseHost
	if databaseHost == "" {
		databaseHost = item.Host
	}
	configured := srunapi.AuthorizationDatabase{Host: databaseHost, Port: defaults.DatabasePort, Database: defaults.DatabaseName, Username: defaults.DatabaseUsername, Password: defaults.DatabasePassword, TLS: defaults.DatabaseTLS}
	if defaults.DatabaseUsername != "" || defaults.DatabasePassword != "" {
		if defaults.DatabaseUsername == "" || defaults.DatabasePassword == "" {
			return configured, fmt.Errorf("4K授权库部署账号配置不完整")
		}
		return configured, nil
	}
	if s.operations == nil || s.operations.db == nil {
		return configured, fmt.Errorf("4K授权库部署账号未配置")
	}
	var raw, encrypted []byte
	err := s.operations.db.QueryRowContext(ctx, `SELECT public_config,encrypted_password FROM enforcement_4k_databases WHERE public_config->>'host'=$1 ORDER BY updated_at DESC LIMIT 1`, databaseHost).Scan(&raw, &encrypted)
	if err != nil {
		if err == sql.ErrNoRows {
			return configured, fmt.Errorf("4K授权库部署账号未配置，且没有同地址的兼容配置")
		}
		return configured, err
	}
	var legacy srunapi.AuthorizationDatabase
	if json.Unmarshal(raw, &legacy) != nil || strings.TrimSpace(legacy.Username) == "" || len(encrypted) == 0 {
		return configured, fmt.Errorf("同地址的兼容授权库配置无效")
	}
	password, err := s.decryptConnectorSecret(string(encrypted))
	if err != nil {
		return configured, fmt.Errorf("同地址的兼容授权库密码不可用")
	}
	legacy.Host = databaseHost
	legacy.Password = password
	return legacy, nil
}

func (s *Server) srunRedis(item srun4KIntegration) *legacy4k.RedisOnlineClient {
	defaults := s.srun4KDefaults.normalized()
	return s.srunRedisAtHostPort(item, item.OnlineRedisHost, defaults.RedisPort)
}

func (s *Server) srunCatalogRedis(item srun4KIntegration) *productpolicy.RedisCatalogClient {
	return productpolicy.NewRedisCatalogClient(s.srunRedisOptions(item, item.CatalogRedisHost, s.srun4KDefaults.normalized().RedisCatalogPort))
}

func (s *Server) srunRedisAtPort(item srun4KIntegration, port int) *legacy4k.RedisOnlineClient {
	return s.srunRedisAtHostPort(item, item.OnlineRedisHost, port)
}

func (s *Server) srunRedisAtHostPort(item srun4KIntegration, host string, port int) *legacy4k.RedisOnlineClient {
	return legacy4k.NewRedisOnlineClient(s.srunRedisOptions(item, host, port))
}

func (s *Server) srunRedisOptions(item srun4KIntegration, host string, port int) *redis.Options {
	defaults := s.srun4KDefaults.normalized()
	if host == "" {
		host = item.Host
	}
	options := &redis.Options{Addr: net.JoinHostPort(host, strconv.Itoa(port)), Password: defaults.RedisPassword, DialTimeout: 3 * time.Second, ReadTimeout: 8 * time.Second, WriteTimeout: 3 * time.Second, PoolSize: 4, MaxRetries: 1, ContextTimeoutEnabled: true}
	if defaults.RedisTLS {
		options.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return options
}

func (s *Server) srunClient(ctx context.Context, item srun4KIntegration) (*srunapi.Client, error) {
	var appID string
	var encrypted []byte
	if err := s.operations.db.QueryRowContext(ctx, `SELECT northbound_app_id,encrypted_northbound_app_secret FROM srun4k_integrations WHERE connector_id=$1`, item.ConnectorID).Scan(&appID, &encrypted); err != nil {
		return nil, fmt.Errorf("4K北向授权尚未配置")
	}
	if appID == "" || len(encrypted) == 0 {
		return nil, fmt.Errorf("4K北向授权尚未配置")
	}
	secret, err := s.decryptConnectorSecret(string(encrypted))
	if err != nil {
		return nil, fmt.Errorf("4K北向授权不可用")
	}
	return s.srunClientWithCredentials(item, appID, secret)
}

func (s *Server) srunClientWithCredentials(item srun4KIntegration, appID, secret string) (*srunapi.Client, error) {
	defaults := s.srun4KDefaults.normalized()
	apiHost := item.NorthboundAPIHost
	if apiHost == "" {
		apiHost = item.Host
	}
	endpoint := (&url.URL{Scheme: defaults.APIScheme, Host: net.JoinHostPort(apiHost, strconv.Itoa(defaults.APIPort))}).String()
	var httpClient *http.Client
	var err error
	if strings.TrimSpace(defaults.APICertificatePEM) != "" {
		httpClient, err = srunapi.NewCertificatePinnedClient([]byte(defaults.APICertificatePEM))
		if err != nil {
			return nil, fmt.Errorf("4K北向接口部署证书无效: %w", err)
		}
	}
	return srunapi.New(endpoint, appID, secret, httpClient)
}

func redisHostFromAddress(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.TrimSpace(address)
}

func (s *Server) refreshSRun4KAuthorization(ctx context.Context, id string) error {
	item, err := s.loadSRun4K(ctx, id)
	if err != nil {
		return err
	}
	database, err := s.srunDatabase(ctx, item)
	if err != nil {
		return fmt.Errorf("4K授权数据库只读配置不可用: %w", err)
	}
	credentials, err := srunapi.ReadApplicationCredentials(ctx, database)
	if err != nil {
		return fmt.Errorf("4K授权记录读取失败")
	}
	client, err := s.srunClientWithCredentials(item, credentials.AppID, credentials.AppSecret)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	if _, err = client.Groups(ctx); err != nil {
		return fmt.Errorf("北向接口授权验证失败")
	}
	encrypted, err := s.encryptConnectorSecret(credentials.AppSecret)
	if err != nil {
		return fmt.Errorf("北向授权安全存储不可用")
	}
	result, err := s.operations.db.ExecContext(ctx, `UPDATE srun4k_integrations SET northbound_app_id=$2,encrypted_northbound_app_secret=$3,authorization_refreshed_at=now(),updated_at=now() WHERE connector_id=$1 AND authorization_database_host=$4 AND northbound_api_host=$5`, id, credentials.AppID, []byte(encrypted), item.AuthorizationDatabaseHost, item.NorthboundAPIHost)
	if err != nil {
		return fmt.Errorf("北向授权保存失败")
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return fmt.Errorf("4K接入配置已变化，请重新刷新授权")
	}
	s.recordSRunAuditOutcome(ctx, id, "integration.srun4k.authorization", "refreshed")
	s.refreshSRunConnector(ctx, id)
	return nil
}

// Keep a safe public error and the original channel detail together, so a
// enclosing sync report does not replace a precise connection failure.
type srun4KReadTestError struct {
	message string
	detail  string
	cause   error
}

func (e *srun4KReadTestError) Error() string { return e.message }
func (e *srun4KReadTestError) Unwrap() error { return e.cause }

// Preserve the typed cause without exposing upstream credentials or addresses
// through the public message. Cancellation is an operation outcome, not a
// failed observation of the source's health.
func (s *Server) recordSRunReadTestFailure(ctx context.Context, id, message, detail string, cause error) error {
	failure := &srun4KReadTestError{message: message, detail: detail, cause: cause}
	if errors.Is(cause, context.Canceled) {
		failure.message = srunOperationFailureMessage(cause)
		s.recordSRunCancellation(ctx, id, "integration.srun4k.test")
	} else if errors.Is(cause, legacy4k.ErrOnlineResourceLimit) {
		failure.message = legacy4k.ErrOnlineResourceLimit.Error()
		s.recordSRunAuditOutcome(ctx, id, "integration.srun4k.test", "online_resource_limit")
	} else if errors.Is(cause, productpolicy.ErrCatalogResourceLimit) {
		failure.message = productpolicy.ErrCatalogResourceLimit.Error()
		s.recordSRunAuditOutcome(ctx, id, "integration.srun4k.test", "catalog_resource_limit")
	} else {
		s.recordSRunFailure(ctx, id, failure.detail)
	}
	return failure
}

func (s *Server) recordSRunCancellation(ctx context.Context, id, action string) {
	s.recordSRunAuditOutcome(ctx, id, action, "cancelled")
}

func (s *Server) recordSRunAuditOutcome(ctx context.Context, id, action, outcome string) {
	reportCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	if err := s.writeAudit(reportCtx, action, id, outcome); err != nil {
		log.Printf("4K operation audit write did not complete: connector=%q action=%q", id, action)
	}
}

func (s *Server) testSRun4K(ctx context.Context, id string) (map[string]any, error) {
	return s.testSRun4KWithDatabaseCheck(ctx, id, true)
}

func (s *Server) testSRun4KWithDatabaseCheck(ctx context.Context, id string, checkDatabase bool) (map[string]any, error) {
	item, err := s.loadSRun4K(ctx, id)
	if err != nil {
		return nil, err
	}
	ctx, err = s.beginSRunOperation(ctx, item)
	if err != nil {
		return nil, err
	}
	authorizationRefreshed := false
	if !item.AuthorizationReady {
		if err := s.refreshSRun4KAuthorization(ctx, id); err != nil {
			return nil, s.recordSRunReadTestFailure(ctx, id, "4K授权读取或北向验证失败", "authorization_database: initial authorization failed", err)
		}
		item, err = s.loadSRun4K(ctx, id)
		if err != nil {
			return nil, err
		}
		authorizationRefreshed = true
	}
	if checkDatabase {
		database, databaseErr := s.srunDatabase(ctx, item)
		if databaseErr != nil {
			return nil, s.recordSRunReadTestFailure(ctx, id, "4K授权数据库连接失败", "authorization_database: readonly database configuration failed", databaseErr)
		}
		if databaseErr = srunapi.PingAuthorizationDatabase(ctx, database); databaseErr != nil {
			return nil, s.recordSRunReadTestFailure(ctx, id, "4K授权数据库连接失败", "authorization_database: readonly database ping failed", databaseErr)
		}
	}
	client, err := s.srunClient(ctx, item)
	if err != nil {
		return nil, s.recordSRunReadTestFailure(ctx, id, "4K北向授权不可用", "northbound_api: stored application credential unavailable", err)
	}
	redisClient := s.srunRedis(item)
	defer redisClient.Close()
	if err = redisClient.Ping(ctx).Err(); err != nil {
		return nil, s.recordSRunReadTestFailure(ctx, id, "4K在线Redis只读连接失败", "online_redis: connection failed", err)
	}
	catalogClient := s.srunCatalogRedis(item)
	defer catalogClient.Close()
	if err = catalogClient.Ping(ctx).Err(); err != nil {
		return nil, s.recordSRunReadTestFailure(ctx, id, "4K产品目录Redis只读连接失败", "catalog_redis: connection failed", err)
	}
	eventClient := redis.NewClient(s.srunRedisOptions(item, item.EventRedisHost, s.srun4KDefaults.normalized().EventRedisPort))
	defer eventClient.Close()
	if err = eventClient.Ping(ctx).Err(); err != nil {
		return nil, s.recordSRunReadTestFailure(ctx, id, "4K上下线事件Redis只读连接失败", "event_redis: connection failed", err)
	}
	online, err := client.OnlineTotal(ctx)
	if err != nil {
		return nil, s.recordSRunReadTestFailure(ctx, id, "4K北向接口检查失败", "northbound_api: request failed", err)
	}
	now := time.Now().UTC()
	return s.completeSRun4KTest(ctx, item, online, now, checkDatabase, authorizationRefreshed)
}

var errSRunTestResultCommit = errors.New("4K只读检查结果保存失败，请重试检查")

func (s *Server) completeSRun4KTest(ctx context.Context, item srun4KIntegration, online int64, now time.Time, checkDatabase, authorizationRefreshed bool) (map[string]any, error) {
	id := item.ConnectorID
	order, ok := ctx.Value(srunOperationOrderKey{}).(int64)
	if !ok || order <= 0 {
		return nil, errSRunTestResultCommit
	}
	commitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tx, err := s.operations.db.BeginTx(commitCtx, nil)
	if err != nil {
		return nil, errSRunTestResultCommit
	}
	defer tx.Rollback()
	// Do not attach an old host's probe to a reconfigured integration. Return
	// the current event-channel state instead of the earlier probe's snapshot.
	var eventState string
	authorizationState := item.AuthorizationDatabaseState
	if checkDatabase || authorizationRefreshed {
		authorizationState = "healthy"
	}
	err = tx.QueryRowContext(commitCtx, `UPDATE srun4k_integrations SET connection_state='healthy',last_error='',last_tested_at=$2,last_test_result_order=$7,last_health_result_order=$7,authorization_database_state=$8,online_redis_state='healthy',catalog_redis_state='healthy',event_redis_state='healthy',northbound_api_state='healthy',updated_at=now() WHERE connector_id=$1 AND host=$3 AND source=$4 AND sensor_id=$5 AND reconcile_interval_hours=$6 AND last_test_result_order<=$7 AND last_health_result_order<=$7 RETURNING event_channel_state`, id, now, item.Host, item.Source, item.SensorID, item.ReconcileIntervalHours, order, authorizationState).Scan(&eventState)
	if err != nil {
		return nil, errSRunTestResultCommit
	}
	_, err = tx.ExecContext(commitCtx, `INSERT INTO audit_logs(audit_id,actor,action,target,outcome,created_at) VALUES($1,$2,'integration.srun4k.test',$3,'read_only_succeeded',$4)`, "audit-srun4k-test-"+shortToken(16), sessionFromContext(ctx).User.ID, id, now)
	if err != nil || tx.Commit() != nil {
		return nil, errSRunTestResultCommit
	}
	return map[string]any{"connector_id": id, "checked_at": now, "online_total": online, "channels": map[string]string{"authorization_database": authorizationState, "online_redis": "healthy", "catalog_redis": "healthy", "event_redis": "healthy", "northbound_api": "healthy", "event_channel": eventState}, "enforcement_ready": eventState == "healthy"}, nil
}

type srunOperationScopeKey struct{}

// Allocated before an upstream observation, not when its result finishes.
type srunOperationOrderKey struct{}

// One database sequence orders overlapping operations across processes and
// connections. Nested probes reuse their sync's order, after checking scope.
func (s *Server) beginSRunOperation(ctx context.Context, item srun4KIntegration) (context.Context, error) {
	if order, ok := ctx.Value(srunOperationOrderKey{}).(int64); ok {
		bound, scoped := ctx.Value(srunOperationScopeKey{}).(srun4KIntegration)
		if order <= 0 || !scoped || bound.ConnectorID != item.ConnectorID || bound.Host != item.Host || bound.Source != item.Source || bound.SensorID != item.SensorID || bound.ReconcileIntervalHours != item.ReconcileIntervalHours {
			return ctx, errSRunTestResultCommit
		}
		return ctx, nil
	}
	allocationCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var order int64
	if err := s.operations.db.QueryRowContext(allocationCtx, `SELECT nextval('srun4k_operation_sequence')`).Scan(&order); err != nil || order <= 0 {
		return ctx, errSRunTestResultCommit
	}
	ctx = context.WithValue(ctx, srunOperationScopeKey{}, item)
	return context.WithValue(ctx, srunOperationOrderKey{}, order), nil
}

func (s *Server) recordSRunFailure(ctx context.Context, id, message string) {
	s.recordSRunOperationFailure(ctx, id, message, "integration.srun4k.test")
}

func (s *Server) recordSRunOperationFailure(ctx context.Context, id, message, action string) {
	// The originating request can already have expired. Retain its actor while
	// giving state and audit writes one finite budget, also for scheduler calls.
	reportCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	order, ordered := ctx.Value(srunOperationOrderKey{}).(int64)
	outcome := "failed_result_without_order"
	if ordered && order > 0 {
		query := `UPDATE srun4k_integrations SET connection_state='failed',last_error=$2,last_health_result_order=$3,updated_at=now() WHERE connector_id=$1 AND last_health_result_order<=$3 AND last_sync_result_order<=$3`
		if action == "integration.srun4k.test" {
			channelColumn := map[string]string{"authorization_database": "authorization_database_state", "online_redis": "online_redis_state", "catalog_redis": "catalog_redis_state", "event_redis": "event_redis_state", "northbound_api": "northbound_api_state"}[strings.SplitN(message, ":", 2)[0]]
			channelUpdate := ""
			if channelColumn != "" {
				channelUpdate = "," + channelColumn + "='failed'"
			}
			query = `UPDATE srun4k_integrations SET connection_state='failed',last_error=$2,last_tested_at=now(),last_test_result_order=$3,last_health_result_order=$3,updated_at=now()` + channelUpdate + ` WHERE connector_id=$1 AND last_health_result_order<=$3 AND last_test_result_order<=$3`
		}
		args := []any{id, message, order}
		item, scoped := ctx.Value(srunOperationScopeKey{}).(srun4KIntegration)
		scoped = scoped && item.ConnectorID == id
		if scoped {
			query += ` AND host=$4 AND source=$5 AND sensor_id=$6 AND reconcile_interval_hours=$7`
			args = append(args, item.Host, item.Source, item.SensorID, item.ReconcileIntervalHours)
		}
		outcome = "failed"
		written, err := s.operations.db.ExecContext(reportCtx, query, args...)
		if err != nil {
			outcome = "failed_result_not_applied"
			log.Printf("4K failure state write did not complete: connector=%q action=%q", id, action)
		} else if count, countErr := written.RowsAffected(); countErr == nil && count == 0 {
			outcome = "superseded"
			if scoped {
				var current bool
				if err := s.operations.db.QueryRowContext(reportCtx, `SELECT EXISTS(SELECT 1 FROM srun4k_integrations WHERE connector_id=$1 AND host=$2 AND source=$3 AND sensor_id=$4 AND reconcile_interval_hours=$5)`, id, item.Host, item.Source, item.SensorID, item.ReconcileIntervalHours).Scan(&current); err != nil {
					outcome = "failed_result_not_applied"
				} else if !current {
					outcome = "failed_for_previous_configuration"
				}
			}
		}
	}
	if err := s.writeAudit(reportCtx, action, id, outcome); err != nil {
		log.Printf("4K failure audit write did not complete: connector=%q action=%q", id, action)
	}
}

func srunOperationFailureStatus(err error) int {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, errIdentityLocalWorkInterrupted):
		return http.StatusRequestTimeout
	case errors.Is(err, productpolicy.ErrCatalogResourceLimit), errors.Is(err, legacy4k.ErrOnlineResourceLimit):
		return http.StatusUnprocessableEntity
	case errors.Is(err, errSRunGroupSnapshotSuperseded), errors.Is(err, errSRunGroupSnapshotConflict), isSRunObservationConflict(err):
		return http.StatusConflict
	case errors.Is(err, errSRunTestResultCommit), errors.Is(err, errSRunSyncResultCommit):
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadGateway
	}
}

func srunOperationFailureMessage(err error) string {
	if errors.Is(err, context.Canceled) {
		return "4K操作已取消，请重试"
	}
	if errors.Is(err, errIdentityLocalWorkInterrupted) {
		return "4K身份清单处理超时，请重试"
	}
	return err.Error()
}

func isSRunObservationConflict(err error) bool {
	return errors.Is(err, legacy4k.ErrOnlineInventoryChanged) || errors.Is(err, productpolicy.ErrRedisCatalogChanged)
}

func (s *Server) recordSRunSyncFailure(ctx context.Context, id string, failure error) {
	if errors.Is(failure, context.Canceled) {
		s.recordSRunCancellation(ctx, id, "integration.srun4k.sync")
		return
	}
	if errors.Is(failure, errIdentityLocalWorkInterrupted) {
		reportCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		if err := s.writeAudit(reportCtx, "integration.srun4k.sync", id, "local_processing_timeout"); err != nil {
			log.Printf("4K local interruption audit write did not complete: connector=%q", id)
		}
		return
	}
	if errors.Is(failure, errSRunTestResultCommit) || errors.Is(failure, errSRunSyncResultCommit) || errors.Is(failure, errSRunGroupSnapshotSuperseded) || errors.Is(failure, errSRunGroupSnapshotConflict) || isSRunObservationConflict(failure) || errors.Is(failure, productpolicy.ErrCatalogResourceLimit) || errors.Is(failure, legacy4k.ErrOnlineResourceLimit) {
		// A rejected/stale result commit is not proof that the current source
		// failed. In particular, do not overwrite a newly configured source.
		reportCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		outcome := "failed"
		if isSRunObservationConflict(failure) {
			outcome = "observation_conflict"
		} else if errors.Is(failure, productpolicy.ErrCatalogResourceLimit) {
			outcome = "catalog_resource_limit"
		} else if errors.Is(failure, legacy4k.ErrOnlineResourceLimit) {
			outcome = "online_resource_limit"
		} else if errors.Is(failure, errSRunGroupSnapshotSuperseded) {
			outcome = "superseded"
		} else if errors.Is(failure, errSRunGroupSnapshotConflict) {
			outcome = "snapshot_conflict"
		}
		if err := s.writeAudit(reportCtx, "integration.srun4k.sync", id, outcome); err != nil {
			log.Printf("4K failure audit write did not complete: connector=%q action=%q", id, "integration.srun4k.sync")
		}
		return
	}
	message := failure.Error()
	var testFailure *srun4KReadTestError
	if errors.As(failure, &testFailure) {
		message = testFailure.detail
	}
	s.recordSRunOperationFailure(ctx, id, message, "integration.srun4k.sync")
}

func (s *Server) syncSRun4K(ctx context.Context, id string) (result map[string]any, err error) {
	item, err := s.loadSRun4K(ctx, id)
	if err != nil {
		return nil, err
	}
	ctx, err = s.beginSRunOperation(ctx, item)
	if err != nil {
		return nil, err
	}
	// Manual and scheduled synchronization share the same failure reporting.
	// Preserve the original error and never overwrite a successful-sync time
	// or a connection-test time merely because full reconciliation failed.
	defer func() {
		if err != nil {
			s.recordSRunSyncFailure(ctx, id, err)
		}
	}()
	if _, err = s.testSRun4KWithDatabaseCheck(ctx, id, false); err != nil {
		return nil, err
	}
	snapshot, stats, err := s.readSRunIdentitySnapshot(ctx, item)
	if err != nil {
		return nil, err
	}
	reconciler, ok := s.reader.(store.IdentityReconciler)
	if !ok {
		return nil, fmt.Errorf("身份快照存储不可用")
	}
	if _, err = reconciler.CommitIdentitySnapshot(ctx, snapshot); err != nil {
		return nil, err
	}
	catalogClient := s.srunCatalogRedis(item)
	defer catalogClient.Close()
	catalog, err := productpolicy.ReadRedisSnapshot(ctx, catalogClient, item.Source, 10000)
	if err != nil {
		return nil, fmt.Errorf("读取4K产品目录失败: %w", err)
	}
	if _, _, err = commitProductPolicySnapshot(ctx, s.operations.db, "srun4k-catalog-"+catalog.ContentHash[:32], catalog); err != nil {
		return nil, err
	}
	client, err := s.srunClient(ctx, item)
	if err != nil {
		return nil, err
	}
	// Order group observations by the start of their own read, rather than
	// letting a slow response claim a newer observation merely by finishing late.
	groupsObservedAt := time.Now().UTC().Truncate(time.Microsecond)
	groups, err := client.Groups(ctx)
	if err != nil {
		return nil, fmt.Errorf("读取4K用户组目录失败: %w", err)
	}
	if err = s.commitSRunGroups(ctx, item.Source, groups, groupsObservedAt); err != nil {
		return nil, err
	}
	// Policy directory reads for the managed identity bridge are version
	// scoped.  Publish the same group snapshot into that scope during an
	// explicit sync as well; waiting for the six-hour background refresh made
	// the strategy editor show raw group IDs immediately after configuration.
	var bridgeVersion int64
	if err = s.operations.db.QueryRowContext(ctx, `SELECT active_config_version FROM identity_bridge_runtime WHERE bridge_id=$1 AND active_host=$2 AND active_config_version>0`, s.identityBridge.normalized().BridgeID, item.OnlineRedisHost).Scan(&bridgeVersion); err == nil {
		if err = s.commitSRunGroupsScoped(ctx, managedGroupCatalogSource(s.identityBridge.normalized().Source, bridgeVersion), groups, groupsObservedAt, item.OnlineRedisHost, bridgeVersion); err != nil {
			return nil, err
		}
	} else if err != sql.ErrNoRows {
		return nil, err
	}
	now := time.Now().UTC()
	return s.completeSRun4KSync(ctx, item, stats, len(catalog.Products), len(groups), len(catalog.Controls), now)
}

var errSRunSyncResultCommit = errors.New("4K同步结果保存失败，请重试同步")

func (s *Server) completeSRun4KSync(ctx context.Context, item srun4KIntegration, stats legacy4k.InventoryStats, products, groups, controls int, now time.Time) (map[string]any, error) {
	id := item.ConnectorID
	order, ok := ctx.Value(srunOperationOrderKey{}).(int64)
	if !ok || order <= 0 {
		return nil, errSRunSyncResultCommit
	}
	commitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tx, err := s.operations.db.BeginTx(commitCtx, nil)
	if err != nil {
		return nil, errSRunSyncResultCommit
	}
	defer tx.Rollback()
	var eventState, connectionState string
	err = tx.QueryRowContext(commitCtx, `UPDATE srun4k_integrations SET connection_state=CASE WHEN last_health_result_order<=$12 THEN 'healthy' ELSE connection_state END,last_error=CASE WHEN last_health_result_order<=$12 THEN '' ELSE last_error END,last_health_result_order=GREATEST(last_health_result_order,$12),last_sync_result_order=$12,last_synced_at=$2,identity_accounts=$3,identity_sessions=$4,products=$5,groups_count=$6,controls=$7,updated_at=now() WHERE connector_id=$1 AND host=$8 AND source=$9 AND sensor_id=$10 AND reconcile_interval_hours=$11 AND last_sync_result_order<=$12 RETURNING event_channel_state,connection_state`, id, now, stats.Accounts, stats.Sessions, products, groups, controls, item.Host, item.Source, item.SensorID, item.ReconcileIntervalHours, order).Scan(&eventState, &connectionState)
	if err != nil {
		return nil, errSRunSyncResultCommit
	}
	_, err = tx.ExecContext(commitCtx, `INSERT INTO audit_logs(audit_id,actor,action,target,outcome,created_at) VALUES($1,$2,'integration.srun4k.sync',$3,'completed',$4)`, "audit-srun4k-sync-"+shortToken(16), sessionFromContext(ctx).User.ID, id, now)
	if err != nil || tx.Commit() != nil {
		return nil, errSRunSyncResultCommit
	}
	s.refreshSRunConnector(ctx, id)
	return map[string]any{"connector_id": id, "source": item.Source, "synced_at": now, "identity_accounts": stats.Accounts, "identity_sessions": stats.Sessions, "address_records": stats.AddressRecords, "products": products, "groups": groups, "controls": controls, "event_channel_state": eventState, "connection_state": connectionState, "enforcement_ready": eventState == "healthy" && connectionState == "healthy"}, nil
}

var (
	errSRunGroupSnapshotSuperseded = errors.New("用户组目录已被较新的观测更新，请重新同步")
	errSRunGroupSnapshotConflict   = errors.New("相同观测时间的用户组目录内容冲突，请重新同步")
)

func canonicalSRunGroups(groups []srunapi.Group) ([]srunapi.Group, []byte, string, error) {
	ordered := append([]srunapi.Group{}, groups...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	for i, group := range ordered {
		if group.ID == "" || strings.TrimSpace(group.ID) != group.ID || (i > 0 && ordered[i-1].ID == group.ID) {
			return nil, nil, "", fmt.Errorf("用户组目录标识为空或重复")
		}
	}
	raw, err := json.Marshal(ordered)
	if err != nil {
		return nil, nil, "", err
	}
	digest := sha256.Sum256(raw)
	return ordered, raw, hex.EncodeToString(digest[:]), nil
}

func (s *Server) commitSRunGroups(ctx context.Context, source string, groups []srunapi.Group, observedAt time.Time) error {
	return s.commitSRunGroupsScoped(ctx, source, groups, observedAt, "", 0)
}

func (s *Server) commitSRunGroupsScoped(ctx context.Context, source string, groups []srunapi.Group, observedAt time.Time, expectedHost string, expectedVersion int64) error {
	if source == "" || strings.TrimSpace(source) != source || observedAt.IsZero() || observedAt.Nanosecond()%1000 != 0 {
		return fmt.Errorf("用户组目录来源或观测时间无效")
	}
	if (expectedHost == "") != (expectedVersion == 0) || expectedHost != "" && (!validSRunHost(expectedHost) || expectedVersion < 1) {
		return fmt.Errorf("托管4K用户组来源版本无效")
	}
	ordered, raw, digest, err := canonicalSRunGroups(groups)
	if err != nil {
		return err
	}
	tx, err := s.operations.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if expectedHost != "" {
		var activeHost string
		var activeVersion int64
		err = tx.QueryRowContext(ctx, `SELECT active_host,active_config_version FROM identity_bridge_runtime WHERE bridge_id=$1 FOR SHARE`, s.identityBridge.normalized().BridgeID).Scan(&activeHost, &activeVersion)
		if err == sql.ErrNoRows || err == nil && (activeHost != expectedHost || activeVersion != expectedVersion) {
			return errBridgeCatalogScope
		}
		if err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,7142))`, source); err != nil {
		return err
	}
	var latest sql.NullTime
	if err = tx.QueryRowContext(ctx, `SELECT max(observed_at) FROM srun4k_group_snapshots WHERE source=$1`, source).Scan(&latest); err != nil {
		return err
	}
	var oldHash sql.NullString
	var oldRaw []byte
	err = tx.QueryRowContext(ctx, `SELECT content_sha256,groups FROM srun4k_group_snapshots WHERE source=$1 AND observed_at=$2`, source, observedAt).Scan(&oldHash, &oldRaw)
	if err == nil {
		if !oldHash.Valid { // Migrations label legacy baselines explicitly.
			var legacy []srunapi.Group
			if json.Unmarshal(oldRaw, &legacy) != nil {
				return errSRunGroupSnapshotConflict
			}
			_, _, oldHash.String, err = canonicalSRunGroups(legacy)
			if err != nil {
				return errSRunGroupSnapshotConflict
			}
		}
		if oldHash.String != digest {
			return errSRunGroupSnapshotConflict
		}
		if latest.Valid && latest.Time.After(observedAt) {
			return errSRunGroupSnapshotSuperseded
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO srun4k_group_snapshots(source,observed_at,content_sha256,groups) VALUES($1,$2,$3,$4)`, source, observedAt, digest, raw); err != nil {
		return err
	}
	outcome := "committed"
	superseded := latest.Valid && latest.Time.After(observedAt)
	if superseded {
		outcome = "superseded"
	} else {
		if _, err = tx.ExecContext(ctx, `UPDATE srun4k_group_catalog SET active=false,updated_at=now() WHERE source=$1`, source); err != nil {
			return err
		}
		for _, group := range ordered {
			if _, err = tx.ExecContext(ctx, `INSERT INTO srun4k_group_catalog(source,group_id,name,parent_id,path,active,observed_at) VALUES($1,$2,$3,$4,$5,true,$6) ON CONFLICT(source,group_id) DO UPDATE SET name=EXCLUDED.name,parent_id=EXCLUDED.parent_id,path=EXCLUDED.path,active=true,observed_at=EXCLUDED.observed_at,updated_at=now()`, source, group.ID, group.Name, group.ParentID, group.Path, observedAt); err != nil {
				return err
			}
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(audit_id,actor,action,target,outcome,created_at) VALUES($1,$2,'integration.srun4k.groups',$3,$4,now())`, "audit-srun4k-groups-"+shortToken(16), sessionFromContext(ctx).User.ID, source, outcome); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if superseded {
		return errSRunGroupSnapshotSuperseded
	}
	return nil
}

func (s *Server) refreshSRunConnector(ctx context.Context, id string) {
	epoch := s.invalidateNativeRuntime(id)
	doc := emptyOperationsDocument()
	if loadConnectorsScoped(ctx, s.operations.db, &doc, ` WHERE connector_id=$1`, []any{id}) != nil {
		return
	}
	item, err := s.loadSRun4K(ctx, id)
	if err != nil {
		return
	}
	var runtime *NativeActionRuntime
	if client, clientErr := s.srunClient(ctx, item); clientErr == nil {
		runtime = &NativeActionRuntime{CredentialsFrom4K: false, Probe: client.OnlineTotal, Client: client, CampusID: "", AccessDomain: "", DropType: "radius", Read: func(readCtx context.Context) (legacy4k.OnlineInventory, error) {
			redisClient := s.srunRedis(item)
			defer redisClient.Close()
			return legacy4k.ReadOnlineInventoryPaged(readCtx, redisClient, "list:rad_online", s.srun4KDefaults.normalized().MaxSessions, s.srun4KDefaults.normalized().PageSize)
		}}
	}
	// Keep the established operations -> registry lock order used by native
	// dispatch. A stale refresh cannot overwrite either the runtime or its
	// in-memory connector metadata after a newer refresh has published.
	s.operations.mu.Lock()
	defer s.operations.mu.Unlock()
	if !s.setNativeRuntimeAtEpoch(id, epoch, runtime) {
		return
	}
	for key, connector := range doc.Connectors {
		s.operations.doc.Connectors[key] = connector
	}
}

func (s *Server) runSRun4KScheduler(ctx context.Context) {
	if s.operations == nil || s.operations.db == nil || s.readOnly {
		return
	}
	run := func() {
		items, err := s.listSRun4K(ctx)
		if err != nil {
			return
		}
		now := time.Now().UTC()
		for _, item := range items {
			s.refreshSRunConnector(ctx, item.ConnectorID)
			if item.LastSyncedAt == nil || !item.LastSyncedAt.Add(time.Duration(item.ReconcileIntervalHours)*time.Hour).After(now) {
				syncCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
				_, _ = s.syncSRun4K(syncCtx, item.ConnectorID)
				cancel()
			} else if item.EventChannelState != "healthy" || item.LastIdentityEventAt == nil || now.Sub(*item.LastIdentityEventAt) >= 2*time.Minute {
				pollCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
				_ = s.pollSRunIdentity(pollCtx, item.ConnectorID)
				cancel()
			}
		}
	}
	run()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func (s *Server) srunIdentityRegistration(ctx context.Context, scope store.IdentityScope) (int, bool) {
	interval, registered, err := s.srunIdentityRegistrationContext(ctx, scope)
	return interval, registered && err == nil
}

func (s *Server) srunEventChannelHealthy(ctx context.Context, connectorID string) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	healthy, err := s.srunEventChannelStatusContext(ctx, connectorID)
	return healthy && err == nil
}

func sortDirectoryItems(items []fourKDirectoryItem) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Name != items[j].Name {
			return items[i].Name < items[j].Name
		}
		return items[i].ID < items[j].ID
	})
}
