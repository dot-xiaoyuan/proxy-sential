package controlplane

import (
	"context"
	"net/http"
	"strings"
	"time"

	"proxy-sentinel/internal/legacy4k"
	"proxy-sentinel/internal/srunapi"
)

func (s *Server) handleManagedAccountObservation(w http.ResponseWriter, r *http.Request, connector ActionConnector) {
	account := r.URL.Query().Get("account_id")
	if account == "" || account != strings.TrimSpace(account) || len(account) > 256 {
		writeError(w, 400, "invalid_account", "请提供明确账号")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var hc *http.Client
	if connector.CertificatePEM != "" {
		var err error
		hc, err = srunapi.NewCertificatePinnedClient([]byte(connector.CertificatePEM))
		if err != nil {
			writeError(w, 503, "native_certificate_unavailable", "服务器信任证书无效")
			return
		}
		defer hc.CloseIdleConnections()
	}
	client, err := srunapi.New(connector.EndpointURL, "managed-provider", "managed-provider", hc)
	if err != nil {
		writeError(w, 503, "native_api_unavailable", "管理接口地址无效")
		return
	}
	client = client.WithCredentialsProvider(func(ctx context.Context) (string, string, error) {
		credentials, err := s.credentialsFrom4K(ctx, connector.ConnectorID)
		return credentials.AppID, credentials.AppSecret, err
	})
	observed, err := client.OnlineEquipment(ctx, account)
	if err != nil {
		writeError(w, 503, "native_observation_unavailable", "账号在线查询失败或返回字段无效；此结果不代表用户离线")
		return
	}
	scopeCampus, scopeDomain := "未配置", "未配置"
	registrations, err := s.managedIdentityRegistrations(ctx)
	if err != nil {
		writeError(w, 503, "identity_status_unavailable", "身份配置读取失败")
		return
	}
	var configVersion int64
	for _, registration := range registrations {
		if registration.ID == connector.ConnectorID {
			scopeCampus = registration.Config.CampusID
			scopeDomain = registration.Config.AccessDomain
			configVersion = registration.Version
		}
	}
	sessions := []map[string]any{}
	for _, row := range observed.Rows {
		id := legacy4k.OnlineSessionID("4k:"+connector.ConnectorID, row["rad_online_id"], row["add_time"])
		sessions = append(sessions, map[string]any{"target": map[string]any{"session_id": id, "source_session_id": row["rad_online_id"], "login_generation": row["add_time"], "session_id_source": "derived_connector_raw_id_login"}, "addresses": []string{row["ip"]}, "raw_fields": row})
	}
	writeJSON(w, 200, map[string]any{"connector_id": connector.ConnectorID, "config_version": configVersion, "read_only": true, "coverage": "account_observation_only", "observed_at": observed.ObservedAt, "timestamp_source": "sentinel_query_completed", "complete": false, "absence_verified": false, "enforcement_ready": false, "blockers": []string{observed.Blocker}, "plan": map[string]any{"account": account, "campus_id": scopeCampus, "access_domain": scopeDomain, "fingerprint": "", "sessions": sessions}})
}
