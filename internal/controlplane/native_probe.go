package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"proxy-sentinel/internal/srunapi"
	"time"
)

func (s *Server) handleNativeConnectorProbe(w http.ResponseWriter, r *http.Request, id string) bool {
	runtime, ok := s.nativeRuntime(id)
	if !ok {
		return false
	}
	if runtime.Probe == nil || runtime.Read == nil {
		writeError(w, 503, "native_probe_unavailable", "原生只读检查未配置")
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	count, err := runtime.Probe(ctx)
	if err != nil || count < 0 {
		s.appendAudit(r.Context(), "enforcement.connector.test", id, "native_api_failed")
		writeError(w, 502, "native_api_unavailable", "原生管理接口认证或查询失败")
		return true
	}
	inventory, err := runtime.Read(ctx)
	now := time.Now().UTC()
	if err == nil {
		_, err = inventory.IdentityRecords()
	}
	if err != nil || inventory.InstanceID == "" || inventory.ObservedAt.After(now) || now.Sub(inventory.ObservedAt) > 30*time.Second {
		s.appendAudit(r.Context(), "enforcement.connector.test", id, "native_inventory_failed")
		writeError(w, 502, "native_inventory_unavailable", "权威在线清单不可用或时间无效")
		return true
	}
	s.appendAudit(r.Context(), "enforcement.connector.test", id, "native_read_only_succeeded")
	writeJSON(w, 200, map[string]any{"connector_id": id, "reachable": true, "checked_at": formatDBTime(now), "read_only": true, "online_total": count, "identity_verified": true, "inventory_records": len(inventory.Rows)})
	return true
}

// Management connectivity does not require or prove a complete identity inventory.
// This client is deliberately not registered as an enforcement runtime.
func (s *Server) probeManaged4K(ctx context.Context, connector ActionConnector, hc *http.Client) (int64, error) {
	credentials, err := s.credentialsFrom4K(ctx, connector.ConnectorID)
	if err != nil {
		return 0, fmt.Errorf("数据库授权不可用，请先保存并检查4K数据库授权")
	}
	if connector.CertificatePEM != "" {
		hc, err = srunapi.NewCertificatePinnedClient([]byte(connector.CertificatePEM))
		if err != nil {
			return 0, fmt.Errorf("固定信任证书无效或已过期，请重新配置服务器证书")
		}
		defer hc.CloseIdleConnections()
	}
	client, err := srunapi.New(connector.EndpointURL, credentials.AppID, credentials.AppSecret, hc)
	if err != nil {
		return 0, fmt.Errorf("管理API根地址无效，请检查高级设置")
	}
	count, err := client.OnlineTotal(ctx)
	if err != nil {
		if errors.Is(err, srunapi.ErrCertificateTrust) {
			return 0, fmt.Errorf("管理API证书不受信任或与固定证书不匹配，请在高级设置中配置经核实的服务器证书")
		}
		if errors.Is(err, srunapi.ErrAuthentication) {
			return 0, fmt.Errorf("管理API令牌申请失败，请检查地址、网络及authorization授权")
		}
		return 0, fmt.Errorf("令牌申请成功，但管理API只读查询失败，请检查接口能力和查询权限")
	}
	return count, nil
}

func (s *Server) handleManaged4KProbe(w http.ResponseWriter, r *http.Request, connector ActionConnector) {
	if s.operations.db == nil {
		writeError(w, 409, "native_runtime_unavailable", "请先配置4K数据库授权")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	count, err := s.probeManaged4K(ctx, connector, nil)
	if err != nil {
		s.appendAudit(r.Context(), "enforcement.connector.test", connector.ConnectorID, "managed_api_failed")
		writeError(w, 502, "native_api_unavailable", err.Error())
		return
	}
	s.appendAudit(r.Context(), "enforcement.connector.test", connector.ConnectorID, "managed_api_read_only_succeeded")
	writeJSON(w, 200, map[string]any{"connector_id": connector.ConnectorID, "reachable": true, "read_only": true, "checked_at": formatDBTime(time.Now().UTC()), "online_total": count, "identity_verified": false, "enforcement_ready": false, "blockers": []string{"authoritative_inventory_not_configured"}})
}
