package controlplane

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"proxy-sentinel/internal/store"
)

type managedIdentityConfig struct {
	store.IdentityScope
	Kind         string   `json:"kind"`
	UserCIDRs    []string `json:"user_cidrs"`
	InventoryURL string   `json:"inventory_url,omitempty"`
	Token        string   `json:"token,omitempty"`
	MaxRecords   int      `json:"max_records"`
	Enabled      bool     `json:"enabled"`
}

func (c managedIdentityConfig) validate() error {
	for _, v := range []string{c.Source, c.SensorID, c.CampusID, c.AccessDomain} {
		if v == "" || strings.TrimSpace(v) != v || len(v) > 200 {
			return fmt.Errorf("explicit scope required")
		}
	}
	if c.MaxRecords < 1 || c.MaxRecords > 10000 || len(c.UserCIDRs) == 0 || len(c.UserCIDRs) > 64 || len(c.Token) > 4096 {
		return fmt.Errorf("invalid bounds")
	}
	for _, v := range c.UserCIDRs {
		p, e := netip.ParsePrefix(v)
		if e != nil || p.Bits() == 0 || p != p.Masked() {
			return fmt.Errorf("canonical controlled user CIDRs required")
		}
	}
	switch c.Kind {
	case "online_equipment":
		if c.InventoryURL != "" || c.Token != "" {
			return fmt.Errorf("native source uses configured management authorization")
		}
	case "complete_inventory":
		u, e := url.Parse(c.InventoryURL)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("existing complete inventory HTTPS URL required")
		}
	default:
		return fmt.Errorf("unsupported identity source")
	}
	return nil
}
func managedIdentityPath(path string) (string, bool) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(path, "/api/v1/actions/"), "/"), "/")
	if len(parts) == 3 && parts[0] == "connectors" && parts[2] == "identity-source" {
		return parts[1], true
	}
	return "", false
}
func (s *Server) handleManagedIdentity(w http.ResponseWriter, r *http.Request, id string) {
	if s.operations.db == nil {
		writeError(w, 503, "configuration_storage_required", "身份配置需要 PostgreSQL 存储")
		return
	}
	ctx, cancel := contextWithRequestTimeout(r.Context())
	defer cancel()
	var connectorType string
	if err := s.operations.db.QueryRowContext(ctx, `SELECT connector_type FROM enforcement_connectors WHERE connector_id=$1`, id).Scan(&connectorType); err != nil {
		if err == sql.ErrNoRows {
			writeError(w, 404, "connector_not_found", "连接器不存在")
		} else {
			writeError(w, 503, "configuration_unavailable", "连接器读取失败")
		}
		return
	}
	if connectorType != "srun4k" {
		writeError(w, 409, "native_connector_required", "身份来源仅适用于原生4K连接器")
		return
	}
	switch r.Method {
	case http.MethodGet:
		var raw []byte
		var version int64
		var token bool
		var state, blocker string
		err := s.operations.db.QueryRowContext(ctx, `SELECT public_config,config_version,octet_length(encrypted_token)>0,state,blocker FROM enforcement_identity_sources WHERE connector_id=$1`, id).Scan(&raw, &version, &token, &state, &blocker)
		if err == sql.ErrNoRows {
			writeJSON(w, 200, map[string]any{"configuration": managedIdentityConfig{Kind: "online_equipment", MaxRecords: 10000, IdentityScope: store.IdentityScope{Source: "4k:" + id, SensorID: s.sensorID}}, "config_version": 0, "state": "not_configured", "blocker": "authoritative_inventory_not_configured", "token_configured": false})
			return
		}
		if err != nil {
			writeError(w, 503, "configuration_unavailable", "身份配置读取失败")
			return
		}
		cache := s.identityFailureCache()
		cache.RLock()
		if failure, ok := cache.Values[id]; ok && failure.Version == version {
			state = "unavailable"
			blocker = failure.Blocker
		}
		cache.RUnlock()
		var cfg managedIdentityConfig
		if json.Unmarshal(raw, &cfg) != nil {
			writeError(w, 503, "configuration_unavailable", "身份配置无效")
			return
		}
		cfg.Token = ""
		writeJSON(w, 200, map[string]any{"configuration": cfg, "config_version": version, "state": state, "blocker": blocker, "token_configured": token})
	case http.MethodPut:
		var req struct {
			Configuration managedIdentityConfig `json:"configuration"`
			Version       int64                 `json:"config_version"`
		}
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32768))
		d.DisallowUnknownFields()
		var extra any
		if d.Decode(&req) != nil || d.Decode(&extra) != io.EOF || req.Configuration.validate() != nil || req.Version < 0 {
			writeError(w, 400, "bad_identity_source", "请填写身份来源、校区、接入域、受控网段和有效清单地址")
			return
		}
		tx, err := s.operations.db.BeginTx(ctx, nil)
		if err != nil {
			writeError(w, 503, "configuration_unavailable", "身份配置保存失败")
			return
		}
		defer tx.Rollback()
		var kind string
		if tx.QueryRowContext(ctx, `SELECT connector_type FROM enforcement_connectors WHERE connector_id=$1 FOR UPDATE`, id).Scan(&kind) != nil || kind != "srun4k" {
			writeError(w, 409, "native_connector_required", "身份来源仅适用于原生4K连接器")
			return
		}
		var version int64
		var token []byte
		var previous []byte
		err = tx.QueryRowContext(ctx, `SELECT config_version,encrypted_token,public_config FROM enforcement_identity_sources WHERE connector_id=$1 FOR UPDATE`, id).Scan(&version, &token, &previous)
		if err != nil && err != sql.ErrNoRows {
			writeError(w, 503, "configuration_unavailable", "身份配置保存失败")
			return
		}
		if version == 0 && err == sql.ErrNoRows {
			if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('sentinel:managed-identity-capacity'))`); err != nil {
				writeError(w, 503, "configuration_unavailable", "身份配置保存失败")
				return
			}
			var count int
			if tx.QueryRowContext(ctx, `SELECT count(*) FROM enforcement_identity_sources`).Scan(&count) != nil {
				writeError(w, 503, "configuration_unavailable", "身份来源配额读取失败")
				return
			}
			if count >= 16 {
				writeError(w, 409, "identity_source_capacity", "身份来源已达到16个有界同步配置的上限")
				return
			}
		}
		if version != req.Version {
			writeError(w, 409, "configuration_changed", "配置已变化，请重新打开后保存")
			return
		}
		cfg := req.Configuration
		if cfg.Kind == "online_equipment" {
			token = nil
		} else if cfg.Token != "" {
			encrypted, e := s.encryptConnectorSecret(cfg.Token)
			if e != nil {
				writeError(w, 503, "encryption_unavailable", "清单凭据加密失败")
				return
			}
			token = []byte(encrypted)
		} else {
			var old managedIdentityConfig
			_ = json.Unmarshal(previous, &old)
			if old.InventoryURL != cfg.InventoryURL {
				token = nil
			}
		}
		if cfg.Kind == "complete_inventory" && len(token) == 0 {
			writeError(w, 400, "inventory_credential_required", "首次配置或更换清单地址时需要填写已有接口凭据")
			return
		}
		cfg.Token = ""
		raw, _ := json.Marshal(cfg)
		if token == nil {
			token = []byte{}
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO enforcement_identity_sources(connector_id,config_version,public_config,encrypted_token) VALUES($1,$2,$3,$4) ON CONFLICT(connector_id) DO UPDATE SET config_version=EXCLUDED.config_version,public_config=EXCLUDED.public_config,encrypted_token=EXCLUDED.encrypted_token,state='pending',blocker='identity_not_checked',observed_at=NULL,updated_at=now()`, id, version+1, raw, token)
		if err == nil {
			_, err = tx.ExecContext(ctx, `INSERT INTO audit_logs(audit_id,actor,action,target,outcome,created_at) VALUES($1,$2,'enforcement.identity.configure',$3,'saved',now())`, "managed-identity-"+shortToken(16), sessionFromContext(ctx).User.ID, id)
		}
		if err != nil || tx.Commit() != nil {
			writeError(w, 503, "configuration_unavailable", "身份配置保存失败")
			return
		}
		writeJSON(w, 200, map[string]any{"configuration": cfg, "config_version": version + 1, "token_configured": len(token) > 0, "state": "pending", "blocker": "identity_not_checked"})
	default:
		writeError(w, 405, "method_not_allowed", "仅支持 GET 和 PUT")
	}
}

func managedAddressInScope(value string, cidrs []string) bool {
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	for _, value := range cidrs {
		prefix, err := netip.ParsePrefix(value)
		if err == nil && prefix.Contains(ip) {
			return true
		}
	}
	return false
}
