package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"proxy-sentinel/internal/srunapi"
)

func (s *Server) load4KDatabase(ctx context.Context, id string, private bool) (srunapi.AuthorizationDatabase, bool, error) {
	var cfg srunapi.AuthorizationDatabase
	if s.operations.db == nil {
		return cfg, false, fmt.Errorf("PostgreSQL configuration storage required")
	}
	var raw, password []byte
	err := s.operations.db.QueryRowContext(ctx, `SELECT public_config,encrypted_password FROM enforcement_4k_databases WHERE connector_id=$1`, id).Scan(&raw, &password)
	if err == sql.ErrNoRows {
		return cfg, false, nil
	}
	if err != nil || json.Unmarshal(raw, &cfg) != nil {
		return cfg, false, fmt.Errorf("4K configuration unavailable")
	}
	cfg.Password = ""
	if private {
		cfg.Password, err = s.decryptConnectorSecret(string(password))
		if err != nil {
			return cfg, false, fmt.Errorf("4K database password unavailable")
		}
	}
	return cfg, true, nil
}

func (s *Server) credentialsFrom4K(ctx context.Context, id string) (srunapi.ApplicationCredentials, error) {
	cfg, exists, err := s.load4KDatabase(ctx, id, true)
	if err != nil || !exists {
		return srunapi.ApplicationCredentials{}, fmt.Errorf("4K database credentials not configured or unavailable")
	}
	return srunapi.ReadApplicationCredentials(ctx, cfg)
}

func (s *Server) bind4KCredentialProviders() {
	for id, runtime := range s.nativeActions {
		client, ok := runtime.Client.(*srunapi.Client)
		if !ok {
			continue
		}
		bound := client.WithCredentialOverride(func(ctx context.Context) (string, string, bool, error) {
			if s.operations.db == nil {
				if runtime.CredentialsFrom4K {
					return "", "", true, fmt.Errorf("4K database configuration storage unavailable")
				}
				return "", "", false, nil
			}
			cfg, configured, err := s.load4KDatabase(ctx, id, true)
			if err != nil {
				return "", "", true, err
			}
			if !configured {
				if runtime.CredentialsFrom4K {
					return "", "", true, fmt.Errorf("4K database credentials not configured")
				}
				return "", "", false, nil
			}
			credentials, err := srunapi.ReadApplicationCredentials(ctx, cfg)
			return credentials.AppID, credentials.AppSecret, true, err
		})
		runtime.Client = bound
		runtime.Probe = bound.OnlineTotal
		s.nativeActions[id] = runtime
	}
}

func (s *Server) handle4KDatabase(w http.ResponseWriter, r *http.Request, id string) {
	if s.operations.db == nil {
		writeError(w, 503, "configuration_storage_required", "4K 数据库配置需要 PostgreSQL 存储")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var exists bool
	if s.operations.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM enforcement_connectors WHERE connector_id=$1)`, id).Scan(&exists) != nil {
		writeError(w, 503, "configuration_unavailable", "连接器配置不可用")
		return
	}
	if !exists {
		writeError(w, 404, "connector_not_found", "连接器不存在")
		return
	}
	switch r.Method {
	case http.MethodGet:
		cfg, configured, err := s.load4KDatabase(ctx, id, false)
		if err != nil {
			writeError(w, 503, "configuration_unavailable", "4K 数据库配置不可用")
			return
		}
		if !configured {
			cfg.Port = 3306
		}
		writeJSON(w, 200, map[string]any{"configuration": cfg, "password_configured": configured, "credential_source": "4k_database"})
	case http.MethodPut:
		var cfg srunapi.AuthorizationDatabase
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 16385))
		if readErr != nil || len(body) > 16384 {
			writeError(w, 400, "bad_4k_database", "数据库配置不能超过 16 KiB")
			return
		}
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		decoder.DisallowUnknownFields()
		var extra any
		if decoder.Decode(&cfg) != nil || decoder.Decode(&extra) != io.EOF || cfg.Validate() != nil || len(cfg.Password) > 4096 {
			writeError(w, 400, "bad_4k_database", "请填写有效的数据库地址、端口、数据库名、用户名及授权 ID")
			return
		}
		tx, err := s.operations.db.BeginTx(ctx, nil)
		if err != nil {
			writeError(w, 503, "configuration_save_failed", "4K 数据库配置保存失败")
			return
		}
		defer tx.Rollback()
		// Use the same connector lock as connector mutations, without network I/O.
		if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "enforcement-connector:"+id); err != nil {
			writeError(w, 503, "configuration_save_failed", "4K 数据库配置保存失败")
			return
		}
		var encrypted []byte
		err = tx.QueryRowContext(ctx, `SELECT encrypted_password FROM enforcement_4k_databases WHERE connector_id=$1 FOR UPDATE`, id).Scan(&encrypted)
		if err != nil && err != sql.ErrNoRows {
			writeError(w, 503, "configuration_save_failed", "4K 数据库配置保存失败")
			return
		}
		if cfg.Password != "" {
			value, err := s.encryptConnectorSecret(cfg.Password)
			if err != nil {
				writeError(w, 409, "action_master_key_required", "请先配置后端 action-master-key，才能加密保存数据库密码")
				return
			}
			encrypted = []byte(value)
		}
		if len(encrypted) == 0 {
			writeError(w, 400, "database_password_required", "首次配置需要数据库密码")
			return
		}
		cfg.Password = ""
		raw, err := json.Marshal(cfg)
		if err != nil {
			writeError(w, 400, "bad_4k_database", "4K 数据库配置无效")
			return
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO enforcement_4k_databases(connector_id,public_config,encrypted_password) VALUES($1,$2,$3) ON CONFLICT(connector_id) DO UPDATE SET public_config=EXCLUDED.public_config,encrypted_password=EXCLUDED.encrypted_password,updated_at=clock_timestamp()`, id, raw, encrypted); err != nil {
			writeError(w, 503, "configuration_save_failed", "4K 数据库配置保存失败")
			return
		}
		if tx.Commit() != nil {
			writeError(w, 503, "configuration_save_failed", "4K 数据库配置保存失败")
			return
		}
		s.appendAudit(r.Context(), "enforcement.4k_database.save", id, "saved")
		writeJSON(w, 200, map[string]any{"configuration": cfg, "password_configured": true, "credential_source": "4k_database"})
	case http.MethodPost:
		credentials, err := s.credentialsFrom4K(ctx, id)
		if err != nil {
			s.appendAudit(r.Context(), "enforcement.4k_database.test", id, "failed")
			writeError(w, 502, "4k_authorization_unavailable", err.Error())
			return
		}
		s.appendAudit(r.Context(), "enforcement.4k_database.test", id, "read_only_succeeded")
		writeJSON(w, 200, map[string]any{"read_only": true, "authorization_id": credentials.ID, "app_id": credentials.AppID, "organization": credentials.Organization, "expires_at": credentials.ExpiresAt, "checked_at": time.Now().UTC(), "management_api_verified": false})
	default:
		w.Header().Set("Allow", "GET, PUT, POST")
		writeError(w, 405, "method_not_allowed", "不支持此操作")
	}
}

func is4KDatabasePath(path string) bool {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(strings.TrimPrefix(path, "/api/v1"), "/actions/"), "/"), "/")
	return len(parts) == 3 && parts[0] == "connectors" && parts[2] == "4k-database"
}
