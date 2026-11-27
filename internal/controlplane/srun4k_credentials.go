package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	"proxy-sentinel/internal/srunapi"
)

const srun4KCredentialsPrefix = "srun4k_connection_credentials:"

type srun4KCredentialsInput struct {
	DatabaseUsername      string `json:"database_username,omitempty"`
	DatabasePassword      string `json:"database_password,omitempty"`
	RedisPassword         string `json:"redis_password,omitempty"`
	NorthboundCertificate string `json:"northbound_certificate,omitempty"`
}

type srun4KStoredCredentials struct {
	Revision              string `json:"revision,omitempty"`
	DatabaseUsername      string `json:"database_username,omitempty"`
	EncryptedDatabase     string `json:"encrypted_database_password,omitempty"`
	EncryptedRedis        string `json:"encrypted_redis_password,omitempty"`
	NorthboundCertificate string `json:"northbound_certificate,omitempty"`
}

type srun4KCredentialStatus struct {
	DatabaseConfigured    bool `json:"database_configured"`
	RedisConfigured       bool `json:"redis_configured"`
	CertificateConfigured bool `json:"certificate_configured"`
}

func srun4KCredentialTransport(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || !net.ParseIP(peer).IsLoopback() {
		return false
	}
	host := r.Host
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	return host == "localhost" || net.ParseIP(strings.Trim(host, "[]")).IsLoopback()
}

func (input srun4KCredentialsInput) validate() error {
	username := strings.TrimSpace(input.DatabaseUsername)
	if (username == "") != (input.DatabasePassword == "") {
		return errors.New("请同时填写授权数据库只读账号和密码")
	}
	if len(username) > 128 || strings.ContainsAny(username, "\r\n\x00") || len(input.DatabasePassword) > 4096 || len(input.RedisPassword) > 4096 {
		return errors.New("4K账号或密码格式无效")
	}
	if input.NorthboundCertificate != "" {
		client, err := srunapi.NewCertificatePinnedClient([]byte(input.NorthboundCertificate))
		if err != nil {
			return errors.New("请填写一份有效期内的北向服务端 PEM 证书")
		}
		client.CloseIdleConnections()
	}
	return nil
}

func (s *Server) saveSRun4KCredentials(ctx context.Context, tx *sql.Tx, id string, input srun4KCredentialsInput, previous srun4KStoredCredentials, databaseChanged, redisChanged, apiChanged bool) (srun4KStoredCredentials, error) {
	next := previous
	if databaseChanged {
		next.DatabaseUsername, next.EncryptedDatabase = "", ""
	}
	if redisChanged {
		next.EncryptedRedis = ""
	}
	if apiChanged {
		next.NorthboundCertificate = ""
	}
	var err error
	if input.DatabasePassword != "" {
		next.DatabaseUsername = strings.TrimSpace(input.DatabaseUsername)
		next.EncryptedDatabase, err = s.encryptConnectorSecret(input.DatabasePassword)
		if err != nil {
			return previous, err
		}
	}
	if input.RedisPassword != "" {
		next.EncryptedRedis, err = s.encryptConnectorSecret(input.RedisPassword)
		if err != nil {
			return previous, err
		}
	}
	if input.NorthboundCertificate != "" {
		next.NorthboundCertificate = input.NorthboundCertificate
	}
	if next == previous && !apiChanged {
		return next, nil
	}
	next.Revision = shortToken(16)
	raw, err := json.Marshal(next)
	if err != nil {
		return previous, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO control_plane_settings(setting_key,setting_value) VALUES($1,$2)
		ON CONFLICT (setting_key) DO UPDATE SET setting_value=EXCLUDED.setting_value,updated_at=now()`, srun4KCredentialsPrefix+id, raw)
	return next, err
}

const srun4KCredentialsRevision = `COALESCE((SELECT setting_value->>'revision' FROM control_plane_settings WHERE setting_key='` + srun4KCredentialsPrefix + `'||srun4k_integrations.connector_id),'')`
