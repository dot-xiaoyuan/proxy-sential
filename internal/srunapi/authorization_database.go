package srunapi

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

// AuthorizationDatabase is private runtime configuration. Password must never
// be included in a public response; controlplane encrypts it before persistence.
type AuthorizationDatabase struct {
	Host            string `json:"host"`
	Port            int    `json:"port"`
	Database        string `json:"database"`
	Username        string `json:"username"`
	Password        string `json:"password,omitempty"`
	TLS             bool   `json:"tls"`
	AuthorizationID int64  `json:"authorization_id,omitempty"`
}

type ApplicationCredentials struct {
	ID                             int64
	AppID, AppSecret, Organization string
	ExpiresAt                      int64
}

func (c AuthorizationDatabase) Validate() error {
	if strings.TrimSpace(c.Host) != c.Host || c.Host == "" || strings.ContainsAny(c.Host, "/\\@?# \t\r\n") || c.Port < 1 || c.Port > 65535 || c.Database == "" || len(c.Database) > 64 || strings.TrimSpace(c.Username) == "" || len(c.Username) > 128 || c.AuthorizationID < 0 {
		return fmt.Errorf("valid 4K database host, port, database, username and authorization selection required")
	}
	return nil
}

// ReadApplicationCredentials executes only a SELECT in a read-only transaction.
// No credentials are cached: revocation and rotation are checked at each token request.
func ReadApplicationCredentials(ctx context.Context, c AuthorizationDatabase) (ApplicationCredentials, error) {
	var empty ApplicationCredentials
	if c.Validate() != nil || c.Password == "" {
		return empty, fmt.Errorf("4K database configuration incomplete")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cfg := mysql.NewConfig()
	cfg.User = c.Username
	cfg.Passwd = c.Password
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	cfg.DBName = c.Database
	cfg.Timeout = 2 * time.Second
	cfg.ReadTimeout = 2 * time.Second
	cfg.WriteTimeout = 2 * time.Second
	if c.TLS {
		cfg.TLSConfig = "true"
	}
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return empty, fmt.Errorf("4K database unavailable")
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return empty, fmt.Errorf("4K database unavailable or read-only transaction unsupported")
	}
	defer tx.Rollback()
	result, err := selectApplicationCredentials(ctx, tx, c.AuthorizationID)
	if err != nil {
		return empty, err
	}
	if tx.Commit() != nil {
		return empty, fmt.Errorf("4K authorization read failed")
	}
	return result, nil
}

type credentialQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func selectApplicationCredentials(ctx context.Context, q credentialQuerier, id int64) (ApplicationCredentials, error) {
	var empty ApplicationCredentials
	query := "SELECT id,appId,appSecret,accessOrganization,expired_at FROM authorization WHERE status=0 AND (expired_at=0 OR expired_at>=UNIX_TIMESTAMP())"
	args := []any{}
	if id > 0 {
		query += " AND id=?"
		args = append(args, id)
	}
	query += " ORDER BY id LIMIT 2"
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return empty, fmt.Errorf("4K authorization query failed")
	}
	defer rows.Close()
	var result ApplicationCredentials
	count := 0
	for rows.Next() {
		var item ApplicationCredentials
		if rows.Scan(&item.ID, &item.AppID, &item.AppSecret, &item.Organization, &item.ExpiresAt) != nil {
			return empty, fmt.Errorf("4K authorization fields invalid")
		}
		if item.ID <= 0 || strings.TrimSpace(item.AppID) == "" || item.AppSecret == "" || strings.TrimSpace(item.Organization) == "" {
			return empty, fmt.Errorf("4K authorization fields incomplete")
		}
		result = item
		count++
	}
	if rows.Err() != nil {
		return empty, fmt.Errorf("4K authorization result incomplete")
	}
	if count == 0 {
		return empty, fmt.Errorf("no enabled unexpired 4K authorization found")
	}
	if count != 1 {
		return empty, fmt.Errorf("multiple enabled 4K authorizations; select an authorization ID")
	}
	return result, nil
}
