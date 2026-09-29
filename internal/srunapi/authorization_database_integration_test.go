package srunapi

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

func TestMySQLAuthorizationReadOnlySelectionRotationAndExpiry(t *testing.T) {
	dsn := os.Getenv("PROXY_SENTINEL_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("isolated MySQL required")
	}
	root, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal("invalid isolated DSN")
	}
	if root.DBName != "sentinel_auth_test" {
		t.Fatal("requires explicitly isolated sentinel_auth_test database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal("isolated MySQL unavailable")
	}
	defer db.Close()
	name := fmt.Sprintf("sentinel_auth_%d", time.Now().UnixNano())
	user := fmt.Sprintf("auth_%d", time.Now().UnixNano())
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("isolated fixture query failed: %v", err)
		}
	}
	exec("CREATE DATABASE `" + name + "`")
	defer db.ExecContext(context.Background(), "DROP DATABASE `"+name+"`")
	exec("CREATE TABLE `" + name + "`.authorization (id bigint PRIMARY KEY,appId varchar(32),appSecret varchar(128),accessOrganization varchar(128),status int,expired_at bigint)")
	exec("CREATE USER '" + user + "'@'%' IDENTIFIED BY 'isolated-readonly-password'")
	defer db.ExecContext(context.Background(), "DROP USER '"+user+"'@'%'")
	exec("GRANT SELECT ON `" + name + "`.authorization TO '" + user + "'@'%'")
	table := "`" + name + "`.authorization"
	exec("INSERT INTO " + table + " VALUES(7,'sentinel','first-secret','test',0,0),(9,'expired','secret','test',0,UNIX_TIMESTAMP()-1),(10,'disabled','secret','test',1,0)")
	cfg := AuthorizationDatabase{Host: "127.0.0.1", Port: 23306, Database: name, Username: user, Password: "isolated-readonly-password"}
	got, err := ReadApplicationCredentials(ctx, cfg)
	if err != nil || got.ID != 7 || got.AppSecret != "first-secret" {
		t.Fatalf("unique read: %v", err)
	}
	exec("INSERT INTO " + table + " VALUES(8,'second','secret','other',0,0)")
	if _, err = ReadApplicationCredentials(ctx, cfg); err == nil {
		t.Fatal("multiple authorizations silently selected")
	}
	cfg.AuthorizationID = 7
	exec("UPDATE " + table + " SET appSecret='rotated-secret' WHERE id=7")
	if got, err = ReadApplicationCredentials(ctx, cfg); err != nil || got.AppSecret != "rotated-secret" {
		t.Fatalf("rotation not visible: %v", err)
	}
	exec("UPDATE " + table + " SET status=1 WHERE id=7")
	if _, err = ReadApplicationCredentials(ctx, cfg); err == nil {
		t.Fatal("disabled authorization used")
	}
	exec("UPDATE " + table + " SET status=0,expired_at=UNIX_TIMESTAMP()-1 WHERE id=7")
	if _, err = ReadApplicationCredentials(ctx, cfg); err == nil {
		t.Fatal("expired authorization used")
	}
	cfg.Password = "wrong-private-password"
	if _, err = ReadApplicationCredentials(ctx, cfg); err == nil || strings.Contains(err.Error(), cfg.Password) {
		t.Fatal("authentication failure not sanitized")
	}
}
