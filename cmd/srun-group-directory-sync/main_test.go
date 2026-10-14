package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"proxy-sentinel/internal/srunapi"
)

func northboundStub(t *testing.T, groups string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/auth/get-access-token":
			_, _ = io.WriteString(w, `{"code":0,"message":"ok","data":{"access_token":"token","lifetime":60}}`)
		case "/api/v2/groups":
			if r.URL.Query().Get("access_token") != "token" || r.URL.Query().Get("per-page") != "100" {
				_, _ = io.WriteString(w, `{"code":10206,"message":"分页操作错误"}`)
				return
			}
			_, _ = io.WriteString(w, `{"code":0,"message":"ok","data":`+groups+`}`)
		default:
			http.NotFound(w, r)
		}
	}))
}

func secretFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("app-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunPreviewFetchesDirectoryWithoutWriting(t *testing.T) {
	server := northboundStub(t, `[{"id":208,"name":"访客"},{"id":209,"name":"教职工"}]`)
	defer server.Close()
	var out bytes.Buffer
	if err := run(server.URL, "app", secretFile(t), "ncu-srun4k", "", false, true, 20*time.Second, &out); err != nil {
		t.Fatalf("preview failed: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "2 groups, 2 named") {
		t.Fatalf("unexpected summary: %s", text)
	}
	if !strings.Contains(text, "208 = 访客") {
		t.Fatalf("preview did not print the names: %s", text)
	}
	if !strings.Contains(text, "preview only") {
		t.Fatalf("preview did not state that nothing was written: %s", text)
	}
}

func TestRunWritesDirectoryUnderItsOwnSource(t *testing.T) {
	server := northboundStub(t, `[{"id":208,"name":"访客"},{"id":212,"name":"学生宿舍辅导员","pid":"211","path":"/学生/学生宿舍辅导员"}]`)
	defer server.Close()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	observedAt := time.Date(2026, 10, 14, 6, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE srun4k_group_catalog SET active=false,updated_at=now() WHERE source=$1`)).
		WithArgs("ncu-srun4k").WillReturnResult(sqlmock.NewResult(0, 34))
	mock.ExpectExec(`INSERT INTO srun4k_group_catalog`).
		WithArgs("ncu-srun4k", "208", "访客", "", "", observedAt).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO srun4k_group_catalog`).
		WithArgs("ncu-srun4k", "212", "学生宿舍辅导员", "211", "/学生/学生宿舍辅导员", observedAt).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO audit_logs`).
		WithArgs(sqlmock.AnyArg(), "ncu-srun4k", "synced:2").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	written, err := replaceGroupCatalog(context.Background(), db, "ncu-srun4k", []srunapi.Group{
		{ID: "208", Name: "访客"},
		{ID: "212", Name: "学生宿舍辅导员", ParentID: "211", Path: "/学生/学生宿舍辅导员"},
		{ID: "213", Name: "   "},
	}, observedAt)
	if err != nil {
		t.Fatalf("replace failed: %v", err)
	}
	if written != 2 {
		t.Fatalf("wrote %d groups, want 2 (the unnamed entry must be skipped)", written)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// A directory without names must not replace real names with numbers.
func TestReplaceGroupCatalogSkipsUnnamedEntries(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec(`UPDATE srun4k_group_catalog`).WithArgs("ncu-srun4k").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`INSERT INTO audit_logs`).WithArgs(sqlmock.AnyArg(), "ncu-srun4k", "synced:0").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	written, err := replaceGroupCatalog(context.Background(), db, "ncu-srun4k", []srunapi.Group{{ID: "208"}}, time.Now().UTC())
	if err != nil || written != 0 {
		t.Fatalf("written=%d err=%v", written, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRunRequiresSourceAndSecret(t *testing.T) {
	var out bytes.Buffer
	if err := run("https://example.invalid", "app", secretFile(t), "", "", false, true, time.Second, &out); err == nil {
		t.Fatal("empty source accepted")
	}
	if err := run("https://example.invalid", "app", "", "ncu-srun4k", "", false, true, time.Second, &out); err == nil {
		t.Fatal("missing secret file accepted")
	}
}
