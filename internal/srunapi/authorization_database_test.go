package srunapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestSelectApplicationCredentials(t *testing.T) {
	for _, name := range []string{"valid", "explicit", "none", "multiple", "query_failed", "incomplete", "interrupted"} {
		t.Run(name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			id := int64(0)
			if name == "explicit" {
				id = 7
			}
			query := mock.ExpectQuery("SELECT id,appId,appSecret,accessOrganization,expired_at FROM authorization WHERE status=0 AND ")
			if id > 0 {
				query.WithArgs(id)
			} else {
				query.WithArgs()
			}
			rows := sqlmock.NewRows([]string{"id", "appId", "appSecret", "accessOrganization", "expired_at"})
			if name != "none" {
				rows.AddRow(7, "application", "private-secret", "sentinel", 0)
			}
			switch name {
			case "multiple":
				rows.AddRow(8, "another", "other-secret", "other", 0)
			case "query_failed":
				query.WillReturnError(errors.New("dsn=private-password"))
			case "incomplete":
				rows = sqlmock.NewRows([]string{"id", "appId", "appSecret", "accessOrganization", "expired_at"}).AddRow(7, "application", "", "sentinel", 0)
			case "interrupted":
				rows.RowError(0, errors.New("private-password"))
			}
			if name != "query_failed" {
				query.WillReturnRows(rows)
			}
			got, err := selectApplicationCredentials(context.Background(), db, id)
			if name == "valid" || name == "explicit" {
				if err != nil || got.AppSecret != "private-secret" {
					t.Fatalf("valid credentials: %v", err)
				}
			} else if err == nil {
				t.Fatal("invalid authorization accepted")
			} else if strings.Contains(err.Error(), "private-") {
				t.Fatal("secret leaked")
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
