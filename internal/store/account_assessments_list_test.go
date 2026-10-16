package store

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestListAccountAssessmentsScansCurrentTag(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(sharedIdentityTestConverter{}))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	mock.ExpectQuery(`SELECT count\(DISTINCT a.account_id\)`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery(`SELECT a.account_id,max\(a.last_seen\)`).WithArgs(20, 0).WillReturnRows(sqlmock.NewRows([]string{"account_id", "last_seen"}).AddRow("test-account", now))
	mock.ExpectQuery(`SELECT a.account_id,a.tag_type.*a.last_seen FROM`).WillReturnRows(sqlmock.NewRows([]string{
		"account_id", "tag_type", "assessment_version", "state", "evidence_level", "source_type", "reason", "endpoint_ids", "evidence_ids", "rule_version", "raw_score", "first_seen", "last_seen", "valid_until", "review_state", "recorded_at",
	}).AddRow("test-account", "pc", "version-1", "current", "confirmed", "account_session", "PC 终端", []byte(`["endpoint-1"]`), []byte(`["evidence-1"]`), "rule-1", 1.0, now, now, now.Add(time.Hour), "pending", now))
	mock.ExpectQuery(`SELECT last_success_at,last_error FROM account_tag_projection_runtime`).WillReturnRows(sqlmock.NewRows([]string{"last_success_at", "last_error"}).AddRow(now, ""))
	page, err := (&PostgresStore{db: db}).ListAccountAssessments(context.Background(), AccountAssessmentQuery{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].AccountID != "test-account" || page.Items[0].EndpointCount != 1 {
		t.Fatalf("unexpected page: %+v", page)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
