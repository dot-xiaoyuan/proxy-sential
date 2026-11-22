package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestDefenseReportUsesBoundedDecisionBuckets(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Minute)
	mock.ExpectQuery(`SELECT date_bin.*trigger_type='shared_access'.*evaluated_at >= \$1 AND evaluated_at < \$2 GROUP BY 1`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "1 minute").
		WillReturnRows(sqlmock.NewRows([]string{"from", "matched", "insufficient", "expired"}).AddRow(at, 0, 8, 3))

	server := &Server{productPolicies: &productPolicyState{db: db}}
	w := httptest.NewRecorder()
	server.handleSharedDecisionTrend(w, httptest.NewRequest("GET", "/policy-decisions/shared-trend?window=15m", nil))
	var result sharedDecisionTrend
	if err := json.Unmarshal(w.Body.Bytes(), &result); w.Code != http.StatusOK || err != nil {
		t.Fatalf("bad response: %d %s", w.Code, w.Body.String())
	}
	if result.BucketMinutes != 1 || len(result.Buckets) != 15 || result.To.Sub(result.From) != 15*time.Minute {
		t.Fatalf("unexpected time window: %+v", result)
	}
	for i, bucket := range result.Buckets {
		if !bucket.From.Equal(result.From.Add(time.Duration(i) * time.Minute)) {
			t.Fatalf("unexpected bucket %d: %+v", i, bucket)
		}
		if bucket.From.Equal(at) {
			if bucket.Matched != 0 || bucket.Insufficient != 8 || bucket.Expired != 3 {
				t.Fatalf("unexpected results: %+v", bucket)
			}
		} else if bucket.Matched != 0 || bucket.Insufficient != 0 || bucket.Expired != 0 {
			t.Fatalf("empty interval returned decisions: %+v", bucket)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDefenseReportRejectsLongWindowAndRequiresReadPermission(t *testing.T) {
	w := httptest.NewRecorder()
	(&Server{}).handleSharedDecisionTrend(w, httptest.NewRequest("GET", "/policy-decisions/shared-trend?window=30d", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unbounded window returned %d", w.Code)
	}
	if got := requiredPermission("GET", "/policy-decisions/shared-trend"); got != "policies:read" {
		t.Fatalf("shared trend permission: %q", got)
	}
	if got := requiredPermission("GET", "/router-observations/summary"); got != "identity:read" {
		t.Fatalf("router statistics permission: %q", got)
	}
	if got := requiredPermission("GET", "/shared-access/observations/summary"); got != "cases:read" {
		t.Fatalf("shared observation statistics permission: %q", got)
	}
}
