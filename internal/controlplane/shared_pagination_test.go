package controlplane

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"proxy-sentinel/internal/pagination"
	"proxy-sentinel/internal/policy"
)

func TestPolicyDecisionNumberedPositionUsesOnlyBoundaryKeysAndSnapshot(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	s := &Server{productPolicies: &productPolicyState{db: db}}
	stamp := time.Now().UTC().Add(-time.Minute)
	mock.ExpectQuery(`SELECT evaluated_at,decision_id FROM policy_decision_records WHERE .*trigger_type=.*result=.*ORDER BY evaluated_at DESC,decision_id DESC LIMIT 2 OFFSET`).WillReturnRows(sqlmock.NewRows([]string{"at", "id"}).AddRow(stamp, "boundary").AddRow(stamp, "target"))
	w := httptest.NewRecorder()
	s.queryPolicyDecisionPosition(w, httptest.NewRequest("GET", "/policy-decisions/position?trigger=shared_access&result=matched&page=3&limit=2&snapshot="+url.QueryEscape(stamp.Format(time.RFC3339Nano)), nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var p pagination.Position
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	var c policyDecisionCursor
	raw, _ := base64.RawURLEncoding.DecodeString(p.Cursor)
	_ = json.Unmarshal(raw, &c)
	if p.Page != 3 || p.Limit != 2 || c.ID != "boundary" || !c.Snapshot.Equal(stamp) {
		t.Fatal(w.Body.String())
	}
	mock.ExpectQuery(`SELECT evaluated_at,decision_id.*LIMIT 2 OFFSET`).WillReturnRows(sqlmock.NewRows([]string{"at", "id"}).AddRow(stamp, "last"))
	w = httptest.NewRecorder()
	s.queryPolicyDecisionPosition(w, httptest.NewRequest("GET", "/policy-decisions/position?page=2&limit=2", nil))
	if w.Code != 400 {
		t.Fatal("exact-full last page yielded nonexistent next page", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyDecisionMetadataCountsSameFiltersWithoutCursor(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	s := &Server{productPolicies: &productPolicyState{db: db}}
	mock.ExpectQuery(`SELECT count\(\*\) FROM policy_decision_records WHERE .*trigger_type=.*result=.*evaluated_at >= .*evaluated_at <=`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(7))
	w := httptest.NewRecorder()
	s.queryPolicyDecisionMetadata(w, httptest.NewRequest("GET", "/policy-decisions/metadata?trigger=shared_access&result=matched", nil))
	var meta pagination.Metadata
	_ = json.Unmarshal(w.Body.Bytes(), &meta)
	if w.Code != 200 || meta.Total != 7 || meta.AsOf.IsZero() {
		t.Fatal(w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReviewPositionMetadataPreservesVersionAndRejectsEmptyTarget(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	s := &Server{operations: &operationsState{db: db}}
	call := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", path, nil)
		s.handleSharedReviews(w, r, strings.Split(path, "?")[0])
		return w
	}
	mock.ExpectQuery(`SELECT EXISTS`).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery(`SELECT count\(\*\) FROM shared_access_review_evidence WHERE review_id=\$1`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(4))
	w := call("/shared-access/reviews/r/evidence/metadata")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"total":4`) {
		t.Fatal(w.Code, w.Body.String())
	}
	mock.ExpectQuery(`SELECT EXISTS`).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery(`SELECT version FROM shared_access_review_evidence WHERE review_id=\$1.*ORDER BY version DESC LIMIT 2 OFFSET`).WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(3).AddRow(2))
	w = call("/shared-access/reviews/r/evidence/position?page=2&limit=2")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"cursor":"3"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	mock.ExpectQuery(`SELECT EXISTS`).WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	mock.ExpectQuery(`SELECT version.*LIMIT 2 OFFSET`).WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(1))
	w = call("/shared-access/reviews/r/evidence/position?page=3&limit=2")
	if w.Code != 400 {
		t.Fatal(w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSharedPaginationRejectsInvalidBoundsAndPolicySnapshotMismatch(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	s := &Server{productPolicies: &productPolicyState{db: db}, operations: &operationsState{db: db}}
	for _, path := range []string{"/policy-decisions/position?page=0", "/policy-decisions/position?page=2&limit=201", "/policy-decisions/metadata?snapshot=invalid"} {
		w := httptest.NewRecorder()
		s.queryPolicyDecisionPosition(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 400 {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/shared-access/reviews/position?page=0", "/shared-access/reviews/position?limit=101", "/shared-access/reviews/metadata?snapshot=invalid"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", path, nil)
		s.handleSharedReviews(w, r, r.URL.Path)
		if w.Code != 400 {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	stamp := time.Now().UTC()
	raw, _ := json.Marshal(policyDecisionCursor{At: stamp, ID: "test", Snapshot: stamp, Key: policy.StableID("", "", "", "", "", "", "", "")})
	w := httptest.NewRecorder()
	s.queryPolicyDecisions(w, httptest.NewRequest("GET", "/policy-decisions?cursor="+base64.RawURLEncoding.EncodeToString(raw)+"&snapshot="+url.QueryEscape(stamp.Add(-time.Second).Format(time.RFC3339Nano)), nil))
	if w.Code != 400 {
		t.Fatal("cursor snapshot changed", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
