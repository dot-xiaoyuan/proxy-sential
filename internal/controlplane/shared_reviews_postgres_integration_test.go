package controlplane

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxy-sentinel/internal/sharedaccess"
)

func TestSharedReviewPersistenceVersionsAndPagination(t *testing.T) {
	s, actor := taskIntegrationServer(t)
	account := "review-test-" + shortToken(12)
	result := sharedaccess.Result{ID: "window1", AccountID: account, CampusID: account, AccessDomain: "office", State: "basis_present", ConfigVersion: "config1", ObservedAt: time.Now().UTC()}
	window := sharedaccess.Window{ID: "window1"}
	t.Cleanup(func() {
		s.operations.db.Exec(`DELETE FROM audit_logs WHERE target IN (SELECT review_id FROM shared_access_reviews WHERE account_id=$1)`, account)
		s.operations.db.Exec(`DELETE FROM shared_access_review_conclusions WHERE review_id IN (SELECT review_id FROM shared_access_reviews WHERE account_id=$1)`, account)
		s.operations.db.Exec(`DELETE FROM shared_access_review_evidence WHERE review_id IN (SELECT review_id FROM shared_access_reviews WHERE account_id=$1)`, account)
		s.operations.db.Exec(`DELETE FROM shared_access_reviews WHERE account_id=$1`, account)
	})
	for i := 0; i < 2; i++ {
		if err := s.persistSharedReview(context.Background(), result, window, "generation1"); err != nil {
			t.Fatal(err)
		}
	}
	result.ID = "window2"
	window.ID = result.ID
	if err := s.persistSharedReview(context.Background(), result, window, "generation1"); err != nil {
		t.Fatal(err)
	}
	var id string
	var count, version int
	if s.operations.db.QueryRow(`SELECT review_id,latest_version FROM shared_access_reviews WHERE account_id=$1`, account).Scan(&id, &version) != nil || version != 2 {
		t.Fatal("refresh duplicated case or failed to append version")
	}
	s.operations.db.QueryRow(`SELECT count(*) FROM shared_access_reviews WHERE account_id=$1`, account).Scan(&count)
	if count != 1 {
		t.Fatal("duplicate case")
	}
	call := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/v1"+path, strings.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), sessionContextKey{}, actor))
		w := httptest.NewRecorder()
		s.handleSharedReviews(w, r, strings.TrimPrefix(r.URL.Path, "/api/v1"))
		return w
	}
	page := call("GET", "/shared-access/reviews/"+id+"/evidence?limit=1", "")
	if page.Code != 200 {
		t.Fatal(page.Body.String())
	}
	var response struct {
		Items []struct{ Version int }
		Next  string `json:"next_cursor"`
	}
	json.Unmarshal(page.Body.Bytes(), &response)
	if len(response.Items) != 1 || response.Items[0].Version != 2 || response.Next != "2" {
		t.Fatal("invalid history page", page.Body.String())
	}
	page = call("GET", "/shared-access/reviews/"+id+"/evidence?limit=1&cursor=2", "")
	json.Unmarshal(page.Body.Bytes(), &response)
	if page.Code != 200 || response.Items[0].Version != 1 {
		t.Fatal("history cursor failed")
	}
	if w := call("POST", "/shared-access/reviews/"+id+"/conclusion", `{"evidence_version":1,"conclusion":"shared","reason":"isolated replay"}`); w.Code != 409 {
		t.Fatal("stale confirmation accepted")
	}
	if w := call("POST", "/shared-access/reviews/"+id+"/conclusion", `{"evidence_version":2,"conclusion":"insufficient","reason":"coverage unknown"}`); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	// An older window is retained in history but must not become current evidence.
	result.ID = "late-old-window"
	result.ObservedAt = result.ObservedAt.Add(-time.Minute)
	if err := s.persistSharedReview(context.Background(), result, window, "generation1"); err != nil {
		t.Fatal(err)
	}
	var latestRaw []byte
	if err := s.operations.db.QueryRow(`SELECT latest_version,latest_result FROM shared_access_reviews WHERE review_id=$1`, id).Scan(&version, &latestRaw); err != nil {
		t.Fatal(err)
	}
	var current sharedaccess.Result
	if json.Unmarshal(latestRaw, &current) != nil || current.ID != "window2" || version != 2 {
		t.Fatal("late evidence replaced current summary", string(latestRaw), version)
	}
	result.ID = "window3"
	result.ObservedAt = result.ObservedAt.Add(2 * time.Minute)
	if err := s.persistSharedReview(context.Background(), result, window, "generation1"); err != nil {
		t.Fatal(err)
	}
	if err := s.operations.db.QueryRow(`SELECT latest_version FROM shared_access_reviews WHERE review_id=$1`, id).Scan(&version); err != nil || version != 4 {
		t.Fatal("history sequence reused after late evidence", err, version)
	}

	var operator string
	s.operations.db.QueryRow(`SELECT operator_id FROM shared_access_review_conclusions WHERE review_id=$1`, id).Scan(&operator)
	if operator != actor.User.ID {
		t.Fatal("review actor lost")
	}
	if w := call("GET", "/shared-access/reviews/"+id+"/executions", ""); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	// Cursor encoding preserves same-time ID ordering and rejects malformed input.
	encoded := encodeReviewCursor(time.Now().UTC(), id)
	if _, err := decodeReviewCursor(encoded); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeReviewCursor("broken"); err == nil {
		t.Fatal("malformed cursor accepted")
	}
}
