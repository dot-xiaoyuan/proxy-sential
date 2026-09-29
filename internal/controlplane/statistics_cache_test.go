package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStatisticsCacheCoalescesColdReadersAndIsolatesScopes(t *testing.T) {
	c := newStatisticsCache()
	var calls atomic.Int32
	loader := func(w http.ResponseWriter, r *http.Request, path string) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		writeJSON(w, 200, map[string]any{"count": 1})
	}
	request := func(role, query string) *http.Request {
		r := httptest.NewRequest("GET", "/api/v1/overview?"+query, nil)
		return r.WithContext(context.WithValue(r.Context(), sessionContextKey{}, Session{Role: role, Permissions: []string{role + ":read"}}))
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			c.serve(w, request("viewer", "campus_id=a"), "/overview", loader)
			if w.Code != 200 {
				t.Errorf("cold read: %d", w.Code)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("20 readers repeated expensive work %d times", calls.Load())
	}
	for _, v := range []struct{ role, query string }{{"admin", "campus_id=a"}, {"viewer", "campus_id=b"}} {
		c.serve(httptest.NewRecorder(), request(v.role, v.query), "/overview", loader)
	}
	if calls.Load() != 3 {
		t.Fatal("permissions/network scope not isolated")
	}
}
func TestStatisticsCacheServesLastSuccessfulSnapshotAfterFailure(t *testing.T) {
	c := newStatisticsCache()
	r := httptest.NewRequest("GET", "/api/v1/overview", nil)
	good := func(w http.ResponseWriter, r *http.Request, path string) {
		writeJSON(w, 200, map[string]any{"count": 1})
	}
	c.serve(httptest.NewRecorder(), r, "/overview", good)
	key := statisticsKey(r, "/overview")
	c.mu.Lock()
	c.entries[key].value.asOf = time.Now().Add(-61 * time.Second)
	c.mu.Unlock()
	w := httptest.NewRecorder()
	c.serve(w, r, "/overview", func(w http.ResponseWriter, r *http.Request, path string) {
		writeError(w, 503, "db_failed", "unavailable")
	})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"delayed"`) {
		t.Fatalf("failed refresh did not preserve delayed snapshot: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	c.serve(w, r, "/overview", func(w http.ResponseWriter, r *http.Request, path string) {
		writeJSON(w, 200, map[string]any{"as_of": time.Now().Add(-61 * time.Second).Format(time.RFC3339Nano)})
	})
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"delayed"`) {
		t.Fatalf("stale snapshot was not identified: %d %s", w.Code, w.Body.String())
	}
}

func TestStatisticsCacheIsolatesUsersWithIdenticalPermissions(t *testing.T) {
	c := newStatisticsCache()
	var calls int
	for _, id := range []string{"alice", "bob", "alice"} {
		r := httptest.NewRequest("GET", "/api/v1/overview?campus_id=a", nil)
		r = r.WithContext(context.WithValue(r.Context(), sessionContextKey{}, Session{User: User{ID: id}, Role: "viewer", Permissions: []string{"overview:read"}}))
		w := httptest.NewRecorder()
		c.serve(w, r, "/overview", func(w http.ResponseWriter, r *http.Request, _ string) {
			calls++
			writeJSON(w, 200, map[string]any{"actor": sessionFromContext(r.Context()).User.ID})
		})
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"actor":"`+id+`"`) {
			t.Fatalf("user %s received another actor's response: %s", id, w.Body.String())
		}
	}
	if calls != 2 {
		t.Fatalf("expected one fill per user, got %d", calls)
	}
}

func TestStatisticsCacheFirstBrowserCancellationDoesNotAbortSharedFill(t *testing.T) {
	c := newStatisticsCache()
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest("GET", "/api/v1/overview", nil).WithContext(ctx)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	loader := func(w http.ResponseWriter, r *http.Request, _ string) {
		calls.Add(1)
		close(entered)
		<-release
		if err := r.Context().Err(); err != nil {
			writeError(w, 503, "cancelled", err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"count": 1})
	}
	first, second := httptest.NewRecorder(), httptest.NewRecorder()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); c.serve(first, r, "/overview", loader) }()
	<-entered
	cancel()
	go func() {
		defer wg.Done()
		c.serve(second, httptest.NewRequest("GET", "/api/v1/overview", nil), "/overview", loader)
	}()
	close(release)
	wg.Wait()
	if first.Code != 200 || second.Code != 200 || calls.Load() != 1 {
		t.Fatalf("shared fill was aborted or repeated: first=%d second=%d calls=%d", first.Code, second.Code, calls.Load())
	}
}

func TestStatisticsCacheCoalescesFailureWithoutCallingItFreshStatistics(t *testing.T) {
	c := newStatisticsCache()
	var calls atomic.Int32
	loader := func(w http.ResponseWriter, r *http.Request, _ string) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		writeError(w, 503, "statistics_refresh_failed", "source unavailable")
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			c.serve(w, httptest.NewRequest("GET", "/api/v1/overview", nil), "/overview", loader)
			if w.Code != 503 || w.Header().Get("X-Statistics-As-Of") != "" {
				t.Errorf("failure masqueraded as fresh statistics: code=%d headers=%v", w.Code, w.Header())
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("waiting readers serialized repeated failed refreshes: %d", calls.Load())
	}
}
