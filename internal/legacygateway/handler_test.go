package legacygateway

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHandlerVerifiesSignatureTranslatesAndDeduplicates(t *testing.T) {
	calls := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"username":"student"`) || !strings.Contains(string(body), `"action":"kick"`) {
			t.Fatalf("unexpected payload %s", body)
		}
		_, _ = io.WriteString(w, `{"action_id":"remote-1","status":"completed"}`)
	}))
	defer target.Close()
	now := time.Now().UTC()
	handler, err := New(Options{Secret: "secret", TargetURL: target.URL, StatePath: filepath.Join(t.TempDir(), "state.json"), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"action_id":"a1","action":"kick","subject":{"account_id":"student","ip":"10.0.0.8"}}`)
	timestamp := now.Format(time.RFC3339Nano)
	for range 2 {
		request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		request.Header.Set("X-Proxy-Sentinel-Timestamp", timestamp)
		request.Header.Set("X-Proxy-Sentinel-Signature", signature("secret", timestamp, body))
		request.Header.Set("Idempotency-Key", "same")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != 200 {
			t.Fatalf("unexpected status %d: %s", recorder.Code, recorder.Body.String())
		}
	}
	if calls != 1 {
		t.Fatalf("expected one legacy call, got %d", calls)
	}
}

func TestGatewayDoesNotCacheUnconfirmedSuccess(t *testing.T) {
	calls := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		io.WriteString(w, `{"action_id":"remote","status":"pending"}`)
	}))
	defer target.Close()
	now := time.Now().UTC()
	h, err := New(Options{Secret: "test", TargetURL: target.URL, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"action_id":"a","action":"disconnect","subject":{"account_id":"test"}}`)
	timestamp := now.Format(time.RFC3339Nano)
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("POST", "/", bytes.NewReader(body))
		r.Header.Set("Idempotency-Key", "same")
		r.Header.Set("X-Proxy-Sentinel-Timestamp", timestamp)
		r.Header.Set("X-Proxy-Sentinel-Signature", signature("test", timestamp, body))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 502 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if calls != 2 || len(h.completed) != 0 {
		t.Fatal("accepted response cached as completion")
	}
}

func TestGatewayRequiresVerifiedCacheFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	for _, raw := range []string{`{"old-id":"remote"}`, `broken`, `{"version":1}`} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := New(Options{Secret: "s", TargetURL: "http://127.0.0.1", StatePath: path}); err == nil {
			t.Fatal("unverified cache accepted", raw)
		}
	}
}

func TestGatewayRejectsTruncatedCompletion(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "999")
		io.WriteString(w, `{"action_id":"remote","status":"completed"}`)
	}))
	defer target.Close()
	now := time.Now().UTC()
	h, err := New(Options{Secret: "test", TargetURL: target.URL, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"action_id":"a","action":"disconnect","subject":{"account_id":"test"}}`)
	timestamp := now.Format(time.RFC3339Nano)
	r := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	r.Header.Set("Idempotency-Key", "same")
	r.Header.Set("X-Proxy-Sentinel-Timestamp", timestamp)
	r.Header.Set("X-Proxy-Sentinel-Signature", signature("test", timestamp, body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 502 || len(h.completed) != 0 {
		t.Fatalf("truncated response committed: %d %+v", w.Code, h.completed)
	}
}
