package srunapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGroupsUsesSupportedPaginationAndCollectsAllPages(t *testing.T) {
	pages := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/auth/get-access-token":
			io.WriteString(w, `{"code":0,"data":{"access_token":"token","lifetime":60}}`)
		case "/api/v2/groups":
			if r.Method != http.MethodGet || r.URL.Query().Get("access_token") != "token" || r.URL.Query().Get("per-page") != "100" {
				io.WriteString(w, `{"code":10206,"message":"分页参数错误"}`)
				return
			}
			pages++
			items := []map[string]any{}
			if r.URL.Query().Get("page") == "1" {
				for i := 1; i <= 100; i++ {
					items = append(items, map[string]any{"id": i, "name": fmt.Sprintf("用户组%d", i), "pid": 0})
				}
			} else if r.URL.Query().Get("page") == "2" {
				items = append(items, map[string]any{"id": 101, "name": "最后用户组", "pid": 1})
			} else {
				t.Errorf("unexpected page %s", r.URL.Query().Get("page"))
			}
			json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": items})
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, "app", "secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	groups, err := client.Groups(context.Background())
	if err != nil || len(groups) != 101 || pages != 2 {
		t.Fatalf("incomplete directory: groups=%d pages=%d error=%v", len(groups), pages, err)
	}
	if groups[100].ID != "101" || groups[100].Name != "最后用户组" || groups[100].ParentID != "1" {
		t.Fatalf("directory fields changed: %+v", groups[100])
	}
}

func TestNativeDropResponseIsOnlyAcknowledgement(t *testing.T) {
	for _, body := range []string{`{"code":0,"message":"ok","version":"v2"}`, `{"code":10503}`, `{}`, `{"code":null}`, `{"code":0} {}`, `<html>login</html>`} {
		t.Run(body, func(t *testing.T) {
			calls := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "POST" {
					t.Error("native API requires POST")
				}
				_ = r.ParseForm()
				switch r.URL.Path {
				case "/api/v2/auth/get-access-token":
					if r.Form.Get("appId") != "app" || r.Form.Get("appSecret") != "secret" {
						t.Error("bad native auth mapping")
					}
					io.WriteString(w, `{"code":0,"data":{"access_token":"token","lifetime":60}}`)
				case "/api/v2/base/online-drop":
					if r.Form.Get("rad_online_id") != "native-42" || r.Form.Get("user_name") != "test-user" || r.Form.Get("drop_type") != "radius" || r.Form.Get("access_token") != "token" {
						t.Error("bad native drop mapping")
					}
					io.WriteString(w, body)
				default:
					t.Error("unexpected path")
				}
			}))
			defer s.Close()
			c, err := New(s.URL, "app", "secret", s.Client())
			if err != nil {
				t.Fatal(err)
			}
			err = c.RequestDisconnect(context.Background(), "test-user", "native-42", "radius")
			if (err == nil) != strings.Contains(body, `"message":"ok"`) {
				t.Fatalf("unexpected acknowledgement: %v", err)
			}
			if calls != 2 {
				t.Fatalf("unexpected retry: %d", calls)
			}
		})
	}
}

func TestNoCredentialsFollowRedirect(t *testing.T) {
	calls := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer target.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer s.Close()
	c, _ := New(s.URL, "app", "secret", s.Client())
	if err := c.RequestDisconnect(context.Background(), "u", "42", "radius"); err == nil {
		t.Fatal("accepted redirect")
	}
	if calls != 0 {
		t.Fatal("credentials followed redirect")
	}
}

func TestRejectUnscopedDisconnectBeforeNetwork(t *testing.T) {
	c, _ := New("http://127.0.0.1:1", "app", "secret", nil)
	for _, args := range [][3]string{{"", "42", "radius"}, {"u", "", "radius"}, {"u", "42", "ip"}, {"u", "42", " radius"}} {
		if err := c.RequestDisconnect(context.Background(), args[0], args[1], args[2]); err == nil || strings.Contains(err.Error(), "transport") {
			t.Fatalf("invalid target reached transport: %v", err)
		}
	}
}

func TestAuthenticationFailureNeverSendsAction(t *testing.T) {
	for _, body := range []string{`{"code":10902}`, `{"code":0}`, `{"code":0,"data":{"access_token":"token","lifetime":0}}`} {
		t.Run(body, func(t *testing.T) {
			drops := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v2/auth/get-access-token" {
					drops++
				}
				io.WriteString(w, body)
			}))
			defer s.Close()
			c, _ := New(s.URL, "app", "secret", s.Client())
			if err := c.RequestDisconnect(context.Background(), "u", "42", "radius"); err == nil {
				t.Fatal("accepted invalid authorization")
			}
			if drops != 0 {
				t.Fatal("action sent after invalid authorization")
			}
		})
	}
}

func TestSafeDisableUsesBoundedAccountContractAfterFinalGuard(t *testing.T) {
	guarded := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.URL.Path {
		case "/api/v2/auth/get-access-token":
			_, _ = io.WriteString(w, `{"code":0,"data":{"access_token":"token","lifetime":60}}`)
		case "/api/v2/safe/disable":
			if !guarded || r.Form.Get("type") != "user_name@proxy" || r.Form.Get("value") != "student" || r.Form.Get("disable_time") != "600" {
				t.Fatalf("unexpected safe-disable request: guarded=%t form=%v", guarded, r.Form)
			}
			_, _ = io.WriteString(w, `{"code":0,"data":{}}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, "app", "secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	err = client.RequestSafeDisableChecked(context.Background(), "student", 600, func(context.Context) error {
		guarded = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

type brokenBody struct{ sent bool }

func (b *brokenBody) Read(p []byte) (int, error) {
	if b.sent {
		return 0, io.ErrUnexpectedEOF
	}
	b.sent = true
	return copy(p, `{"code":0}`), nil
}
func (*brokenBody) Close() error { return nil }

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTruncatedTransportCannotAcknowledge(t *testing.T) {
	hc := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: &brokenBody{}, Header: make(http.Header)}, nil
	})}
	c, _ := New("http://localhost", "app", "secret", hc)
	if _, err := c.post(context.Background(), "/test", nil); err == nil {
		t.Fatal("valid JSON prefix hid failed response body")
	}
}

func TestDatabaseCredentialOverrideRotationAndFailure(t *testing.T) {
	var requests int
	secret := "rotated-one"
	failed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		r.ParseForm()
		switch r.URL.Path {
		case "/api/v2/auth/get-access-token":
			if r.Form.Get("appId") != "db-app" || r.Form.Get("appSecret") != secret {
				t.Error("database credentials not used")
			}
			w.Write([]byte(`{"code":0,"data":{"access_token":"token","lifetime":60}}`))
		case "/api/v2/base/get-online-total":
			w.Write([]byte(`{"code":0,"data":{"online_total":1}}`))
		default:
			t.Error("unexpected mutation")
		}
	}))
	defer server.Close()
	client, err := New(server.URL, "static-app", "static-secret", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	client = client.WithCredentialOverride(func(context.Context) (string, string, bool, error) {
		if failed {
			return "", "", true, fmt.Errorf("private-database-password")
		}
		return "db-app", secret, true, nil
	})
	for _, value := range []string{"rotated-one", "rotated-two"} {
		secret = value
		if _, err = client.OnlineTotal(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	before := requests
	failed = true
	if _, err = client.OnlineTotal(context.Background()); err == nil || strings.Contains(err.Error(), "private-database-password") {
		t.Fatal("failure not sanitized")
	}
	if requests != before {
		t.Fatal("database failure fell back to static credentials or sent HTTP")
	}
}
