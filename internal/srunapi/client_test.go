package srunapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
