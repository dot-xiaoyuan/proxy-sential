package legacy4k

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDecodeRecordMapsLoginAndLogout(t *testing.T) {
	login, err := DecodeRecord(`{"action":1,"user_name":"20260001","ip":"10.0.0.8","user_mac":"AA-BB-CC-DD-EE-FF","session_id":"s-1","add_time":1785232800}`, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if login["action"] != "login" || login["account_id"] != "20260001" || login["session_id"] != "s-1" {
		t.Fatalf("unexpected login: %#v", login)
	}
	logout, err := DecodeRecord(`{"action":2,"user_name":"20260001","ip":"10.0.0.8","session_id":"s-1","drop_time":1785232900}`, time.Now())
	if err != nil || logout["action"] != "logout" {
		t.Fatalf("unexpected logout: %#v %v", logout, err)
	}
}

func TestSenderUsesExistingIdentityContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "Bearer token" || r.Header.Get("Idempotency-Key") != "batch-1" || !strings.Contains(string(body), `"source":"legacy-4k"`) {
			t.Fatalf("unexpected request")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	err := (Sender{Endpoint: server.URL, Token: "token", SensorID: "sensor-a"}).Send(context.Background(), []map[string]string{{"ip": "10.0.0.8"}}, "batch-1")
	if err != nil {
		t.Fatal(err)
	}
}
