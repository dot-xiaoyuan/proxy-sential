package legacy4k

import (
	"context"
	"encoding/json"
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

func TestDecodeRecordUsesSnapshotSessionIdentityAndDropsSensitiveFields(t *testing.T) {
	raw := `{"action":1,"rad_online_id":42,"user_name":"student","ip":"10.1.2.3","ip6_1":"2001:db8::1","user_mac":"AA-BB-CC-DD-EE-FF","add_time":1785232800,"device_id":"endpoint-1","mobile_phone":"13800000000","mobile_password":"secret","balance":999}`
	record, err := DecodeRecordForInstance(raw, "redis-run-id", time.Unix(1785232900, 0))
	if err != nil {
		t.Fatal(err)
	}
	wantSession := OnlineSessionID("redis-run-id", "42", "1785232800")
	if record["session_id"] != wantSession || record["source_session_id"] != "42" || record["ip"] != "10.1.2.3" {
		t.Fatalf("unexpected identity record: %#v", record)
	}
	encoded, _ := json.Marshal(record)
	for _, secret := range []string{"13800000000", "secret", "balance", "mobile_phone", "mobile_password"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("sensitive field leaked: %s", secret)
		}
	}
}

func TestDecodeRecordIPv6FallbackAndGenerationReuse(t *testing.T) {
	login, err := DecodeRecordForInstance(`{"action":1,"session_id":"session-a","user_name":"student","ip6_3":"2001:db8::8","add_time":1785232800}`, "redis-run-id", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	logout, err := DecodeRecordForInstance(`{"action":2,"session_id":"session-a","user_name":"student","ip6_3":"2001:db8::8","add_time":1785232800,"drop_time":1785232900}`, "redis-run-id", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if login["ip"] != "2001:db8::8" || login["session_id"] != logout["session_id"] {
		t.Fatalf("login/logout generation mismatch: %#v %#v", login, logout)
	}
	newLogin, err := DecodeRecordForInstance(`{"action":1,"session_id":"session-a","user_name":"student","ip":"10.0.0.9","add_time":1785233000}`, "redis-run-id", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if newLogin["session_id"] == login["session_id"] {
		t.Fatal("reused online id overwrote a newer login generation")
	}
}

func TestSenderAddsExplicitAuthorityScopeWithoutMutatingInput(t *testing.T) {
	record := map[string]string{"ip": "10.0.0.8"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Source  string              `json:"source"`
			Sensor  string              `json:"sensor_id"`
			Records []map[string]string `json:"records"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Source != "ncu-srun4k" || body.Sensor != "ncu-auth-redis" || body.Records[0]["campus_id"] != "ncu" || body.Records[0]["access_domain"] != "campus-auth" {
			t.Fatalf("unexpected scope: %#v", body)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	err := (Sender{Endpoint: server.URL, Token: "token", SensorID: "ncu-auth-redis", Source: "ncu-srun4k", CampusID: "ncu", AccessDomain: "campus-auth"}).Send(context.Background(), []map[string]string{record}, "batch-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, mutated := record["campus_id"]; mutated {
		t.Fatal("sender mutated caller record")
	}
}
