package srunapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOnlineEquipmentReadOnlyContract(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		fail       bool
	}{
		{"190 field alias", `[{"user_name":"yuantong","rad_online_id":"212","user_ip":"192.168.0.93","add_time":"1750000000"}]`, false},
		{"conflicting aliases", `[{"user_name":"yuantong","rad_online_id":"212","ip":"192.168.0.94","user_ip":"192.168.0.93","add_time":"1750000000"}]`, true},
		{"actual fields", `[{"user_name":"yuantong","rad_online_id":17,"ip":"192.168.0.93","add_time":"1750000000"}]`, false},
		{"success envelope containing error number", `10004`, true},
		{"empty is not absence proof", `[]`, false},
		{"nested unknown paging contract", `{"rows":[],"total":0}`, true},
		{"missing generation", `[{"user_name":"yuantong","rad_online_id":"17","ip":"192.168.0.93"}]`, true},
		{"wrong account", `[{"user_name":"other","rad_online_id":"17","ip":"192.168.0.93","add_time":"1750000000"}]`, true},
		{"duplicate raw identity", `[{"user_name":"yuantong","rad_online_id":"17","ip":"192.168.0.93","add_time":"1750000000"},{"user_name":"yuantong","rad_online_id":"17","ip":"192.168.0.94","add_time":"1750000000"}]`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v2/auth/get-access-token" {
					w.Write([]byte(`{"code":0,"data":{"access_token":"test","lifetime":60}}`))
					return
				}
				if r.URL.Path != "/api/v2/base/online-equipment" || r.Method != "POST" {
					t.Error("unexpected operation")
				}
				r.ParseForm()
				if r.Form.Get("user_name") != "yuantong" {
					t.Error("account filter missing")
				}
				w.Write([]byte(`{"code":0,"data":` + tc.data + `}`))
			}))
			defer srv.Close()
			c, _ := New(srv.URL, "test", "test", srv.Client())
			result, err := c.OnlineEquipment(context.Background(), "yuantong")
			if (err != nil) != tc.fail {
				t.Fatalf("error=%v, fail=%v", err, tc.fail)
			}
			if err == nil && (result.Complete || result.AbsenceVerified || result.Blocker == "") {
				t.Fatal("legacy query must not claim authoritative completeness")
			}
		})
	}
}
