package srunapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEquipmentCapabilitiesNeverInventCompleteness(t *testing.T) {
	for _, data := range []string{`10004`, `[]`, `[{"user_name":"private-account","user_ip":"192.0.2.1"}]`, `{"complete":true,"rows":[],"total":0}`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v2/auth/get-access-token" {
				w.Write([]byte(`{"code":0,"data":{"access_token":"test","lifetime":60}}`))
				return
			}
			r.ParseForm()
			if _, exists := r.Form["user_name"]; exists {
				t.Error("unfiltered probe added an empty account filter")
			}
			w.Write([]byte(`{"code":0,"data":` + data + `}`))
		}))
		client, _ := New(server.URL, "test", "test", server.Client())
		result, err := client.InspectEquipmentCapabilities(context.Background())
		server.Close()
		if err != nil || result.Complete || result.Blocker == "" {
			t.Fatalf("invented full inventory: %+v %v", result, err)
		}
	}
}

func TestOnlineDataCapabilityUsesReadOnlyGET(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/auth/get-access-token" {
			w.Write([]byte(`{"code":0,"data":{"access_token":"test","lifetime":60}}`))
			return
		}
		if r.Method != http.MethodGet || r.URL.Query().Get("access_token") != "test" {
			t.Error("wrong online-data method or token")
			w.WriteHeader(405)
			return
		}
		w.Write([]byte(`{"code":0,"data":[{"user_name":"private","group_id":"1","ip":"192.0.2.1"}]}`))
	}))
	defer server.Close()
	c, _ := New(server.URL, "test", "test", server.Client())
	result, err := c.InspectOnlineDataCapabilities(context.Background())
	if err != nil || result.RecordCount != 1 || result.Complete || len(result.Fields) != 3 {
		t.Fatal(result, err)
	}
}
