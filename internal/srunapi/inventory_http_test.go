package srunapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestInventoryHTTPRejectsPartialStaleAndWrongOwnership(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, name := range []string{"valid", "empty", "partial", "wrong_count", "scope", "stale", "future", "no_native_id", "no_login", "duplicate", "unauthorized", "total_only", "trailing", "redirect"} {
		t.Run(name, func(t *testing.T) {
			count := 1
			doc := InventoryDocument{SchemaVersion: "online-inventory/v1", InstanceID: "source-1", ObservedAt: now, CampusID: "lab", AccessDomain: "nas", Complete: true, ExpectedCount: &count, Rows: []map[string]string{{"rad_online_id": "42", "session_id": "session-42", "user_name": "test", "ip": "192.0.2.1", "add_time": strconv.FormatInt(now.Add(-time.Minute).Unix(), 10)}}}
			switch name {
			case "empty":
				count = 0
				doc.Rows = []map[string]string{}
			case "partial":
				doc.Complete = false
			case "wrong_count":
				count = 2
			case "scope":
				doc.CampusID = "other"
			case "stale":
				doc.ObservedAt = now.Add(-6 * time.Second)
			case "future":
				doc.ObservedAt = now.Add(time.Second)
			case "no_native_id":
				delete(doc.Rows[0], "rad_online_id")
			case "no_login":
				delete(doc.Rows[0], "add_time")
			case "duplicate":
				doc.Rows = append(doc.Rows, doc.Rows[0])
				count = 2
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer private-token" {
					t.Error("invalid read-only authentication")
				}
				switch name {
				case "unauthorized":
					w.WriteHeader(401)
					return
				case "redirect":
					http.Redirect(w, r, "/another", 302)
					return
				case "total_only":
					w.Write([]byte(`{"online_total":1}`))
					return
				}
				json.NewEncoder(w).Encode(doc)
				if name == "trailing" {
					w.Write([]byte(`{}`))
				}
			}))
			defer server.Close()
			reader, err := NewInventoryHTTP(server.URL, "private-token", "lab", "nas", 10, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			reader.Now = func() time.Time { return now }
			in, err := reader.Read(context.Background())
			if name == "valid" || name == "empty" {
				if err != nil || len(in.Rows) != count {
					t.Fatalf("valid read: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("invalid response masqueraded as successful inventory")
				}
				if strings.Contains(err.Error(), "private-token") {
					t.Fatal("credential leaked")
				}
			}
		})
	}
}
