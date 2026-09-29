package controlplane

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNativeConfigPrivateExplicitAndNoStartupRequests(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer srv.Close()
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	valid := nativeConfigEntry{AllowLegacyRedisReplay: true, ConnectorID: "c", CampusID: "lab", AccessDomain: "nas", Endpoint: srv.URL, AppID: "app", AppSecret: "test-secret", CertificateFile: cert, RedisURL: "redis://:test-password@127.0.0.1:1/0", OnlineList: "list:rad_online", ReadyKey: "ready", MaxRecords: 100, DropType: "radius"}
	for _, name := range []string{"valid", "production_redis", "replay_not_explicit", "duplicate", "portal", "scope_missing", "public_file", "unknown_field", "trailing", "bad_redis", "valid_api", "api_missing_token", "api_with_redis", "api_http", "valid_4k", "4k_static_mix"} {
		t.Run(name, func(t *testing.T) {
			entry := valid
			if name == "production_redis" {
				entry.Endpoint = "https://192.168.0.190:8001"
			}
			if name == "replay_not_explicit" {
				entry.AllowLegacyRedisReplay = false
			}
			if name == "valid_4k" || name == "4k_static_mix" {
				entry.CredentialSource = "4k_database"
				entry.AppID, entry.AppSecret = "", ""
				if name == "4k_static_mix" {
					entry.AppID = "not-permitted"
				}
			}
			if strings.HasPrefix(name, "api_") || name == "valid_api" {
				entry.InventoryURL, entry.InventoryToken = srv.URL+"/inventory", "test-inventory-secret"
				entry.RedisURL, entry.OnlineList, entry.ReadyKey = "", "", ""
				switch name {
				case "api_missing_token":
					entry.InventoryToken = ""
				case "api_with_redis":
					entry.RedisURL = valid.RedisURL
				case "api_http":
					entry.InventoryURL = "http://127.0.0.1/inventory"
				}
			}
			if name == "portal" {
				entry.DropType = "portal"
			}
			if name == "scope_missing" {
				entry.AccessDomain = ""
			}
			if name == "bad_redis" {
				entry.RedisURL = "not-a-url:test-password"
			}
			entries := []nativeConfigEntry{entry}
			if name == "duplicate" {
				entries = append(entries, entry)
			}
			raw, _ := json.Marshal(entries)
			if name == "unknown_field" {
				raw = []byte(strings.Replace(string(raw), "\"connector_id\"", "\"unexpected\"", 1))
			}
			if name == "trailing" {
				raw = append(raw, []byte(" {}")...)
			}
			path := filepath.Join(t.TempDir(), "native.json")
			mode := os.FileMode(0600)
			if name == "public_file" {
				mode = 0644
			}
			if err := os.WriteFile(path, raw, mode); err != nil {
				t.Fatal(err)
			}
			got, closeFn, err := LoadNativeActions(path)
			defer closeFn()
			if name == "valid" || name == "valid_api" || name == "valid_4k" {
				if err != nil || len(got) != 1 {
					t.Fatalf("valid load: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("invalid configuration accepted")
				}
				if strings.Contains(err.Error(), "test-secret") || strings.Contains(err.Error(), "test-password") || strings.Contains(err.Error(), "test-inventory-secret") {
					t.Fatal("credentials leaked")
				}
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("configuration loading issued controller requests")
	}
	got, closeFn, err := LoadNativeActions("")
	defer closeFn()
	if err != nil || len(got) != 0 {
		t.Fatal("default not disabled")
	}
}
