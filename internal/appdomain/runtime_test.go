package appdomain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRuntimeSettingsAndPull(t *testing.T) {
	raw, err := ExampleBundle(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(raw) }))
	defer server.Close()
	dir := t.TempDir()
	s, err := OpenServiceWithDefault(dir, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if s.Status().Enabled {
		t.Fatal("must start disabled")
	}
	if err = s.Configure(RuntimeConfig{Enabled: true, UpdateURL: server.URL + "/bundle.tar.gz"}); err != nil {
		t.Fatal(err)
	}
	if err = s.Pull(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.Status().Library.RuleCount == 0 {
		t.Fatal("pull did not activate rules")
	}
	if err = s.Pull(context.Background()); err != nil {
		t.Fatalf("same version pull must be idempotent: %v", err)
	}
	reopened, err := OpenServiceWithDefault(dir, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.Status().Enabled || reopened.Status().Config.UpdateURL != server.URL+"/bundle.tar.gz" {
		t.Fatal("configuration lost on restart")
	}
	if err = s.Configure(RuntimeConfig{Enabled: false, UpdateURL: server.URL + "/bundle.tar.gz"}); err != nil {
		t.Fatal(err)
	}
	if more, err := s.Step(context.Background(), time.Now()); err != nil || more {
		t.Fatal("disabled module must not scan")
	}
}

func TestRuntimePullFailureKeepsLibrary(t *testing.T) {
	raw, _ := ExampleBundle(time.Now())
	s, _ := OpenServiceWithDefault(t.TempDir(), nil, false)
	if err := s.ChangeLibrary(raw, ""); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("bad bundle")) }))
	defer server.Close()
	if err := s.Configure(RuntimeConfig{UpdateURL: server.URL + "/bundle.tar.gz"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Pull(context.Background()); err == nil {
		t.Fatal("invalid bundle accepted")
	}
	if s.Status().Library.Version != "contract-fixture-v1" || s.Status().Config.LastPullError == "" {
		t.Fatal("lost previous library or diagnostics")
	}
	if err := s.Configure(RuntimeConfig{UpdateURL: "file:///etc/passwd"}); err == nil {
		t.Fatal("invalid scheme accepted")
	}
}

func TestDefaultServerAndVersionDiscovery(t *testing.T) {
	s, err := OpenServiceWithDefault(t.TempDir(), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if s.Status().Config.UpdateURL != DefaultUpdateURL {
		t.Fatal("missing default address")
	}
	raw, _ := ExampleBundle(time.Now())
	seen := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("authentication missing")
		}
		seen = append(seen, r.URL.Path)
		if r.URL.Path == "/api/features/application-domain/bundles/index" {
			sum := sha256.Sum256(raw)
			bundle, _ := Verify(raw)
			json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{"latest_version": bundle.Manifest.Version, "releases": []Release{{Version: bundle.Manifest.Version, CreatedAt: bundle.Manifest.CreatedAt, OrderingBasis: "created_at_fallback", SHA256: hex.EncodeToString(sum[:]), Size: len(raw), RuleCount: len(bundle.Rules), ApplicationCount: len(bundle.Catalog.Applications)}}}})
			return
		}
		if r.URL.Path != "/api/features/application-domain/bundles/contract-fixture-v1/download" {
			t.Error("wrong download path")
		}
		w.Write(raw)
	}))
	defer server.Close()
	if err = s.Configure(RuntimeConfig{UpdateURL: server.URL}); err != nil {
		t.Fatal(err)
	}
	if err = s.PullWithToken(context.Background(), "test-token"); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || s.Status().Library.Version != "contract-fixture-v1" {
		t.Fatal("discovery failed")
	}
}

func TestSavedDownloadCredentialBinding(t *testing.T) {
	s, err := OpenServiceWithDefault(t.TempDir(), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	token := "fld_" + strings.Repeat("a", 64)
	if err = s.SaveCredential(token); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(s.Status())
	if strings.Contains(string(raw), token) || !s.Status().Config.CredentialConfigured {
		t.Fatal("credential status leaks or missing")
	}
	reopened, err := OpenServiceWithDefault(s.dir, nil, false)
	if err != nil || reopened.savedCredential(DefaultUpdateURL) != token {
		t.Fatal("credential not restored")
	}
	if err = s.Configure(RuntimeConfig{UpdateURL: "http://different.example"}); err != nil {
		t.Fatal(err)
	}
	if s.savedCredential("http://different.example") != "" || s.Status().Config.CredentialConfigured {
		t.Fatal("credential forwarded to another origin")
	}
}

func TestIndexedPullRejectsMetadataMismatch(t *testing.T) {
	raw, err := ExampleBundle(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	for _, field := range []string{"digest", "size", "rules", "applications", "created_at", "unavailable_index"} {
		t.Run(field, func(t *testing.T) {
			s, err := OpenServiceWithDefault(t.TempDir(), nil, false)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.ChangeLibrary(raw, ""); err != nil {
				t.Fatal(err)
			}
			release := Release{Version: bundle.Manifest.Version, CreatedAt: bundle.Manifest.CreatedAt, OrderingBasis: "created_at_fallback", SHA256: hex.EncodeToString(sum[:]), Size: len(raw), RuleCount: len(bundle.Rules), ApplicationCount: len(bundle.Catalog.Applications)}
			switch field {
			case "digest":
				release.SHA256 = strings.Repeat("0", 64)
			case "size":
				release.Size++
			case "rules":
				release.RuleCount++
			case "applications":
				release.ApplicationCount++
			case "created_at":
				release.CreatedAt = "2020-01-01T00:00:00Z"
			}
			downloads := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/features/application-domain/bundles/index" {
					if field == "unavailable_index" {
						http.NotFound(w, r)
						return
					}
					json.NewEncoder(w).Encode(map[string]any{"success": true, "data": map[string]any{"latest_version": release.Version, "releases": []Release{release}}})
					return
				}
				if !strings.HasSuffix(r.URL.Path, "/download") {
					t.Error("unexpected fallback", r.URL.Path)
				}
				downloads++
				w.Write(raw)
			}))
			defer server.Close()
			if err = s.Configure(RuntimeConfig{UpdateURL: server.URL}); err != nil {
				t.Fatal(err)
			}
			if err = s.Pull(context.Background()); err == nil {
				t.Fatal("accepted inconsistent index")
			}
			if s.Status().Library.Version != bundle.Manifest.Version || s.Status().Config.LastPullError == "" {
				t.Fatal("lost library or error")
			}
			if field == "unavailable_index" && downloads != 0 {
				t.Fatal("fell back from unavailable index")
			}
		})
	}
}
