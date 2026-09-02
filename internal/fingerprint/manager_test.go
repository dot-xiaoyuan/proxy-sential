package fingerprint

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDomainBackfillStatusReportsCountsVersionAndFailure(t *testing.T) {
	domainData := []byte(`[{"domain":"push.apple.test","match_type":"subdomain","ecosystem":"Apple","category":"push","confidence":0.55,"source":"NextDNS"},{"domain":"cloud.huawei.test","match_type":"exact","ecosystem":"Huawei","category":"device_cloud","confidence":0.55,"source":"NextDNS"}]`)
	library, err := LoadWithDomainData("status-v2", embeddedOUI, []byte("[]"), []byte("[]"), embeddedBrandAliases, domainData)
	if err != nil {
		t.Fatal(err)
	}
	status := libraryStatus(library, Status{Sources: []BundleSource{{Name: "NextDNS native-tracking-domains", Version: "abcdef123456", URL: "https://example.test", License: "MIT"}}})
	if status.DomainRuleCount != 2 || status.DomainEcosystemCount != 2 || status.DomainSourceVersion != "abcdef123456" {
		t.Fatalf("unexpected domain status: %+v", status)
	}
	manager := NewManager("")
	manager.SetDomainBackfill("running", 120)
	manager.SetDomainBackfillFailure(121, fmt.Errorf("cursor query failed"))
	status = manager.Status()
	if status.DomainBackfillStatus != "failed" || status.DomainBackfillProcessed != 121 || status.DomainBackfillLastError != "cursor query failed" {
		t.Fatalf("failure status missing: %+v", status)
	}
}

func TestManagerUpdateActivatesValidatedLibraryAndKeepsLastGoodOnFailure(t *testing.T) {
	previous := Default()
	defer SetDefault(previous)
	failing := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing {
			http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/oui"):
			fmt.Fprint(w, "Assignment,Organization Name\n000C29,VMware Test\n")
		case r.URL.Path == "/commit":
			fmt.Fprint(w, `{"sha":"1234567890abcdef"}`)
		case strings.HasPrefix(r.URL.Path, "/raw/"):
			fmt.Fprint(w, "device_parsers:\n")
			for index := 0; index < 12; index++ {
				fmt.Fprintf(w, "  - regex: 'Device%d'\n    device_replacement: 'Model%d'\n    brand_replacement: 'Brand%d'\n", index, index, index)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	manager := NewManager(dir)
	manager.SetOffline(false)
	manager.ouiURLs = []string{server.URL + "/oui-l", server.URL + "/oui-m", server.URL + "/oui-s"}
	manager.uapCommitURL = server.URL + "/commit"
	manager.uapRawURL = server.URL + "/raw/%s"
	status, err := manager.Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "ready" || !strings.HasPrefix(status.Version, "ieee+uap-") {
		t.Fatalf("unexpected status: %+v", status)
	}
	if _, err := os.Stat(filepath.Join(dir, "device-rules.json")); err != nil {
		t.Fatal(err)
	}
	result := Default().Identify("00:0c:29:00:00:01", "Device7")
	if result.Brand != "Brand7" || result.Model != "Model7" {
		t.Fatalf("updated library not active: %+v", result)
	}
	lastVersion := Default().Version()
	failing = true
	if _, err := manager.Update(context.Background()); err == nil {
		t.Fatal("expected failed update")
	}
	if Default().Version() != lastVersion {
		t.Fatalf("failed update replaced last good version")
	}
}

func TestOfflineManagerNeverCallsNetworkUpdate(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()
	manager := NewManager(t.TempDir())
	manager.ouiURLs = []string{server.URL}
	manager.SetOffline(true)
	if _, err := manager.Update(context.Background()); err == nil || !strings.Contains(err.Error(), "offline_update_required") {
		t.Fatalf("expected explicit offline rejection, got %v", err)
	}
	if calls != 0 {
		t.Fatalf("offline manager made %d network calls", calls)
	}
}

func TestMergeOfficialIEEECSVShape(t *testing.T) {
	merged, err := mergeOUICSV([][]byte{[]byte("Registry,Assignment,Organization Name,Organization Address\nMA-L,000C29,VMware Inc.,Palo Alto\n")})
	if err != nil {
		t.Fatalf("merge official IEEE CSV: %v", err)
	}
	library, err := Load("test", merged, []byte("[]"))
	if err != nil {
		t.Fatalf("load normalized IEEE CSV: %v", err)
	}
	result := library.Identify("00:0c:29:01:02:03")
	if result.Vendor != "VMware Inc." {
		t.Fatalf("unexpected vendor: %q", result.Vendor)
	}
}
