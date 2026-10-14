package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOrganizationBuildingCIDRWithoutAccessPointOrVLAN(t *testing.T) {
	s := NewServer(Options{ShadowDir: t.TempDir(), ReadOnly: true})
	s.auth.enabled = true
	s.auth.sessions["cidr-session"] = authSession{User: localUser{ID: "cidr-admin", Role: "admin"}, CSRFToken: "cidr-csrf", ExpiresAt: time.Now().Add(time.Hour)}
	request := func(method, path, body string) *http.Request {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "cidr-session"})
		r.Header.Set("X-CSRF-Token", "cidr-csrf")
		return r
	}
	post := func(kind, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, request(http.MethodPost, "/api/v1/organization/"+kind, body))
		return w
	}
	for _, row := range []struct{ kind, body string }{
		{"campuses", `{"campus_id":"ncu","name":"前湖校区"}`},
		{"buildings", `{"building_id":"admin","campus_id":"ncu","name":"行政楼"}`},
		{"network-zones", `{"network_zone_id":"admin-ip","campus_id":"ncu","building_id":"admin","name":"行政楼","cidrs":["222.204.88.0/23"]}`},
	} {
		w := post(row.kind, row.body)
		if w.Code != 201 {
			t.Fatalf("%s: %d %s", row.kind, w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, request(http.MethodGet, "/api/v1/organization", ""))
	var response struct {
		Zones []NetworkZone `json:"network_zones"`
		APs   []AccessPoint `json:"access_points"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Zones) != 1 || len(response.APs) != 0 {
		t.Fatalf("unexpected directory: %+v", response)
	}
	zone := response.Zones[0]
	if zone.BuildingID != "admin" || len(zone.CIDRs) != 1 || zone.CIDRs[0] != "222.204.88.0/23" || len(zone.VLANs) != 0 || len(zone.SSIDs) != 0 {
		t.Fatalf("unexpected mapping: %+v", zone)
	}
	w = post("network-zones", `{"network_zone_id":"admin-ip","campus_id":"ncu","building_id":"admin","name":"行政楼","cidrs":["222.204.88.0/99"]}`)
	if w.Code != 400 {
		t.Fatalf("invalid CIDR accepted: %d %s", w.Code, w.Body.String())
	}
	if s.operations.doc.NetworkZones["admin-ip"].CIDRs[0] != "222.204.88.0/23" {
		t.Fatal("invalid edit replaced saved mapping")
	}
}

func TestNormalizeNetworkZoneCIDRs(t *testing.T) {
	zone := NetworkZone{CIDRs: []string{" 222.204.89.21/23 ", "222.204.88.0/23", "2001:db8::1/64"}}
	if err := normalizeNetworkZoneCIDRs(&zone); err != nil {
		t.Fatal(err)
	}
	if len(zone.CIDRs) != 2 || zone.CIDRs[0] != "222.204.88.0/23" || zone.CIDRs[1] != "2001:db8::/64" {
		t.Fatalf("wrong prefixes: %v", zone.CIDRs)
	}
}
