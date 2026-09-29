package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDescriptionBoundary(t *testing.T) {
	if _, e := ReadDescription(context.Background(), "http://127.0.0.1/a", "192.0.2.1"); e == nil {
		t.Fatal("cross target accepted")
	}
	if _, e := ReadDescription(context.Background(), "http://printer.example/a", "192.0.2.1"); e == nil {
		t.Fatal("DNS target accepted")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://192.0.2.2/")
		w.WriteHeader(302)
	}))
	defer server.Close()
	if _, e := ReadDescription(context.Background(), server.URL, "127.0.0.1"); e == nil {
		t.Fatal("redirect accepted")
	}
	if err := ValidateXML([]byte(`<!DOCTYPE x [<!ENTITY y SYSTEM "file:///etc/passwd">]><x>&y;</x>`)); err == nil {
		t.Fatal("DTD accepted")
	}
	if err := ValidateXML([]byte(strings.Repeat("x", 1048577))); err == nil {
		t.Fatal("oversize accepted")
	}
}
