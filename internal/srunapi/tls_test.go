package srunapi

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExplicitCertificatePin(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, err := NewCertificatePinnedClient(cert)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal(response.StatusCode)
	}
	for _, bad := range [][]byte{[]byte("invalid"), append(append([]byte{}, cert...), cert...), append(append([]byte{}, cert...), []byte("trailing")...)} {
		if _, err := NewCertificatePinnedClient(bad); err == nil {
			t.Fatal("invalid certificate bundle accepted")
		}
	}
	if _, err := client.Get("http://127.0.0.1:1"); err == nil {
		t.Fatal("unencrypted pin bypass accepted")
	}
	transport := client.Transport.(*pinnedTransport).base
	// Pin checking is independent of hostname matching and must never be absent.
	verifier := transport.TLSClientConfig.VerifyConnection
	if verifier == nil {
		t.Fatal("no pin verifier")
	}
	state := response.TLS
	if err := verifier(*state); err != nil {
		t.Fatal(err)
	}
	copied := *state.PeerCertificates[0]
	copied.Raw = []byte("different leaf")
	state.PeerCertificates = []*x509.Certificate{&copied}
	if err := verifier(*state); err == nil {
		t.Fatal("changed certificate accepted")
	}
	copied = *server.Certificate()
	copied.NotAfter = time.Now().Add(-time.Hour)
	state.PeerCertificates = []*x509.Certificate{&copied}
	if err := verifier(*state); err == nil {
		t.Fatal("expired pinned certificate accepted")
	}
}

func TestReadOnlyProbeReportsTLSAuthenticationAndQuerySeparately(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/auth/get-access-token" {
			w.Write([]byte(`{"code":0,"data":{"access_token":"test-token","lifetime":60}}`))
			return
		}
		w.Write([]byte(`{"code":403,"data":null}`))
	}))
	defer server.Close()
	client, err := New(server.URL, "app", "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.OnlineTotal(context.Background()); !errors.Is(err, ErrCertificateTrust) || !errors.Is(err, ErrAuthentication) {
		t.Fatal("TLS failure not classified", err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	hc, err := NewCertificatePinnedClient(cert)
	if err != nil {
		t.Fatal(err)
	}
	defer hc.CloseIdleConnections()
	client, err = New(server.URL, "app", "secret", hc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.OnlineTotal(context.Background()); !errors.Is(err, ErrReadOnlyQuery) || errors.Is(err, ErrCertificateTrust) {
		t.Fatal("query failure not classified", err)
	}
}
