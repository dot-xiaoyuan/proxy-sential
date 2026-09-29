package srunapi

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"
)

type pinnedTransport struct{ base *http.Transport }

func (t *pinnedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" {
		return nil, fmt.Errorf("pinned management transport requires HTTPS")
	}
	return t.base.RoundTrip(r)
}
func (t *pinnedTransport) CloseIdleConnections() { t.base.CloseIdleConnections() }

// NewCertificatePinnedClient trusts exactly one explicitly provisioned leaf
// certificate. Obtain it over an authenticated management channel, never from
// an unverified first network connection. Rotation requires configuration review.
func NewCertificatePinnedClient(raw []byte) (*http.Client, error) {
	if len(raw) > 64<<10 {
		return nil, fmt.Errorf("pinned certificate exceeds 64 KiB")
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("exactly one PEM leaf certificate required")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid pinned certificate")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, fmt.Errorf("pinned certificate is not currently valid")
	}
	pin := sha256.Sum256(cert.Raw)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // Management credentials never traverse environment proxies.
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12,
		// Verification is replaced by exact out-of-band leaf pinning below. This
		// permits a managed legacy certificate without DNS SANs, not arbitrary peers.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("missing peer certificate")
			}
			peer := state.PeerCertificates[0]
			at := time.Now()
			if sha256.Sum256(peer.Raw) != pin {
				return fmt.Errorf("management certificate pin mismatch")
			}
			if at.Before(peer.NotBefore) || at.After(peer.NotAfter) {
				return fmt.Errorf("management certificate is not currently valid")
			}
			return nil
		},
	}
	return &http.Client{Transport: &pinnedTransport{base: transport}, Timeout: 7 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
