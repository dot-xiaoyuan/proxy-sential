// Package srunapi implements native SRun v2 transport. Successful transport is
// never a completed Sentinel action: callers must reconcile authoritative state.
package srunapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var ErrCertificateTrust = errors.New("native certificate trust failed")
var ErrAuthentication = errors.New("native authentication failed")
var ErrBusinessRejected = errors.New("native API business rejection")
var ErrReadOnlyQuery = errors.New("native read-only query failed")

type Client struct {
	base, appID, secret string
	http                *http.Client
	credentials         func(context.Context) (string, string, error)
}

func New(base, appID, secret string, client *http.Client) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("native API requires an HTTP(S) origin without credentials, query or path")
	}
	if strings.TrimSpace(appID) == "" || secret == "" {
		return nil, fmt.Errorf("native application credentials required")
	}
	var hc http.Client
	if client != nil {
		hc = *client
	}
	if hc.Timeout <= 0 {
		hc.Timeout = 7 * time.Second
	}
	// POST bodies contain credentials. Never follow even a same-origin redirect.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{base: strings.TrimRight(base, "/"), appID: appID, secret: secret, http: &hc}, nil
}

// WithCredentialsProvider returns an immutable client copy. No lookup occurs
// until a token is requested; a provider failure never falls back to static keys.
func (c *Client) WithCredentialsProvider(provider func(context.Context) (string, string, error)) *Client {
	copy := *c
	copy.credentials = provider
	return &copy
}

// WithCredentialOverride uses a configured database source in preference to
// static credentials. Storage/query errors never select the static fallback.
func (c *Client) WithCredentialOverride(provider func(context.Context) (string, string, bool, error)) *Client {
	return c.WithCredentialsProvider(func(ctx context.Context) (string, string, error) {
		appID, secret, configured, err := provider(ctx)
		if err != nil || configured {
			return appID, secret, err
		}
		if c.credentials != nil {
			return c.credentials(ctx)
		}
		return c.appID, c.secret, nil
	})
}

type envelope struct {
	Code *int            `json:"code"`
	Data json.RawMessage `json:"data"`
}

func (c *Client) post(ctx context.Context, path string, values url.Values) (json.RawMessage, error) {
	return c.postBounded(ctx, path, values, 1<<20)
}

func (c *Client) postBounded(ctx context.Context, path string, values url.Values, limit int64) (json.RawMessage, error) {
	return c.requestBounded(ctx, http.MethodPost, path, values, limit)
}
func (c *Client) requestBounded(ctx context.Context, method, path string, values url.Values, limit int64) (json.RawMessage, error) {
	endpoint := c.base + path
	var body io.Reader = strings.NewReader(values.Encode())
	if method == http.MethodGet {
		endpoint += "?" + values.Encode()
		body = nil
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("native request construction failed")
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	res, err := c.http.Do(req)
	if err != nil {
		var verification *tls.CertificateVerificationError
		var authority x509.UnknownAuthorityError
		if errors.As(err, &verification) || errors.As(err, &authority) || strings.Contains(err.Error(), "certificate pin mismatch") || strings.Contains(err.Error(), "certificate is not currently valid") {
			return nil, ErrCertificateTrust
		}
		return nil, fmt.Errorf("native transport outcome uncertain")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("native API HTTP status %d", res.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, fmt.Errorf("native response incomplete or oversized")
	}
	var e envelope
	d := json.NewDecoder(bytes.NewReader(b))
	if err := d.Decode(&e); err != nil {
		return nil, fmt.Errorf("invalid native response")
	}
	var extra any
	if d.Decode(&extra) != io.EOF || e.Code == nil {
		return nil, fmt.Errorf("missing native result code or trailing response")
	}
	if *e.Code != 0 {
		return nil, fmt.Errorf("%w: code %d", ErrBusinessRejected, *e.Code)
	}
	return e.Data, nil
}

// RequestDisconnect makes exactly one native drop request after authentication.
// nil means code=0 acknowledgement only, NOT verified disconnection. It neither
// retries an uncertain operation nor manufactures a completion receipt. The
// caller must validate fresh ownership, persist intent, and reconcile the exact
// source instance/session against a complete authoritative online inventory.
var ErrDispatchPrevented = errors.New("native dispatch prevented before send")

func (c *Client) RequestDisconnect(ctx context.Context, account, rawOnlineID, dropType string) error {
	return c.requestDisconnect(ctx, account, rawOnlineID, dropType, nil)
}

// RequestDisconnectChecked runs the final guard after token acquisition. It
// does not retry, and a guard failure guarantees this call sent no drop request.
func (c *Client) RequestDisconnectChecked(ctx context.Context, account, rawOnlineID, dropType string, guard func(context.Context) error) error {
	if guard == nil {
		return fmt.Errorf("%w: final guard required", ErrDispatchPrevented)
	}
	return c.requestDisconnect(ctx, account, rawOnlineID, dropType, guard)
}

func (c *Client) requestDisconnect(ctx context.Context, account, rawOnlineID, dropType string, guard func(context.Context) error) error {
	if account == "" || strings.TrimSpace(account) != account || rawOnlineID == "" || strings.TrimSpace(rawOnlineID) != rawOnlineID {
		return fmt.Errorf("account and raw online ID required")
	}
	switch dropType {
	case "radius", "proxy", "dhcp", "portal":
	default:
		return fmt.Errorf("unsupported native drop type")
	}
	token, err := c.authenticate(ctx)
	if err != nil {
		return err
	}
	if guard != nil {
		if err := guard(ctx); err != nil {
			return fmt.Errorf("%w: authorization or session changed", ErrDispatchPrevented)
		}
	}
	if ctx.Err() != nil {
		return fmt.Errorf("%w: context cancelled", ErrDispatchPrevented)
	}
	_, err = c.post(ctx, "/api/v2/base/online-drop", url.Values{"access_token": {token}, "user_name": {account}, "rad_online_id": {rawOnlineID}, "drop_type": {dropType}})
	return err
}

func (c *Client) authenticate(ctx context.Context) (string, error) {
	appID, secret := c.appID, c.secret
	if c.credentials != nil {
		var err error
		appID, secret, err = c.credentials(ctx)
		if err != nil || strings.TrimSpace(appID) == "" || secret == "" {
			return "", fmt.Errorf("native application credentials unavailable")
		}
	}
	data, err := c.post(ctx, "/api/v2/auth/get-access-token", url.Values{"appId": {appID}, "appSecret": {secret}})
	if err != nil {
		return "", err
	}
	var token struct {
		AccessToken string `json:"access_token"`
		Lifetime    int    `json:"lifetime"`
	}
	if json.Unmarshal(data, &token) != nil || strings.TrimSpace(token.AccessToken) == "" || token.Lifetime <= 0 {
		return "", fmt.Errorf("invalid native access token response")
	}
	return token.AccessToken, nil
}

// OnlineTotal is a read-only connectivity probe, not a complete session snapshot.
func (c *Client) OnlineTotal(ctx context.Context) (int64, error) {
	token, err := c.authenticate(ctx)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrAuthentication, err)
	}
	data, err := c.post(ctx, "/api/v2/base/get-online-total", url.Values{"access_token": {token}})
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrReadOnlyQuery, err)
	}
	var result struct {
		Total *int64 `json:"online_total"`
	}
	if json.Unmarshal(data, &result) != nil || result.Total == nil || *result.Total < 0 {
		return 0, fmt.Errorf("%w: invalid native online total", ErrReadOnlyQuery)
	}
	return *result.Total, nil
}
