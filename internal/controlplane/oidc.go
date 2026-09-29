package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	oidcStateCookie    = "proxy_sentinel_oidc_state"
	oidcVerifierCookie = "proxy_sentinel_oidc_verifier"
	oidcNonceCookie    = "proxy_sentinel_oidc_nonce"
)

type OIDCOptions struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	RoleMapping  map[string]string
	DefaultRole  string
}

type oidcManager struct {
	config      oauth2.Config
	verifier    *oidc.IDTokenVerifier
	auth        *authManager
	issuer      string
	roleMapping map[string]string
	defaultRole string
}

type oidcClaims struct {
	Subject           string   `json:"sub"`
	Email             string   `json:"email"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Nonce             string   `json:"nonce"`
	Groups            []string `json:"groups"`
}

func newOIDCManager(ctx context.Context, options OIDCOptions, auth *authManager) (*oidcManager, error) {
	if strings.TrimSpace(options.Issuer) == "" {
		return nil, nil
	}
	if auth == nil || auth.db == nil {
		return nil, errors.New("OIDC requires PostgreSQL-backed authentication")
	}
	if options.ClientID == "" || options.ClientSecret == "" || options.RedirectURL == "" {
		return nil, errors.New("OIDC issuer, client ID, client secret and redirect URL are required")
	}
	defaultRole := options.DefaultRole
	if defaultRole == "" {
		defaultRole = "viewer"
	}
	if !validRole(defaultRole) {
		return nil, fmt.Errorf("invalid OIDC default role %q", defaultRole)
	}
	for group, role := range options.RoleMapping {
		if strings.TrimSpace(group) == "" || !validRole(role) {
			return nil, fmt.Errorf("invalid OIDC role mapping %q=%q", group, role)
		}
	}
	provider, err := oidc.NewProvider(ctx, options.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}
	return &oidcManager{
		config:   oauth2.Config{ClientID: options.ClientID, ClientSecret: options.ClientSecret, Endpoint: provider.Endpoint(), RedirectURL: options.RedirectURL, Scopes: []string{oidc.ScopeOpenID, "profile", "email", "groups"}},
		verifier: provider.Verifier(&oidc.Config{ClientID: options.ClientID}), auth: auth, issuer: options.Issuer,
		roleMapping: options.RoleMapping, defaultRole: defaultRole,
	}, nil
}

func (m *oidcManager) start(w http.ResponseWriter, r *http.Request) {
	state, verifier, nonce := shortToken(24), oauth2.GenerateVerifier(), shortToken(24)
	setOIDCCookie(w, oidcStateCookie, state, m.auth.secure)
	setOIDCCookie(w, oidcVerifierCookie, verifier, m.auth.secure)
	setOIDCCookie(w, oidcNonceCookie, nonce, m.auth.secure)
	http.Redirect(w, r, m.config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce)), http.StatusFound)
}

func (m *oidcManager) callback(w http.ResponseWriter, r *http.Request) error {
	state, ok := oidcCookieValue(r, oidcStateCookie)
	if !ok || state == "" || r.URL.Query().Get("state") != state {
		return errors.New("OIDC state validation failed")
	}
	verifier, ok := oidcCookieValue(r, oidcVerifierCookie)
	if !ok {
		return errors.New("OIDC PKCE verifier is missing")
	}
	nonce, ok := oidcCookieValue(r, oidcNonceCookie)
	if !ok {
		return errors.New("OIDC nonce is missing")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	token, err := m.config.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		return fmt.Errorf("exchange OIDC authorization code: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return errors.New("OIDC response does not contain an ID token")
	}
	idToken, err := m.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return fmt.Errorf("verify OIDC ID token: %w", err)
	}
	var claims oidcClaims
	if err := idToken.Claims(&claims); err != nil {
		return fmt.Errorf("decode OIDC claims: %w", err)
	}
	if claims.Subject == "" || claims.Nonce != nonce {
		return errors.New("OIDC subject or nonce validation failed")
	}
	role := roleForGroups(claims.Groups, m.roleMapping, m.defaultRole)
	displayName := firstNonEmptyString(claims.Name, claims.PreferredUsername, claims.Email, claims.Subject)
	tokenValue, session, err := m.auth.loginExternal(ctx, m.issuer, claims.Subject, displayName, role)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: tokenValue, Path: "/", HttpOnly: true, Secure: m.auth.secure, SameSite: http.SameSiteLaxMode, MaxAge: int((12 * time.Hour).Seconds())})
	clearOIDCCookies(w, m.auth.secure)
	_ = session
	http.Redirect(w, r, "/", http.StatusFound)
	return nil
}

func roleForGroups(groups []string, mapping map[string]string, fallback string) string {
	roles := map[string]int{"viewer": 0, "reviewer": 1, "operator": 2, "admin": 3}
	selected := fallback
	for _, group := range groups {
		if role, ok := mapping[group]; ok && roles[role] > roles[selected] {
			selected = role
		}
	}
	return selected
}

func (a *authManager) loginExternal(ctx context.Context, issuer, subject, name, role string) (string, authSession, error) {
	if a.db == nil {
		return "", authSession{}, errors.New("external authentication requires PostgreSQL")
	}
	digest := sha256.Sum256([]byte(issuer + "\x00" + subject))
	id := "oidc-" + base64.RawURLEncoding.EncodeToString(digest[:12])
	externalKey := base64.RawURLEncoding.EncodeToString(digest[:])
	username := id
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return "", authSession{}, err
	}
	defer tx.Rollback()
	var user localUser
	err = tx.QueryRowContext(ctx, `INSERT INTO local_users(user_id,username,display_name,role,password_hash,disabled,auth_source,external_subject)
		VALUES($1,$2,$3,$4,'external-auth-disabled',false,'oidc',$5)
		ON CONFLICT(auth_source,external_subject) WHERE external_subject IS NOT NULL DO UPDATE
		SET display_name=EXCLUDED.display_name,role=EXCLUDED.role,updated_at=now()
		RETURNING user_id,username,display_name,role,password_hash,disabled`, id, username, name, role, externalKey).
		Scan(&user.ID, &user.Username, &user.Name, &user.Role, &user.PasswordHash, &user.Disabled)
	if err != nil {
		return "", authSession{}, err
	}
	if user.Disabled {
		return "", authSession{}, errors.New("OIDC user is disabled")
	}
	token := shortToken(32)
	csrf := csrfForToken(token)
	expiresAt := a.now().UTC().Add(12 * time.Hour)
	if _, err := tx.ExecContext(ctx, `INSERT INTO local_auth_sessions(session_hash,user_id,csrf_hash,expires_at,last_seen_at) VALUES($1,$2,$3,$4,now())`, tokenHash(token), user.ID, tokenHash(csrf), expiresAt); err != nil {
		return "", authSession{}, err
	}
	if err := tx.Commit(); err != nil {
		return "", authSession{}, err
	}
	return token, authSession{User: user, CSRFToken: csrf, ExpiresAt: expiresAt}, nil
}

func setOIDCCookie(w http.ResponseWriter, name, value string, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/api/v1/auth/oidc/callback", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: 600})
}

func oidcCookieValue(r *http.Request, name string) (string, bool) {
	cookie, err := r.Cookie(name)
	return func() string {
		if err != nil {
			return ""
		}
		return cookie.Value
	}(), err == nil
}

func clearOIDCCookies(w http.ResponseWriter, secure bool) {
	for _, name := range []string{oidcStateCookie, oidcVerifierCookie, oidcNonceCookie} {
		http.SetCookie(w, &http.Cookie{Name: name, Path: "/api/v1/auth/oidc/callback", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	}
}

func ParseOIDCRoleMapping(raw string) (map[string]string, error) {
	result := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return result, nil
	}
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, fmt.Errorf("decode OIDC role mapping: %w", err)
	}
	for group, role := range result {
		if strings.TrimSpace(group) == "" || !validRole(role) {
			return nil, fmt.Errorf("invalid OIDC role mapping %q=%q", group, role)
		}
	}
	return result, nil
}
