package controlplane

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const sessionCookieName = "proxy_sentinel_session"

type localUser struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	Name         string `json:"name"`
	Role         string `json:"role"`
	PasswordHash string `json:"password_hash"`
	Disabled     bool   `json:"disabled,omitempty"`
}

type localUserFile struct {
	Version int         `json:"version"`
	Users   []localUser `json:"users"`
}

type authSession struct {
	User      localUser
	CSRFToken string
	ExpiresAt time.Time
}

type loginAttempt struct {
	Count       int
	WindowStart time.Time
}

type authManager struct {
	mu       sync.Mutex
	enabled  bool
	users    map[string]localUser
	sessions map[string]authSession
	attempts map[string]loginAttempt
	secure   bool
	now      func() time.Time
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func newAuthManager(path string, secure bool) (*authManager, error) {
	manager := &authManager{enabled: strings.TrimSpace(path) != "", users: map[string]localUser{}, sessions: map[string]authSession{}, attempts: map[string]loginAttempt{}, secure: secure, now: time.Now}
	if !manager.enabled {
		return manager, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read local auth file: %w", err)
	}
	var file localUserFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("decode local auth file: %w", err)
	}
	for _, user := range file.Users {
		if !validRole(user.Role) || strings.TrimSpace(user.Username) == "" || strings.TrimSpace(user.PasswordHash) == "" {
			return nil, fmt.Errorf("invalid local user %q", user.Username)
		}
		manager.users[strings.ToLower(user.Username)] = user
	}
	return manager, nil
}

func BootstrapAdmin(path, username, name, password string) error {
	username = strings.TrimSpace(username)
	if username == "" || len(password) < 12 {
		return errors.New("username is required and password must contain at least 12 characters")
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("auth file already exists: %s", path)
	} else if !os.IsNotExist(err) {
		return err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	file := localUserFile{Version: 1, Users: []localUser{{ID: "user-" + shortToken(8), Username: username, Name: firstNonEmptyString(strings.TrimSpace(name), username), Role: "admin", PasswordHash: hash}}}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, 600000, 32)
	if err != nil {
		return "", err
	}
	return "pbkdf2-sha256$600000$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key), nil
}

func verifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	var iterations int
	if _, err := fmt.Sscanf(parts[1], "%d", &iterations); err != nil || iterations < 100000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	actual, err := pbkdf2.Key(sha256.New, password, salt, iterations, len(expected))
	return err == nil && hmac.Equal(actual, expected)
}

func shortToken(size int) string {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func validRole(role string) bool {
	return role == "viewer" || role == "reviewer" || role == "operator" || role == "admin"
}

func rolePermissions(role string) []string {
	read := []string{"risks:read", "evidence:read", "events:read", "shadow:read", "audit:read", "ingest:read", "dpi:read", "cases:read", "identity:read", "organization:read", "actions:read"}
	switch role {
	case "reviewer":
		return append(read, "labels:create", "cases:write")
	case "operator":
		return append(read, "labels:create", "cases:write", "endpoints:write", "actions:execute", "actions:revoke")
	case "admin":
		return append(read, "labels:create", "cases:write", "endpoints:write", "actions:execute", "actions:revoke", "rules:reload", "device-fingerprint-library:update", "organization:write", "integrations:write", "users:manage")
	default:
		return read
	}
}

func sessionForUser(user localUser) Session {
	return Session{User: User{ID: user.ID, Name: user.Name}, Role: user.Role, Permissions: rolePermissions(user.Role)}
}

func (a *authManager) login(remoteAddr, username, password string) (string, authSession, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	attempt := a.attempts[remoteAddr]
	if now.Sub(attempt.WindowStart) > 15*time.Minute {
		attempt = loginAttempt{WindowStart: now}
	}
	if attempt.Count >= 10 {
		return "", authSession{}, errors.New("too many login attempts")
	}
	user, ok := a.users[strings.ToLower(strings.TrimSpace(username))]
	if !ok || user.Disabled || !verifyPassword(user.PasswordHash, password) {
		attempt.Count++
		if attempt.WindowStart.IsZero() {
			attempt.WindowStart = now
		}
		a.attempts[remoteAddr] = attempt
		return "", authSession{}, errors.New("invalid credentials")
	}
	delete(a.attempts, remoteAddr)
	token := shortToken(32)
	session := authSession{User: user, CSRFToken: shortToken(24), ExpiresAt: now.Add(12 * time.Hour)}
	a.sessions[token] = session
	return token, session, nil
}

func (a *authManager) current(r *http.Request) (authSession, bool) {
	if !a.enabled {
		return authSession{}, false
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return authSession{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	session, ok := a.sessions[cookie.Value]
	if !ok || a.now().After(session.ExpiresAt) {
		delete(a.sessions, cookie.Value)
		return authSession{}, false
	}
	return session, true
}

func (a *authManager) logout(r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return
	}
	a.mu.Lock()
	delete(a.sessions, cookie.Value)
	a.mu.Unlock()
}

func sessionHasPermission(session Session, permission string) bool {
	for _, candidate := range session.Permissions {
		if candidate == permission {
			return true
		}
	}
	return false
}
