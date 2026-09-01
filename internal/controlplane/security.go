package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
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
	db       *sql.DB
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func newAuthManager(path string, secure bool, postgresDSN string) (*authManager, error) {
	manager := &authManager{enabled: strings.TrimSpace(path) != "" || strings.TrimSpace(postgresDSN) != "", users: map[string]localUser{}, sessions: map[string]authSession{}, attempts: map[string]loginAttempt{}, secure: secure, now: time.Now}
	if !manager.enabled {
		return manager, nil
	}
	if strings.TrimSpace(postgresDSN) != "" {
		db, err := sql.Open("pgx", postgresDSN)
		if err != nil {
			return nil, err
		}
		db.SetMaxOpenConns(10)
		db.SetMaxIdleConns(2)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := db.PingContext(ctx); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("connect PostgreSQL authentication repository: %w", err)
		}
		manager.db = db
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

func BootstrapAdminPostgres(dsn, username, name, password string) error {
	username = strings.TrimSpace(username)
	if username == "" || len(password) < 12 {
		return errors.New("username is required and password must contain at least 12 characters")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := db.ExecContext(ctx, `INSERT INTO local_users(user_id,username,display_name,role,password_hash,disabled) VALUES($1,$2,$3,'admin',$4,false) ON CONFLICT(username) DO NOTHING`, "user-"+shortToken(8), username, firstNonEmptyString(strings.TrimSpace(name), username), hash)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return fmt.Errorf("local administrator already exists: %s", username)
	}
	return nil
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
	if a.db != nil {
		return a.loginPostgres(remoteAddr, username, password)
	}
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
	if a.db != nil {
		return a.currentPostgres(cookie.Value)
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
	if a.db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = a.db.ExecContext(ctx, `DELETE FROM local_auth_sessions WHERE session_hash=$1`, tokenHash(cookie.Value))
		return
	}
	a.mu.Lock()
	delete(a.sessions, cookie.Value)
	a.mu.Unlock()
}

func (a *authManager) loginPostgres(remoteAddr, username, password string) (string, authSession, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	now := a.now().UTC()
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return "", authSession{}, err
	}
	defer tx.Rollback()
	var attempts int
	var windowStarted time.Time
	err = tx.QueryRowContext(ctx, `SELECT attempt_count, window_started_at FROM login_rate_limits WHERE remote_key=$1 FOR UPDATE`, remoteAddr).Scan(&attempts, &windowStarted)
	if err != nil && err != sql.ErrNoRows {
		return "", authSession{}, err
	}
	if err == sql.ErrNoRows || now.Sub(windowStarted) > 15*time.Minute {
		attempts, windowStarted = 0, now
	}
	if attempts >= 10 {
		return "", authSession{}, errors.New("too many login attempts")
	}
	var user localUser
	err = tx.QueryRowContext(ctx, `SELECT user_id, username, display_name, role, password_hash, disabled FROM local_users WHERE lower(username)=lower($1)`, strings.TrimSpace(username)).Scan(&user.ID, &user.Username, &user.Name, &user.Role, &user.PasswordHash, &user.Disabled)
	if err != nil || user.Disabled || !verifyPassword(user.PasswordHash, password) {
		attempts++
		_, upsertErr := tx.ExecContext(ctx, `INSERT INTO login_rate_limits(remote_key,attempt_count,window_started_at,updated_at) VALUES($1,$2,$3,now()) ON CONFLICT(remote_key) DO UPDATE SET attempt_count=EXCLUDED.attempt_count,window_started_at=EXCLUDED.window_started_at,updated_at=now()`, remoteAddr, attempts, windowStarted)
		if upsertErr != nil {
			return "", authSession{}, upsertErr
		}
		if err := tx.Commit(); err != nil {
			return "", authSession{}, err
		}
		return "", authSession{}, errors.New("invalid credentials")
	}
	token := shortToken(32)
	csrf := csrfForToken(token)
	expiresAt := now.Add(12 * time.Hour)
	if _, err := tx.ExecContext(ctx, `DELETE FROM login_rate_limits WHERE remote_key=$1`, remoteAddr); err != nil {
		return "", authSession{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO local_auth_sessions(session_hash,user_id,csrf_hash,expires_at,last_seen_at) VALUES($1,$2,$3,$4,$5)`, tokenHash(token), user.ID, tokenHash(csrf), expiresAt, now); err != nil {
		return "", authSession{}, err
	}
	if err := tx.Commit(); err != nil {
		return "", authSession{}, err
	}
	return token, authSession{User: user, CSRFToken: csrf, ExpiresAt: expiresAt}, nil
}

func (a *authManager) currentPostgres(token string) (authSession, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var user localUser
	var expiresAt time.Time
	err := a.db.QueryRowContext(ctx, `SELECT u.user_id,u.username,u.display_name,u.role,u.password_hash,u.disabled,s.expires_at FROM local_auth_sessions s JOIN local_users u ON u.user_id=s.user_id WHERE s.session_hash=$1 AND s.expires_at>now() AND u.disabled=false`, tokenHash(token)).Scan(&user.ID, &user.Username, &user.Name, &user.Role, &user.PasswordHash, &user.Disabled, &expiresAt)
	if err != nil {
		return authSession{}, false
	}
	_, _ = a.db.ExecContext(ctx, `UPDATE local_auth_sessions SET last_seen_at=now() WHERE session_hash=$1`, tokenHash(token))
	return authSession{User: user, CSRFToken: csrfForToken(token), ExpiresAt: expiresAt}, true
}

func tokenHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func csrfForToken(token string) string {
	digest := sha256.Sum256([]byte("proxy-sentinel-csrf:" + token))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func sessionHasPermission(session Session, permission string) bool {
	for _, candidate := range session.Permissions {
		if candidate == permission {
			return true
		}
	}
	return false
}
