package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
)

type userView struct {
	ID       string `json:"user_id"`
	Username string `json:"username"`
	Name     string `json:"display_name"`
	Role     string `json:"role"`
	Disabled bool   `json:"disabled"`
}

type userMutation struct {
	Username string `json:"username"`
	Name     string `json:"display_name"`
	Role     string `json:"role"`
	Password string `json:"password"`
	Disabled *bool  `json:"disabled,omitempty"`
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/users"), "/")
	if r.Method == http.MethodGet && rest == "" {
		items, err := s.auth.listUsers(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "list_users_failed", err.Error())
			return
		}
		limit, err := boundedInt(r.URL.Query().Get("limit"), 20, 1, 50)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_page", err.Error())
			return
		}
		cursor, err := cursorOffset(r.URL.Query().Get("cursor"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_page", err.Error())
			return
		}
		paged, page := paginate(items, cursor, limit)
		writeJSON(w, http.StatusOK, map[string]any{"items": paged, "page": page})
		return
	}
	if r.Method == http.MethodPost && rest == "" {
		var body userMutation
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "bad_user", err.Error())
			return
		}
		item, err := s.auth.createUser(r.Context(), body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "create_user_failed", err.Error())
			return
		}
		s.appendAudit(r.Context(), "security.user_created", item.ID, "succeeded")
		writeJSON(w, http.StatusCreated, item)
		return
	}
	parts := strings.Split(rest, "/")
	if r.Method != http.MethodPost || len(parts) != 2 {
		writeError(w, http.StatusNotFound, "user_endpoint_not_found", "user endpoint not found")
		return
	}
	var body userMutation
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_user", err.Error())
		return
	}
	item, err := s.auth.updateUser(r.Context(), parts[0], parts[1], body)
	if err != nil {
		status := http.StatusBadRequest
		if err == sql.ErrNoRows {
			status = http.StatusNotFound
		}
		writeError(w, status, "update_user_failed", err.Error())
		return
	}
	s.appendAudit(r.Context(), "security.user_"+parts[1], item.ID, "succeeded")
	writeJSON(w, http.StatusOK, item)
}

func (a *authManager) listUsers(ctx context.Context) ([]userView, error) {
	items := []userView{}
	if a.db != nil {
		rows, err := a.db.QueryContext(ctx, `SELECT user_id,username,display_name,role,disabled FROM local_users ORDER BY lower(username)`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var item userView
			if err := rows.Scan(&item.ID, &item.Username, &item.Name, &item.Role, &item.Disabled); err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		return items, rows.Err()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, item := range a.users {
		items = append(items, userView{ID: item.ID, Username: item.Username, Name: item.Name, Role: item.Role, Disabled: item.Disabled})
	}
	sort.Slice(items, func(i, j int) bool { return strings.ToLower(items[i].Username) < strings.ToLower(items[j].Username) })
	return items, nil
}

func (a *authManager) createUser(ctx context.Context, body userMutation) (userView, error) {
	body.Username = strings.TrimSpace(body.Username)
	body.Name = strings.TrimSpace(body.Name)
	if body.Username == "" || len(body.Password) < 12 || !validRole(body.Role) {
		return userView{}, fmt.Errorf("username, a valid role, and a password with at least 12 characters are required")
	}
	hash, err := hashPassword(body.Password)
	if err != nil {
		return userView{}, err
	}
	user := localUser{ID: "user-" + shortToken(8), Username: body.Username, Name: firstNonEmptyString(body.Name, body.Username), Role: body.Role, PasswordHash: hash}
	if a.db != nil {
		_, err = a.db.ExecContext(ctx, `INSERT INTO local_users(user_id,username,display_name,role,password_hash,disabled) VALUES($1,$2,$3,$4,$5,false)`, user.ID, user.Username, user.Name, user.Role, user.PasswordHash)
		if err != nil {
			return userView{}, err
		}
	} else {
		a.mu.Lock()
		defer a.mu.Unlock()
		key := strings.ToLower(user.Username)
		if _, ok := a.users[key]; ok {
			return userView{}, fmt.Errorf("username already exists")
		}
		a.users[key] = user
		if err := a.saveUsersLocked(); err != nil {
			return userView{}, err
		}
	}
	return userView{ID: user.ID, Username: user.Username, Name: user.Name, Role: user.Role}, nil
}

func (a *authManager) updateUser(ctx context.Context, id, operation string, body userMutation) (userView, error) {
	if a.db != nil {
		tx, err := a.db.BeginTx(ctx, nil)
		if err != nil {
			return userView{}, err
		}
		defer tx.Rollback()
		var query string
		var args []any
		switch operation {
		case "profile":
			if !validRole(body.Role) || strings.TrimSpace(body.Name) == "" {
				return userView{}, fmt.Errorf("display_name and valid role are required")
			}
			query = `UPDATE local_users SET display_name=$2,role=$3,updated_at=now() WHERE user_id=$1`
			args = []any{id, strings.TrimSpace(body.Name), body.Role}
		case "password":
			if len(body.Password) < 12 {
				return userView{}, fmt.Errorf("password must contain at least 12 characters")
			}
			hash, err := hashPassword(body.Password)
			if err != nil {
				return userView{}, err
			}
			query = `UPDATE local_users SET password_hash=$2,updated_at=now() WHERE user_id=$1`
			args = []any{id, hash}
		case "disable", "enable":
			query = `UPDATE local_users SET disabled=$2,updated_at=now() WHERE user_id=$1`
			args = []any{id, operation == "disable"}
		default:
			return userView{}, fmt.Errorf("unsupported user operation")
		}
		result, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return userView{}, err
		}
		if affected, _ := result.RowsAffected(); affected == 0 {
			return userView{}, sql.ErrNoRows
		}
		if operation == "password" || operation == "disable" {
			if _, err = tx.ExecContext(ctx, `DELETE FROM local_auth_sessions WHERE user_id=$1`, id); err != nil {
				return userView{}, err
			}
		}
		var item userView
		if err = tx.QueryRowContext(ctx, `SELECT user_id,username,display_name,role,disabled FROM local_users WHERE user_id=$1`, id).Scan(&item.ID, &item.Username, &item.Name, &item.Role, &item.Disabled); err != nil {
			return userView{}, err
		}
		if err = tx.Commit(); err != nil {
			return userView{}, err
		}
		return item, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var key string
	var user localUser
	for candidate, item := range a.users {
		if item.ID == id {
			key, user = candidate, item
			break
		}
	}
	if key == "" {
		return userView{}, sql.ErrNoRows
	}
	switch operation {
	case "profile":
		if !validRole(body.Role) || strings.TrimSpace(body.Name) == "" {
			return userView{}, fmt.Errorf("display_name and valid role are required")
		}
		user.Name = strings.TrimSpace(body.Name)
		user.Role = body.Role
	case "password":
		if len(body.Password) < 12 {
			return userView{}, fmt.Errorf("password must contain at least 12 characters")
		}
		hash, err := hashPassword(body.Password)
		if err != nil {
			return userView{}, err
		}
		user.PasswordHash = hash
		a.deleteUserSessionsLocked(id)
	case "disable":
		user.Disabled = true
		a.deleteUserSessionsLocked(id)
	case "enable":
		user.Disabled = false
	default:
		return userView{}, fmt.Errorf("unsupported user operation")
	}
	a.users[key] = user
	if err := a.saveUsersLocked(); err != nil {
		return userView{}, err
	}
	return userView{ID: user.ID, Username: user.Username, Name: user.Name, Role: user.Role, Disabled: user.Disabled}, nil
}

func (a *authManager) deleteUserSessionsLocked(userID string) {
	for token, session := range a.sessions {
		if session.User.ID == userID {
			delete(a.sessions, token)
		}
	}
}

func (a *authManager) saveUsersLocked() error {
	if a.path == "" {
		return nil
	}
	users := make([]localUser, 0, len(a.users))
	for _, user := range a.users {
		users = append(users, user)
	}
	sort.Slice(users, func(i, j int) bool { return strings.ToLower(users[i].Username) < strings.ToLower(users[j].Username) })
	data, err := json.MarshalIndent(localUserFile{Version: 1, Users: users}, "", "  ")
	if err != nil {
		return err
	}
	temporary := a.path + ".tmp"
	if err = os.WriteFile(temporary, append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(temporary, a.path)
}
