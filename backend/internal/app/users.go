package app

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type managedUser struct {
	ID                     int64      `json:"id"`
	Name                   string     `json:"name"`
	Email                  string     `json:"email"`
	Role                   string     `json:"role"`
	Active                 bool       `json:"active"`
	LastLoginAt            *time.Time `json:"lastLoginAt,omitempty"`
	CreatedAt              time.Time  `json:"createdAt"`
	Password               string     `json:"password,omitempty"`
	SSOConnected           bool       `json:"ssoConnected"`
	SSOProviders           string     `json:"ssoProviders,omitempty"`
	ServerCount            int        `json:"serverCount"`
	FolderCount            int        `json:"folderCount"`
	CredentialProfileCount int        `json:"credentialProfileCount"`
}

type userMutation struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	Active   *bool  `json:"active"`
	Password string `json:"password"`
}

func validUserRole(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin", "user":
		return true
	default:
		return false
	}
}

func normalizeUserRole(role string) string {
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "readonly" || role == "read-only" {
		return "user"
	}
	return role
}

func normalizeUserEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

func isLastActiveAdminConstraint(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "last active administrator")
}

func (a *App) adminUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rows, err := a.DB.Query(`SELECT u.id,u.name,u.email,u.role,u.active,u.last_login_at,u.created_at,
			COALESCE((SELECT GROUP_CONCAT(p.name, ', ') FROM oidc_identities i JOIN oidc_providers p ON p.id=i.provider_id WHERE i.user_id=u.id AND p.enabled=1),''),
			(SELECT COUNT(*) FROM servers s WHERE s.owner_user_id=u.id AND s.workspace_id IS NULL),
			(SELECT COUNT(*) FROM folders f WHERE f.owner_user_id=u.id AND f.workspace_id IS NULL),
			(SELECT COUNT(*) FROM credential_profiles cp WHERE cp.owner_user_id=u.id)
			FROM users u ORDER BY u.name,u.email,u.id`)
		if err != nil {
			a.internalError(w, "users", err)
			return
		}
		defer rows.Close()
		out := []managedUser{}
		for rows.Next() {
			var u managedUser
			var active int
			var last sql.NullTime
			if err := rows.Scan(&u.ID, &u.Name, &u.Email, &u.Role, &active, &last, &u.CreatedAt, &u.SSOProviders, &u.ServerCount, &u.FolderCount, &u.CredentialProfileCount); err != nil {
				a.internalError(w, "users", err)
				return
			}
			u.Active = active != 0
			u.SSOConnected = strings.TrimSpace(u.SSOProviders) != ""
			if last.Valid {
				v := last.Time
				u.LastLoginAt = &v
			}
			out = append(out, u)
		}
		if err := rows.Err(); err != nil {
			a.internalError(w, "users", err)
			return
		}
		jsonOut(w, 200, out)
	case http.MethodPost:
		var in userMutation
		if decode(r, &in) != nil {
			jsonOut(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		in.Name = strings.TrimSpace(in.Name)
		in.Email = normalizeUserEmail(in.Email)
		in.Role = normalizeUserRole(in.Role)
		if in.Name == "" || in.Email == "" || !validUserRole(in.Role) || len(in.Password) < 10 {
			jsonOut(w, 400, map[string]string{"error": "name, email, valid role and password (10+ chars) required"})
			return
		}
		active := 1
		passwordHash, saturated := a.hashPasswordLimited(in.Password)
		if saturated {
			jsonOut(w, http.StatusTooManyRequests, map[string]string{"error": "authentication capacity reached; try again shortly"})
			return
		}
		res, err := a.DB.Exec("INSERT INTO users(name,email,password_hash,role,active) VALUES(?,?,?,?,?)", in.Name, in.Email, passwordHash, in.Role, active)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				jsonOut(w, 409, map[string]string{"error": "email already exists"})
			} else {
				a.internalError(w, "users", err)
			}
			return
		}
		id, _ := res.LastInsertId()
		out := managedUser{ID: id, Name: in.Name, Email: in.Email, Role: in.Role, Active: true}
		a.audit(uid(r), "user.create", fmt.Sprintf("user=%d role=%s", id, in.Role))
		jsonOut(w, 201, out)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *App) adminUserByID(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.URL.Path, "/api/admin/users/")
	if err != nil || id <= 0 {
		jsonOut(w, 400, map[string]string{"error": "bad user id"})
		return
	}

	var current managedUser
	var active int
	if err := a.DB.QueryRow("SELECT id,name,email,role,active FROM users WHERE id=?", id).Scan(&current.ID, &current.Name, &current.Email, &current.Role, &active); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			jsonOut(w, 404, map[string]string{"error": "user not found"})
		} else {
			a.internalError(w, "users", err)
		}
		return
	}
	current.Active = active != 0
	_ = a.DB.QueryRow(`SELECT COALESCE((SELECT GROUP_CONCAT(p.name, ', ') FROM oidc_identities i JOIN oidc_providers p ON p.id=i.provider_id WHERE i.user_id=? AND p.enabled=1),''), (SELECT COUNT(*) FROM servers WHERE owner_user_id=? AND workspace_id IS NULL), (SELECT COUNT(*) FROM folders WHERE owner_user_id=? AND workspace_id IS NULL), (SELECT COUNT(*) FROM credential_profiles WHERE owner_user_id=?)`, id, id, id, id).Scan(&current.SSOProviders, &current.ServerCount, &current.FolderCount, &current.CredentialProfileCount)
	current.SSOConnected = strings.TrimSpace(current.SSOProviders) != ""

	switch r.Method {
	case http.MethodPatch:
		wasActiveAdmin := current.Role == "admin" && current.Active
		var in userMutation
		if decode(r, &in) != nil {
			jsonOut(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if strings.TrimSpace(in.Name) != "" {
			current.Name = strings.TrimSpace(in.Name)
		}
		if strings.TrimSpace(in.Email) != "" {
			current.Email = normalizeUserEmail(in.Email)
		}
		if strings.TrimSpace(in.Role) != "" {
			in.Role = normalizeUserRole(in.Role)
			if !validUserRole(in.Role) {
				jsonOut(w, 400, map[string]string{"error": "invalid role"})
				return
			}
			current.Role = in.Role
		}
		if in.Active != nil {
			current.Active = *in.Active
		}
		if current.Name == "" || current.Email == "" {
			jsonOut(w, 400, map[string]string{"error": "name and email are required"})
			return
		}
		if len(in.Password) > 0 && len(in.Password) < 10 {
			jsonOut(w, 400, map[string]string{"error": "new password must have at least 10 characters"})
			return
		}

		if wasActiveAdmin && (current.Role != "admin" || !current.Active) {
			var others int
			if err := a.DB.QueryRow("SELECT COUNT(*) FROM users WHERE id<>? AND role='admin' AND active=1", id).Scan(&others); err != nil {
				a.internalError(w, "users", err)
				return
			}
			if others == 0 {
				jsonOut(w, 409, map[string]string{"error": "cannot disable or demote the last active administrator"})
				return
			}
		}

		newPasswordHash := ""
		if in.Password != "" {
			var saturated bool
			newPasswordHash, saturated = a.hashPasswordLimited(in.Password)
			if saturated {
				jsonOut(w, http.StatusTooManyRequests, map[string]string{"error": "authentication capacity reached; try again shortly"})
				return
			}
		}

		tx, err := a.DB.Begin()
		if err != nil {
			a.internalError(w, "users", err)
			return
		}
		defer tx.Rollback()
		if in.Password != "" {
			_, err = tx.Exec("UPDATE users SET name=?,email=?,role=?,active=?,password_hash=? WHERE id=?", current.Name, current.Email, current.Role, boolInt(current.Active), newPasswordHash, id)
		} else {
			_, err = tx.Exec("UPDATE users SET name=?,email=?,role=?,active=? WHERE id=?", current.Name, current.Email, current.Role, boolInt(current.Active), id)
		}
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				jsonOut(w, 409, map[string]string{"error": "email already exists"})
			} else if isLastActiveAdminConstraint(err) {
				jsonOut(w, 409, map[string]string{"error": "cannot disable or demote the last active administrator"})
			} else {
				a.internalError(w, "users", err)
			}
			return
		}
		if !current.Active {
			if _, err = tx.Exec("DELETE FROM sessions WHERE user_id=?", id); err != nil {
				a.internalError(w, "users", err)
				return
			}
		}
		if err = tx.Commit(); err != nil {
			a.internalError(w, "users", err)
			return
		}
		current.Password = ""
		if !current.Active {
			a.terminateUserLiveSessions(id, "permission_revoked")
			a.terminateUserTransfers(id)
		} else if wasActiveAdmin && current.Role != "admin" {
			// Administrators have implicit access to every workspace/template. A
			// demotion must revoke already-open connections immediately; the user
			// can reconnect to personal or explicitly assigned resources afterwards.
			a.terminateUserLiveSessions(id, "role_permissions_changed")
			a.terminateUserTransfers(id)
		}
		if wasActiveAdmin && current.Role != "admin" {
			a.revalidateAllTemplateRuntimeAccess()
		}
		a.audit(uid(r), "user.update", fmt.Sprintf("user=%d role=%s active=%t", id, current.Role, current.Active))
		jsonOut(w, 200, current)
	case http.MethodDelete:
		if id == uid(r) {
			jsonOut(w, 409, map[string]string{"error": "cannot delete the account used by the current session"})
			return
		}
		if current.Role == "admin" && current.Active {
			var others int
			if err := a.DB.QueryRow("SELECT COUNT(*) FROM users WHERE id<>? AND role='admin' AND active=1", id).Scan(&others); err != nil {
				a.internalError(w, "users", err)
				return
			}
			if others == 0 {
				jsonOut(w, 409, map[string]string{"error": "cannot delete the last active administrator"})
				return
			}
		}
		profiles, servers, folders := current.CredentialProfileCount, current.ServerCount, current.FolderCount
		var externallyUsedProfiles int
		if err := a.DB.QueryRow(`SELECT COUNT(DISTINCT cp.id) FROM credential_profiles cp JOIN servers s ON s.credential_profile_id=cp.id WHERE cp.owner_user_id=? AND (s.owner_user_id<>? OR s.workspace_id IS NOT NULL)`, id, id).Scan(&externallyUsedProfiles); err != nil {
			a.internalError(w, "users", err)
			return
		}
		if externallyUsedProfiles > 0 {
			jsonOut(w, 409, map[string]any{"error": "shared credential profiles owned by this user are still used by another user's server", "code": "credential_profiles_in_use", "credentialProfileCount": externallyUsedProfiles})
			return
		}
		if (profiles > 0 || servers > 0 || folders > 0) && r.URL.Query().Get("force") != "1" {
			jsonOut(w, 409, map[string]any{"error": "user still owns private ZentSSH data", "code": "private_user_data_owned", "serverCount": servers, "folderCount": folders, "credentialProfileCount": profiles})
			return
		}
		a.terminateUserLiveSessions(id, "user_deleted")
		a.terminateUserTransfers(id)
		tx, txErr := a.DB.Begin()
		if txErr != nil {
			a.internalError(w, "users", txErr)
			return
		}
		defer tx.Rollback()
		// Keep SSO account bindings deterministic even if this database was created
		// by an older build that did not enforce SQLite foreign keys on every pooled
		// connection. The schema cascade remains the primary invariant; this explicit
		// cleanup also repairs the historical weak point during account deletion.
		if _, txErr = tx.Exec("DELETE FROM oidc_identities WHERE user_id=?", id); txErr != nil {
			a.internalError(w, "users", txErr)
			return
		}
		if _, txErr = tx.Exec("DELETE FROM oidc_states WHERE link_user_id=?", id); txErr != nil {
			a.internalError(w, "users", txErr)
			return
		}
		// Workspace resources outlive the user who originally created them. Reassign
		// their bookkeeping owner to the administrator performing the deletion before
		// removing the target user's private resources.
		if _, txErr = tx.Exec("UPDATE servers SET owner_user_id=? WHERE owner_user_id=? AND workspace_id IS NOT NULL", uid(r), id); txErr != nil {
			a.internalError(w, "users", txErr)
			return
		}
		if _, txErr = tx.Exec("UPDATE folders SET owner_user_id=? WHERE owner_user_id=? AND workspace_id IS NOT NULL", uid(r), id); txErr != nil {
			a.internalError(w, "users", txErr)
			return
		}
		if _, txErr = tx.Exec("DELETE FROM servers WHERE owner_user_id=? AND workspace_id IS NULL", id); txErr != nil {
			a.internalError(w, "users", txErr)
			return
		}
		if _, txErr = tx.Exec("DELETE FROM credential_profiles WHERE owner_user_id=?", id); txErr != nil {
			a.internalError(w, "users", txErr)
			return
		}
		if _, txErr = tx.Exec("DELETE FROM folders WHERE owner_user_id=? AND workspace_id IS NULL", id); txErr != nil {
			a.internalError(w, "users", txErr)
			return
		}
		if _, txErr = tx.Exec("DELETE FROM users WHERE id=?", id); txErr != nil {
			if isLastActiveAdminConstraint(txErr) {
				jsonOut(w, 409, map[string]string{"error": "cannot delete the last active administrator"})
			} else {
				a.internalError(w, "users", txErr)
			}
			return
		}
		if txErr = tx.Commit(); txErr != nil {
			a.internalError(w, "users", txErr)
			return
		}
		a.audit(uid(r), "user.delete", fmt.Sprintf("user=%d", id))
		jsonOut(w, 200, map[string]bool{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
