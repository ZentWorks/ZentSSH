package app

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

type workspacePermissions struct {
	CanUse    bool `json:"canUse"`
	CanCreate bool `json:"canCreate"`
	CanEdit   bool `json:"canEdit"`
	CanDelete bool `json:"canDelete"`
}

type workspaceItem struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Active      bool   `json:"active"`
	MemberCount int    `json:"memberCount,omitempty"`
	ServerCount int    `json:"serverCount,omitempty"`
	FolderCount int    `json:"folderCount,omitempty"`
	workspacePermissions
}

type workspaceMember struct {
	UserID   int64  `json:"userId"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	Active   bool   `json:"active"`
	Assigned bool   `json:"assigned"`
	workspacePermissions
}

type workspaceMutation struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	Active      *bool   `json:"active,omitempty"`
}

type workspaceMembershipMutation struct {
	WorkspaceID int64 `json:"workspaceId"`
	UserID      int64 `json:"userId"`
	Assigned    bool  `json:"assigned"`
	workspacePermissions
}

type workspaceMembershipItem struct {
	WorkspaceID int64  `json:"workspaceId"`
	Name        string `json:"name"`
	Active      bool   `json:"active"`
	Assigned    bool   `json:"assigned"`
	workspacePermissions
}

func fullWorkspacePermissions() workspacePermissions {
	return workspacePermissions{CanUse: true, CanCreate: true, CanEdit: true, CanDelete: true}
}

func anyWorkspacePermission(p workspacePermissions) bool {
	return p.CanUse || p.CanCreate || p.CanEdit || p.CanDelete
}

func normalizeWorkspaceInput(in *workspaceMutation) error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Description != nil {
		description := strings.TrimSpace(*in.Description)
		in.Description = &description
	}
	if in.Name == "" || len([]byte(in.Name)) > 120 {
		return errors.New("workspace name must contain 1-120 bytes")
	}
	if in.Description != nil && len([]byte(*in.Description)) > 1000 {
		return errors.New("workspace description is too long")
	}
	return nil
}

func (a *App) workspacePermissionsForUser(userID, workspaceID int64) (workspaceItem, workspacePermissions, error) {
	var item workspaceItem
	var active int
	if err := a.DB.QueryRow(`SELECT id,name,description,active FROM workspaces WHERE id=?`, workspaceID).Scan(&item.ID, &item.Name, &item.Description, &active); err != nil {
		return item, workspacePermissions{}, err
	}
	item.Active = active != 0
	userRole, err := a.roleForUser(userID)
	if err != nil {
		return item, workspacePermissions{}, err
	}
	if normalizeUserRole(userRole) == "admin" {
		return item, fullWorkspacePermissions(), nil
	}
	var use, create, edit, del int
	err = a.DB.QueryRow(`SELECT can_use,can_create,can_edit,can_delete FROM workspace_memberships WHERE workspace_id=? AND user_id=?`, workspaceID, userID).Scan(&use, &create, &edit, &del)
	if err != nil {
		return item, workspacePermissions{}, err
	}
	return item, workspacePermissions{CanUse: use != 0, CanCreate: create != 0, CanEdit: edit != 0, CanDelete: del != 0}, nil
}

func workspacePermissionAllowed(p workspacePermissions, need string) bool {
	switch need {
	case "read":
		return anyWorkspacePermission(p)
	case "use":
		return p.CanUse
	case "create":
		return p.CanCreate
	case "edit":
		return p.CanEdit
	case "delete":
		return p.CanDelete
	default:
		return false
	}
}

func (a *App) requireWorkspacePermission(userID, workspaceID int64, need string) (workspaceItem, workspacePermissions, error) {
	item, permissions, err := a.workspacePermissionsForUser(userID, workspaceID)
	if err != nil {
		return item, permissions, err
	}
	if !item.Active && need != "read" {
		return item, permissions, errors.New("workspace is disabled")
	}
	if !workspacePermissionAllowed(permissions, need) {
		return item, permissions, sql.ErrNoRows
	}
	return item, permissions, nil
}

func workspaceIDFromRequest(r *http.Request) (int64, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("workspaceId"))
	if raw == "" || raw == "0" {
		return 0, nil
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("bad workspace id")
	}
	return id, nil
}

func (a *App) workspaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var rows *sql.Rows
	var err error
	if isAdmin(r) {
		rows, err = a.DB.Query(`SELECT w.id,w.name,w.description,w.active,1,1,1,1 FROM workspaces w ORDER BY lower(w.name),w.id`)
	} else {
		rows, err = a.DB.Query(`SELECT w.id,w.name,w.description,w.active,m.can_use,m.can_create,m.can_edit,m.can_delete
			FROM workspaces w JOIN workspace_memberships m ON m.workspace_id=w.id
			WHERE m.user_id=? ORDER BY lower(w.name),w.id`, uid(r))
	}
	if err != nil {
		a.internalError(w, "workspaces", err)
		return
	}
	defer rows.Close()
	out := []workspaceItem{}
	for rows.Next() {
		var item workspaceItem
		var active, use, create, edit, del int
		if err := rows.Scan(&item.ID, &item.Name, &item.Description, &active, &use, &create, &edit, &del); err != nil {
			a.internalError(w, "workspaces", err)
			return
		}
		item.Active = active != 0
		item.CanUse, item.CanCreate, item.CanEdit, item.CanDelete = use != 0, create != 0, edit != 0, del != 0
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		a.internalError(w, "workspaces", err)
		return
	}
	jsonOut(w, http.StatusOK, out)
}

func (a *App) adminWorkspaces(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rows, err := a.DB.Query(`SELECT w.id,w.name,w.description,w.active,
			(SELECT COUNT(*) FROM workspace_memberships m WHERE m.workspace_id=w.id),
			(SELECT COUNT(*) FROM servers s WHERE s.workspace_id=w.id),
			(SELECT COUNT(*) FROM folders f WHERE f.workspace_id=w.id)
			FROM workspaces w ORDER BY lower(w.name),w.id`)
		if err != nil {
			a.internalError(w, "workspaces", err)
			return
		}
		defer rows.Close()
		out := []workspaceItem{}
		for rows.Next() {
			var item workspaceItem
			var active int
			if err := rows.Scan(&item.ID, &item.Name, &item.Description, &active, &item.MemberCount, &item.ServerCount, &item.FolderCount); err != nil {
				a.internalError(w, "workspaces", err)
				return
			}
			item.Active = active != 0
			item.workspacePermissions = fullWorkspacePermissions()
			out = append(out, item)
		}
		jsonOut(w, http.StatusOK, out)
	case http.MethodPost:
		var in workspaceMutation
		if decode(r, &in) != nil || normalizeWorkspaceInput(&in) != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "valid workspace name required"})
			return
		}
		active := true
		if in.Active != nil {
			active = *in.Active
		}
		description := ""
		if in.Description != nil {
			description = *in.Description
		}
		res, err := a.DB.Exec(`INSERT INTO workspaces(name,description,active,created_by) VALUES(?,?,?,?)`, in.Name, description, boolInt(active), uid(r))
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				jsonOut(w, http.StatusConflict, map[string]string{"error": "workspace name already exists"})
			} else {
				a.internalError(w, "workspaces", err)
			}
			return
		}
		id, _ := res.LastInsertId()
		a.audit(uid(r), "workspace.create", fmt.Sprintf("workspace=%d name=%s", id, in.Name))
		jsonOut(w, http.StatusCreated, map[string]any{"id": id, "name": in.Name, "description": description, "active": active})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *App) adminWorkspaceByID(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.URL.Path, "/api/admin/workspaces/")
	if err != nil || id <= 0 {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "bad workspace id"})
		return
	}
	var name, description string
	var active int
	if err := a.DB.QueryRow(`SELECT name,description,active FROM workspaces WHERE id=?`, id).Scan(&name, &description, &active); errors.Is(err, sql.ErrNoRows) {
		jsonOut(w, http.StatusNotFound, map[string]string{"error": "workspace not found"})
		return
	} else if err != nil {
		a.internalError(w, "workspaces", err)
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := a.DB.Query(`SELECT u.id,u.name,u.email,u.role,u.active,CASE WHEN m.user_id IS NULL THEN 0 ELSE 1 END,
			COALESCE(m.can_use,0),COALESCE(m.can_create,0),COALESCE(m.can_edit,0),COALESCE(m.can_delete,0)
			FROM users u LEFT JOIN workspace_memberships m ON m.user_id=u.id AND m.workspace_id=?
			WHERE u.role<>'admin' ORDER BY lower(u.name),lower(u.email),u.id`, id)
		if err != nil {
			a.internalError(w, "workspaces", err)
			return
		}
		defer rows.Close()
		members := []workspaceMember{}
		for rows.Next() {
			var item workspaceMember
			var userActive, assigned, use, create, edit, del int
			if err := rows.Scan(&item.UserID, &item.Name, &item.Email, &item.Role, &userActive, &assigned, &use, &create, &edit, &del); err != nil {
				a.internalError(w, "workspaces", err)
				return
			}
			item.Active, item.Assigned = userActive != 0, assigned != 0
			item.CanUse, item.CanCreate, item.CanEdit, item.CanDelete = use != 0, create != 0, edit != 0, del != 0
			members = append(members, item)
		}
		jsonOut(w, http.StatusOK, map[string]any{"id": id, "name": name, "description": description, "active": active != 0, "members": members})
	case http.MethodPatch:
		var in workspaceMutation
		if decode(r, &in) != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		if strings.TrimSpace(in.Name) == "" {
			in.Name = name
		}
		if err := normalizeWorkspaceInput(&in); err != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		newActive := active != 0
		if in.Active != nil {
			newActive = *in.Active
		}
		newDescription := description
		if in.Description != nil {
			newDescription = *in.Description
		}
		if _, err := a.DB.Exec(`UPDATE workspaces SET name=?,description=?,active=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, in.Name, newDescription, boolInt(newActive), id); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				jsonOut(w, http.StatusConflict, map[string]string{"error": "workspace name already exists"})
			} else {
				a.internalError(w, "workspaces", err)
			}
			return
		}
		if !newActive && active != 0 {
			a.terminateWorkspaceSessions(id, "workspace_disabled")
			a.terminateWorkspaceTransfers(id)
		}
		if (active != 0) != newActive {
			a.revalidateAllTemplateRuntimeAccess()
		}
		a.audit(uid(r), "workspace.update", fmt.Sprintf("workspace=%d name=%s active=%t", id, in.Name, newActive))
		jsonOut(w, http.StatusOK, map[string]any{"id": id, "name": in.Name, "description": newDescription, "active": newActive})
	case http.MethodDelete:
		var servers, folders int
		if err := a.DB.QueryRow(`SELECT (SELECT COUNT(*) FROM servers WHERE workspace_id=?),(SELECT COUNT(*) FROM folders WHERE workspace_id=?)`, id, id).Scan(&servers, &folders); err != nil {
			a.internalError(w, "workspaces", err)
			return
		}
		if (servers > 0 || folders > 0) && r.URL.Query().Get("force") != "1" {
			jsonOut(w, http.StatusConflict, map[string]any{"error": "workspace is not empty", "serverCount": servers, "folderCount": folders})
			return
		}
		a.terminateWorkspaceSessions(id, "workspace_deleted")
		a.terminateWorkspaceTransfers(id)
		if _, err := a.DB.Exec(`DELETE FROM workspaces WHERE id=?`, id); err != nil {
			a.internalError(w, "workspaces", err)
			return
		}
		a.revalidateAllTemplateRuntimeAccess()
		a.audit(uid(r), "workspace.delete", fmt.Sprintf("workspace=%d name=%s servers=%d folders=%d", id, name, servers, folders))
		jsonOut(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *App) adminWorkspaceMemberships(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		userID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("userId")), 10, 64)
		if err != nil || userID <= 0 {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "bad user id"})
			return
		}
		var userRole string
		if err := a.DB.QueryRow(`SELECT role FROM users WHERE id=?`, userID).Scan(&userRole); errors.Is(err, sql.ErrNoRows) {
			jsonOut(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		} else if err != nil {
			a.internalError(w, "workspaces", err)
			return
		}
		rows, err := a.DB.Query(`SELECT w.id,w.name,w.active,CASE WHEN m.user_id IS NULL THEN 0 ELSE 1 END,
			COALESCE(m.can_use,0),COALESCE(m.can_create,0),COALESCE(m.can_edit,0),COALESCE(m.can_delete,0)
			FROM workspaces w LEFT JOIN workspace_memberships m ON m.workspace_id=w.id AND m.user_id=?
			ORDER BY lower(w.name),w.id`, userID)
		if err != nil {
			a.internalError(w, "workspaces", err)
			return
		}
		defer rows.Close()
		out := []workspaceMembershipItem{}
		for rows.Next() {
			var item workspaceMembershipItem
			var active, assigned, use, create, edit, del int
			if err := rows.Scan(&item.WorkspaceID, &item.Name, &active, &assigned, &use, &create, &edit, &del); err != nil {
				a.internalError(w, "workspaces", err)
				return
			}
			item.Active, item.Assigned = active != 0, assigned != 0
			item.CanUse, item.CanCreate, item.CanEdit, item.CanDelete = use != 0, create != 0, edit != 0, del != 0
			out = append(out, item)
		}
		if err := rows.Err(); err != nil {
			a.internalError(w, "workspaces", err)
			return
		}
		jsonOut(w, http.StatusOK, map[string]any{"userId": userID, "admin": normalizeUserRole(userRole) == "admin", "workspaces": out})
	case http.MethodPatch:
		var in workspaceMembershipMutation
		if decode(r, &in) != nil || in.WorkspaceID <= 0 || in.UserID <= 0 {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		var userRole string
		if err := a.DB.QueryRow(`SELECT role FROM users WHERE id=?`, in.UserID).Scan(&userRole); errors.Is(err, sql.ErrNoRows) {
			jsonOut(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		} else if err != nil {
			a.internalError(w, "workspaces", err)
			return
		}
		if normalizeUserRole(userRole) == "admin" {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "administrator workspace permissions are implicit"})
			return
		}
		var exists int
		if err := a.DB.QueryRow(`SELECT COUNT(*) FROM workspaces WHERE id=?`, in.WorkspaceID).Scan(&exists); err != nil || exists == 0 {
			jsonOut(w, http.StatusNotFound, map[string]string{"error": "workspace not found"})
			return
		}
		var oldUse int
		_ = a.DB.QueryRow(`SELECT can_use FROM workspace_memberships WHERE workspace_id=? AND user_id=?`, in.WorkspaceID, in.UserID).Scan(&oldUse)
		if !in.Assigned {
			if _, err := a.DB.Exec(`DELETE FROM workspace_memberships WHERE workspace_id=? AND user_id=?`, in.WorkspaceID, in.UserID); err != nil {
				a.internalError(w, "workspaces", err)
				return
			}
		} else {
			if !anyWorkspacePermission(in.workspacePermissions) {
				in.CanUse = true
			}
			if _, err := a.DB.Exec(`INSERT INTO workspace_memberships(workspace_id,user_id,can_use,can_create,can_edit,can_delete) VALUES(?,?,?,?,?,?)
				ON CONFLICT(workspace_id,user_id) DO UPDATE SET can_use=excluded.can_use,can_create=excluded.can_create,can_edit=excluded.can_edit,can_delete=excluded.can_delete,updated_at=CURRENT_TIMESTAMP`,
				in.WorkspaceID, in.UserID, boolInt(in.CanUse), boolInt(in.CanCreate), boolInt(in.CanEdit), boolInt(in.CanDelete)); err != nil {
				a.internalError(w, "workspaces", err)
				return
			}
		}
		if !in.Assigned || (oldUse != 0 && !in.CanUse) {
			a.terminateUserWorkspaceSessions(in.UserID, in.WorkspaceID, "workspace_access_revoked")
			a.terminateUserWorkspaceTransfers(in.UserID, in.WorkspaceID)
		}
		// Workspace membership may be what grants access to one or more server
		// templates, so revalidate derived private connections as well.
		a.revalidateAllTemplateRuntimeAccess()
		a.audit(uid(r), "workspace.membership.update", fmt.Sprintf("workspace=%d user=%d assigned=%t use=%t create=%t edit=%t delete=%t", in.WorkspaceID, in.UserID, in.Assigned, in.CanUse, in.CanCreate, in.CanEdit, in.CanDelete))
		jsonOut(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

type serverSearchResult struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	Host          string `json:"host"`
	Username      string `json:"username,omitempty"`
	Kind          string `json:"kind"`
	WorkspaceID   *int64 `json:"workspaceId,omitempty"`
	WorkspaceName string `json:"workspaceName"`
	TemplateID    *int64 `json:"templateId,omitempty"`
	TemplateName  string `json:"templateName,omitempty"`
	CanUse        bool   `json:"canUse"`
	CanEdit       bool   `json:"canEdit"`
	CanDelete     bool   `json:"canDelete"`
}

func (a *App) serverSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		jsonOut(w, http.StatusOK, []serverSearchResult{})
		return
	}
	if len([]byte(q)) > 160 {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "search query is too long"})
		return
	}
	pattern := "%" + q + "%"
	var rows *sql.Rows
	var err error
	if isAdmin(r) {
		rows, err = a.DB.Query(`SELECT DISTINCT s.id FROM servers s LEFT JOIN workspaces w ON w.id=s.workspace_id
			WHERE (s.workspace_id IS NOT NULL OR (s.workspace_id IS NULL AND s.owner_user_id=?))
			AND (s.name LIKE ? COLLATE NOCASE OR s.host LIKE ? COLLATE NOCASE OR s.username LIKE ? COLLATE NOCASE)
			ORDER BY lower(s.name),s.id LIMIT 50`, uid(r), pattern, pattern, pattern)
	} else {
		rows, err = a.DB.Query(`SELECT DISTINCT s.id FROM servers s
			LEFT JOIN workspace_memberships m ON m.workspace_id=s.workspace_id AND m.user_id=?
			WHERE ((s.workspace_id IS NULL AND s.owner_user_id=?) OR
				(s.workspace_id IS NOT NULL AND m.user_id IS NOT NULL AND (m.can_use=1 OR m.can_create=1 OR m.can_edit=1 OR m.can_delete=1)))
			AND (s.name LIKE ? COLLATE NOCASE OR s.host LIKE ? COLLATE NOCASE OR s.username LIKE ? COLLATE NOCASE)
			ORDER BY lower(s.name),s.id LIMIT 50`, uid(r), uid(r), pattern, pattern, pattern)
	}
	if err != nil {
		a.internalError(w, "workspaces", err)
		return
	}
	defer rows.Close()
	ids := make([]int64, 0)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			a.internalError(w, "workspaces", err)
			return
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		a.internalError(w, "workspaces", err)
		return
	}
	out := make([]serverSearchResult, 0, len(ids))
	for _, id := range ids {
		s, _, err := a.loadServer(id)
		if err != nil {
			continue
		}
		if s.WorkspaceID == nil {
			if s.OwnerUserID != uid(r) {
				continue
			}
			s.CanUse, s.CanEdit, s.CanDelete = true, true, true
		} else {
			workspace, permissions, accessErr := a.requireWorkspacePermission(uid(r), *s.WorkspaceID, "read")
			if accessErr != nil {
				continue
			}
			s.WorkspaceName = workspace.Name
			s.CanUse, s.CanEdit, s.CanDelete = permissions.CanUse, permissions.CanEdit, permissions.CanDelete
			if !workspace.Active {
				s.CanUse, s.CanEdit, s.CanDelete = false, false, false
			}
		}
		a.decorateTemplateServerAccess(uid(r), role(r), &s)
		out = append(out, serverSearchResult{ID: s.ID, Name: s.Name, Host: s.Host, Username: s.Username, Kind: s.Kind, WorkspaceID: s.WorkspaceID, WorkspaceName: s.WorkspaceName, TemplateID: s.TemplateID, TemplateName: s.TemplateName, CanUse: s.CanUse, CanEdit: s.CanEdit, CanDelete: s.CanDelete})
	}
	jsonOut(w, http.StatusOK, out)
}
