package app

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	maxSnippetNameBytes       = 120
	maxSnippetBodyBytes       = 64 * 1024
	maxSnippetFolderNameBytes = 120
)

type snippetPermissions struct {
	CanUse    bool `json:"canUse"`
	CanCreate bool `json:"canCreate"`
	CanEdit   bool `json:"canEdit"`
	CanDelete bool `json:"canDelete"`
}

type codeSnippet struct {
	ID          int64     `json:"id"`
	OwnerUserID int64     `json:"ownerUserId"`
	OwnerName   string    `json:"ownerName,omitempty"`
	Scope       string    `json:"scope"`
	FolderID    int64     `json:"folderId,omitempty"`
	FolderName  string    `json:"folderName,omitempty"`
	Name        string    `json:"name"`
	Content     string    `json:"content"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
	snippetPermissions
}

type snippetMutation struct {
	Scope    string `json:"scope"`
	FolderID *int64 `json:"folderId"`
	Name     string `json:"name"`
	Content  string `json:"content"`
}

type snippetFolder struct {
	ID          int64     `json:"id"`
	OwnerUserID int64     `json:"ownerUserId"`
	Scope       string    `json:"scope"`
	Name        string    `json:"name"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
	snippetPermissions
}

type snippetFolderMutation struct {
	Scope string `json:"scope"`
	Name  string `json:"name"`
}

type snippetFolderPermissionMutation struct {
	UserID   int64 `json:"userId"`
	FolderID int64 `json:"folderId"`
	Assigned bool  `json:"assigned"`
	snippetPermissions
}

type snippetFolderPermissionItem struct {
	FolderID int64  `json:"folderId"`
	Name     string `json:"name"`
	Assigned bool   `json:"assigned"`
	snippetPermissions
}

type snippetFolderPermissionUser struct {
	UserID   int64  `json:"userId"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Active   bool   `json:"active"`
	Assigned bool   `json:"assigned"`
	snippetPermissions
}

type snippetPermissionUser struct {
	UserID int64  `json:"userId"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	Active bool   `json:"active"`
	snippetPermissions
}

func normalizeSnippetScope(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "private":
		return "private"
	case "shared":
		return "shared"
	default:
		return ""
	}
}

func normalizeSnippetInput(name, content string) (string, string, error) {
	name = strings.TrimSpace(name)
	content = strings.ReplaceAll(strings.ReplaceAll(content, "\r\n", "\n"), "\r", "\n")
	if name == "" || len([]byte(name)) > maxSnippetNameBytes {
		return "", "", fmt.Errorf("snippet name must contain 1-%d bytes", maxSnippetNameBytes)
	}
	if strings.TrimSpace(content) == "" || len([]byte(content)) > maxSnippetBodyBytes {
		return "", "", fmt.Errorf("snippet content must contain 1-%d bytes", maxSnippetBodyBytes)
	}
	return name, content, nil
}

func normalizeSnippetFolderName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len([]byte(name)) > maxSnippetFolderNameBytes {
		return "", fmt.Errorf("folder name must contain 1-%d bytes", maxSnippetFolderNameBytes)
	}
	return name, nil
}

func fullSnippetPermissions() snippetPermissions {
	return snippetPermissions{CanUse: true, CanCreate: true, CanEdit: true, CanDelete: true}
}

func anySnippetPermission(p snippetPermissions) bool {
	return p.CanUse || p.CanCreate || p.CanEdit || p.CanDelete
}

func (a *App) folderPermissionsFor(folderID, userID int64, userRole string) (snippetFolder, snippetPermissions, error) {
	var folder snippetFolder
	err := a.DB.QueryRow(`SELECT id,COALESCE(owner_user_id,0),scope,name,created_at,updated_at FROM snippet_folders WHERE id=?`, folderID).
		Scan(&folder.ID, &folder.OwnerUserID, &folder.Scope, &folder.Name, &folder.CreatedAt, &folder.UpdatedAt)
	if err != nil {
		return folder, snippetPermissions{}, err
	}
	if folder.Scope == "private" {
		if folder.OwnerUserID != userID {
			return folder, snippetPermissions{}, sql.ErrNoRows
		}
		return folder, fullSnippetPermissions(), nil
	}
	if normalizeUserRole(userRole) == "admin" {
		return folder, fullSnippetPermissions(), nil
	}
	var use, create, edit, del int
	err = a.DB.QueryRow(`SELECT can_use,can_create,can_edit,can_delete FROM snippet_folder_permissions WHERE folder_id=? AND user_id=?`, folderID, userID).
		Scan(&use, &create, &edit, &del)
	if errors.Is(err, sql.ErrNoRows) {
		return folder, snippetPermissions{}, nil
	}
	if err != nil {
		return folder, snippetPermissions{}, err
	}
	return folder, snippetPermissions{CanUse: use != 0, CanCreate: create != 0, CanEdit: edit != 0, CanDelete: del != 0}, nil
}

func (a *App) validateSnippetFolder(scope string, folderID, userID int64, userRole string, need string) (snippetFolder, snippetPermissions, error) {
	if folderID <= 0 {
		if scope == "shared" {
			return snippetFolder{}, snippetPermissions{}, errors.New("shared snippets require a folder")
		}
		return snippetFolder{}, fullSnippetPermissions(), nil
	}
	folder, permissions, err := a.folderPermissionsFor(folderID, userID, userRole)
	if err != nil {
		return folder, permissions, err
	}
	if folder.Scope != scope {
		return folder, permissions, errors.New("snippet and folder scope must match")
	}
	allowed := scope == "private"
	if scope == "shared" {
		switch need {
		case "use":
			allowed = permissions.CanUse
		case "create":
			allowed = permissions.CanCreate
		case "edit":
			allowed = permissions.CanEdit
		case "delete":
			allowed = permissions.CanDelete
		case "read":
			allowed = anySnippetPermission(permissions)
		default:
			allowed = false
		}
	}
	if !allowed {
		return folder, permissions, errors.New("shared folder permission required")
	}
	return folder, permissions, nil
}

func (a *App) aggregateSnippetPermissions(userID int64, userRole string) (snippetPermissions, int, int, error) {
	if normalizeUserRole(userRole) == "admin" {
		var snippets, folders int
		if err := a.DB.QueryRow(`SELECT COUNT(*) FROM code_snippets WHERE scope='shared'`).Scan(&snippets); err != nil {
			return snippetPermissions{}, 0, 0, err
		}
		if err := a.DB.QueryRow(`SELECT COUNT(*) FROM snippet_folders WHERE scope='shared'`).Scan(&folders); err != nil {
			return snippetPermissions{}, 0, 0, err
		}
		return fullSnippetPermissions(), snippets, folders, nil
	}
	var use, create, edit, del, folders int
	err := a.DB.QueryRow(`SELECT
		COALESCE(MAX(p.can_use),0),COALESCE(MAX(p.can_create),0),COALESCE(MAX(p.can_edit),0),COALESCE(MAX(p.can_delete),0),COUNT(*)
		FROM snippet_folder_permissions p JOIN snippet_folders f ON f.id=p.folder_id
		WHERE p.user_id=? AND f.scope='shared' AND (p.can_use=1 OR p.can_create=1 OR p.can_edit=1 OR p.can_delete=1)`, userID).
		Scan(&use, &create, &edit, &del, &folders)
	if err != nil {
		return snippetPermissions{}, 0, 0, err
	}
	var snippets int
	err = a.DB.QueryRow(`SELECT COUNT(*) FROM code_snippets s
		JOIN snippet_folder_permissions p ON p.folder_id=s.folder_id
		WHERE s.scope='shared' AND p.user_id=? AND p.can_use=1`, userID).Scan(&snippets)
	if err != nil {
		return snippetPermissions{}, 0, 0, err
	}
	return snippetPermissions{CanUse: use != 0, CanCreate: create != 0, CanEdit: edit != 0, CanDelete: del != 0}, snippets, folders, nil
}

func (a *App) codeSnippetPermissions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	permissions, sharedCount, sharedFolderCount, err := a.aggregateSnippetPermissions(uid(r), role(r))
	if err != nil {
		a.internalError(w, "snippets", err)
		return
	}
	jsonOut(w, http.StatusOK, map[string]any{
		"canUse": permissions.CanUse, "canCreate": permissions.CanCreate, "canEdit": permissions.CanEdit, "canDelete": permissions.CanDelete,
		"sharedCount": sharedCount, "sharedFolderCount": sharedFolderCount,
	})
}

func scanSnippetRows(a *App, rows *sql.Rows) ([]codeSnippet, error) {
	out := []codeSnippet{}
	for rows.Next() {
		var snippet codeSnippet
		var contentEnc string
		var use, create, edit, del int
		if err := rows.Scan(&snippet.ID, &snippet.OwnerUserID, &snippet.OwnerName, &snippet.Scope, &snippet.FolderID, &snippet.FolderName, &snippet.Name, &contentEnc, &snippet.CreatedAt, &snippet.UpdatedAt, &use, &create, &edit, &del); err != nil {
			return nil, err
		}
		snippet.CanUse, snippet.CanCreate, snippet.CanEdit, snippet.CanDelete = use != 0, create != 0, edit != 0, del != 0
		if snippet.Scope == "private" || snippet.CanUse || snippet.CanEdit {
			content, err := a.Box.Decrypt(contentEnc)
			if err != nil {
				return nil, errors.New("could not decrypt code snippet")
			}
			snippet.Content = content
		}
		out = append(out, snippet)
	}
	return out, rows.Err()
}

func (a *App) codeSnippets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		scope := normalizeSnippetScope(r.URL.Query().Get("scope"))
		if scope == "" {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid snippet scope"})
			return
		}
		var rows *sql.Rows
		var err error
		if scope == "private" {
			rows, err = a.DB.Query(`SELECT s.id,COALESCE(s.owner_user_id,0),COALESCE(u.name,''),s.scope,COALESCE(s.folder_id,0),COALESCE(f.name,''),s.name,s.content_enc,s.created_at,s.updated_at,1,1,1,1
				FROM code_snippets s LEFT JOIN users u ON u.id=s.owner_user_id LEFT JOIN snippet_folders f ON f.id=s.folder_id
				WHERE s.scope='private' AND s.owner_user_id=? ORDER BY COALESCE(lower(f.name),''),lower(s.name),s.id`, uid(r))
		} else if normalizeUserRole(role(r)) == "admin" {
			rows, err = a.DB.Query(`SELECT s.id,COALESCE(s.owner_user_id,0),COALESCE(u.name,''),s.scope,COALESCE(s.folder_id,0),COALESCE(f.name,''),s.name,s.content_enc,s.created_at,s.updated_at,1,1,1,1
				FROM code_snippets s LEFT JOIN users u ON u.id=s.owner_user_id LEFT JOIN snippet_folders f ON f.id=s.folder_id
				WHERE s.scope='shared' ORDER BY COALESCE(lower(f.name),''),lower(s.name),s.id`)
		} else {
			rows, err = a.DB.Query(`SELECT s.id,COALESCE(s.owner_user_id,0),COALESCE(u.name,''),s.scope,COALESCE(s.folder_id,0),COALESCE(f.name,''),s.name,s.content_enc,s.created_at,s.updated_at,p.can_use,p.can_create,p.can_edit,p.can_delete
				FROM code_snippets s JOIN snippet_folders f ON f.id=s.folder_id JOIN snippet_folder_permissions p ON p.folder_id=f.id
				LEFT JOIN users u ON u.id=s.owner_user_id
				WHERE s.scope='shared' AND p.user_id=? AND (p.can_use=1 OR p.can_create=1 OR p.can_edit=1 OR p.can_delete=1)
				ORDER BY lower(f.name),lower(s.name),s.id`, uid(r))
		}
		if err != nil {
			a.internalError(w, "snippets", err)
			return
		}
		defer rows.Close()
		out, err := scanSnippetRows(a, rows)
		if err != nil {
			a.internalError(w, "snippets", err)
			return
		}
		jsonOut(w, http.StatusOK, out)
	case http.MethodPost:
		var in snippetMutation
		if decode(r, &in) != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		in.Scope = normalizeSnippetScope(in.Scope)
		if in.Scope == "" {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid snippet scope"})
			return
		}
		name, content, err := normalizeSnippetInput(in.Name, in.Content)
		if err != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		folderID := int64(0)
		if in.FolderID != nil {
			folderID = *in.FolderID
		}
		if _, _, err = a.validateSnippetFolder(in.Scope, folderID, uid(r), role(r), "create"); err != nil {
			status := http.StatusBadRequest
			if in.Scope == "shared" {
				status = http.StatusForbidden
			}
			jsonOut(w, status, map[string]string{"error": err.Error()})
			return
		}
		contentEnc, err := a.Box.Encrypt(content)
		if err != nil {
			jsonOut(w, http.StatusInternalServerError, map[string]string{"error": "could not encrypt code snippet"})
			return
		}
		var folder any
		if folderID > 0 {
			folder = folderID
		}
		res, err := a.DB.Exec(`INSERT INTO code_snippets(owner_user_id,scope,folder_id,name,content_enc) VALUES(?,?,?,?,?)`, uid(r), in.Scope, folder, name, contentEnc)
		if err != nil {
			a.internalError(w, "snippets", err)
			return
		}
		id, _ := res.LastInsertId()
		a.audit(uid(r), "snippet.create", fmt.Sprintf("snippet=%d scope=%s folder=%d", id, in.Scope, folderID))
		jsonOut(w, http.StatusCreated, map[string]any{"id": id, "scope": in.Scope, "folderId": folderID, "name": name, "content": content})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func parseSnippetPath(raw string) (int64, string, error) {
	tail := strings.Trim(strings.TrimPrefix(raw, "/api/code-snippets/"), "/")
	if tail == "" {
		return 0, "", errors.New("missing snippet id")
	}
	parts := strings.Split(tail, "/")
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || id <= 0 {
		return 0, "", errors.New("invalid snippet id")
	}
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	if len(parts) > 2 {
		return 0, "", errors.New("invalid snippet path")
	}
	return id, action, nil
}

func (a *App) loadSnippet(id int64) (codeSnippet, error) {
	var snippet codeSnippet
	var contentEnc string
	err := a.DB.QueryRow(`SELECT s.id,COALESCE(s.owner_user_id,0),COALESCE(u.name,''),s.scope,COALESCE(s.folder_id,0),COALESCE(f.name,''),s.name,s.content_enc,s.created_at,s.updated_at
		FROM code_snippets s LEFT JOIN users u ON u.id=s.owner_user_id LEFT JOIN snippet_folders f ON f.id=s.folder_id WHERE s.id=?`, id).
		Scan(&snippet.ID, &snippet.OwnerUserID, &snippet.OwnerName, &snippet.Scope, &snippet.FolderID, &snippet.FolderName, &snippet.Name, &contentEnc, &snippet.CreatedAt, &snippet.UpdatedAt)
	if err != nil {
		return snippet, err
	}
	snippet.Content, err = a.Box.Decrypt(contentEnc)
	return snippet, err
}

func (a *App) codeSnippetByID(w http.ResponseWriter, r *http.Request) {
	id, action, err := parseSnippetPath(r.URL.Path)
	if err != nil {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	snippet, err := a.loadSnippet(id)
	if errors.Is(err, sql.ErrNoRows) {
		jsonOut(w, http.StatusNotFound, map[string]string{"error": "snippet not found"})
		return
	}
	if err != nil {
		a.internalError(w, "snippets", err)
		return
	}
	var permissions snippetPermissions
	if snippet.Scope == "private" {
		if snippet.OwnerUserID != uid(r) {
			jsonOut(w, http.StatusNotFound, map[string]string{"error": "snippet not found"})
			return
		}
		permissions = fullSnippetPermissions()
	} else {
		_, permissions, err = a.folderPermissionsFor(snippet.FolderID, uid(r), role(r))
		if err != nil {
			a.internalError(w, "snippets", err)
			return
		}
	}

	if action == "use" {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if snippet.Scope == "shared" && !permissions.CanUse {
			jsonOut(w, http.StatusForbidden, map[string]string{"error": "shared folder use permission required"})
			return
		}
		a.audit(uid(r), "snippet.use", fmt.Sprintf("snippet=%d scope=%s folder=%d", snippet.ID, snippet.Scope, snippet.FolderID))
		jsonOut(w, http.StatusOK, map[string]any{"id": snippet.ID, "scope": snippet.Scope, "folderId": snippet.FolderID, "name": snippet.Name, "content": snippet.Content})
		return
	}
	if action != "" {
		jsonOut(w, http.StatusNotFound, map[string]string{"error": "unknown snippet action"})
		return
	}

	switch r.Method {
	case http.MethodPatch:
		if snippet.Scope == "shared" && !permissions.CanEdit {
			jsonOut(w, http.StatusForbidden, map[string]string{"error": "shared folder edit permission required"})
			return
		}
		var in snippetMutation
		if decode(r, &in) != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		name, content, err := normalizeSnippetInput(in.Name, in.Content)
		if err != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		targetFolderID := snippet.FolderID
		if in.FolderID != nil {
			targetFolderID = *in.FolderID
		}
		if snippet.Scope == "shared" && targetFolderID <= 0 {
			targetFolderID = snippet.FolderID
		}
		if targetFolderID != snippet.FolderID {
			if snippet.Scope == "private" {
				if _, _, err := a.validateSnippetFolder("private", targetFolderID, uid(r), role(r), "edit"); err != nil {
					jsonOut(w, http.StatusForbidden, map[string]string{"error": "target folder permission required"})
					return
				}
			} else {
				targetFolder, targetPermissions, err := a.folderPermissionsFor(targetFolderID, uid(r), role(r))
				if err != nil || targetFolder.Scope != "shared" || !(targetPermissions.CanCreate || targetPermissions.CanEdit) {
					jsonOut(w, http.StatusForbidden, map[string]string{"error": "target folder permission required"})
					return
				}
			}
		}
		contentEnc, err := a.Box.Encrypt(content)
		if err != nil {
			jsonOut(w, http.StatusInternalServerError, map[string]string{"error": "could not encrypt code snippet"})
			return
		}
		var folder any
		if targetFolderID > 0 {
			folder = targetFolderID
		}
		if _, err := a.DB.Exec(`UPDATE code_snippets SET name=?,content_enc=?,folder_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, name, contentEnc, folder, id); err != nil {
			a.internalError(w, "snippets", err)
			return
		}
		a.audit(uid(r), "snippet.update", fmt.Sprintf("snippet=%d scope=%s folder=%d", id, snippet.Scope, targetFolderID))
		jsonOut(w, http.StatusOK, map[string]any{"id": id, "scope": snippet.Scope, "folderId": targetFolderID, "name": name, "content": content})
	case http.MethodDelete:
		if snippet.Scope == "shared" && !permissions.CanDelete {
			jsonOut(w, http.StatusForbidden, map[string]string{"error": "shared folder delete permission required"})
			return
		}
		if _, err := a.DB.Exec(`DELETE FROM code_snippets WHERE id=?`, id); err != nil {
			a.internalError(w, "snippets", err)
			return
		}
		a.audit(uid(r), "snippet.delete", fmt.Sprintf("snippet=%d scope=%s folder=%d", id, snippet.Scope, snippet.FolderID))
		jsonOut(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *App) snippetFolders(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		scope := normalizeSnippetScope(r.URL.Query().Get("scope"))
		if scope == "" {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid folder scope"})
			return
		}
		out := []snippetFolder{}
		if scope == "private" {
			rows, err := a.DB.Query(`SELECT id,COALESCE(owner_user_id,0),scope,name,created_at,updated_at FROM snippet_folders WHERE scope='private' AND owner_user_id=? ORDER BY lower(name),id`, uid(r))
			if err != nil {
				a.internalError(w, "snippets", err)
				return
			}
			defer rows.Close()
			for rows.Next() {
				var f snippetFolder
				if err := rows.Scan(&f.ID, &f.OwnerUserID, &f.Scope, &f.Name, &f.CreatedAt, &f.UpdatedAt); err != nil {
					a.internalError(w, "snippets", err)
					return
				}
				f.snippetPermissions = fullSnippetPermissions()
				out = append(out, f)
			}
			if err := rows.Err(); err != nil {
				a.internalError(w, "snippets", err)
				return
			}
		} else if normalizeUserRole(role(r)) == "admin" {
			rows, err := a.DB.Query(`SELECT id,COALESCE(owner_user_id,0),scope,name,created_at,updated_at FROM snippet_folders WHERE scope='shared' ORDER BY lower(name),id`)
			if err != nil {
				a.internalError(w, "snippets", err)
				return
			}
			defer rows.Close()
			for rows.Next() {
				var f snippetFolder
				if err := rows.Scan(&f.ID, &f.OwnerUserID, &f.Scope, &f.Name, &f.CreatedAt, &f.UpdatedAt); err != nil {
					a.internalError(w, "snippets", err)
					return
				}
				f.snippetPermissions = fullSnippetPermissions()
				out = append(out, f)
			}
			if err := rows.Err(); err != nil {
				a.internalError(w, "snippets", err)
				return
			}
		} else {
			rows, err := a.DB.Query(`SELECT f.id,COALESCE(f.owner_user_id,0),f.scope,f.name,f.created_at,f.updated_at,p.can_use,p.can_create,p.can_edit,p.can_delete
				FROM snippet_folders f JOIN snippet_folder_permissions p ON p.folder_id=f.id
				WHERE f.scope='shared' AND p.user_id=? AND (p.can_use=1 OR p.can_create=1 OR p.can_edit=1 OR p.can_delete=1)
				ORDER BY lower(f.name),f.id`, uid(r))
			if err != nil {
				a.internalError(w, "snippets", err)
				return
			}
			defer rows.Close()
			for rows.Next() {
				var f snippetFolder
				var use, create, edit, del int
				if err := rows.Scan(&f.ID, &f.OwnerUserID, &f.Scope, &f.Name, &f.CreatedAt, &f.UpdatedAt, &use, &create, &edit, &del); err != nil {
					a.internalError(w, "snippets", err)
					return
				}
				f.CanUse, f.CanCreate, f.CanEdit, f.CanDelete = use != 0, create != 0, edit != 0, del != 0
				out = append(out, f)
			}
			if err := rows.Err(); err != nil {
				a.internalError(w, "snippets", err)
				return
			}
		}
		jsonOut(w, http.StatusOK, out)
	case http.MethodPost:
		var in snippetFolderMutation
		if decode(r, &in) != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		in.Scope = normalizeSnippetScope(in.Scope)
		name, err := normalizeSnippetFolderName(in.Name)
		if in.Scope == "" || err != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid folder"})
			return
		}
		if in.Scope == "shared" && normalizeUserRole(role(r)) != "admin" {
			jsonOut(w, http.StatusForbidden, map[string]string{"error": "administrator required to create shared folders"})
			return
		}
		var owner any = uid(r)
		if in.Scope == "shared" {
			owner = nil
		}
		res, err := a.DB.Exec(`INSERT INTO snippet_folders(owner_user_id,scope,name) VALUES(?,?,?)`, owner, in.Scope, name)
		if err != nil {
			a.internalError(w, "snippets", err)
			return
		}
		id, _ := res.LastInsertId()
		a.audit(uid(r), "snippet.folder.create", fmt.Sprintf("folder=%d scope=%s", id, in.Scope))
		jsonOut(w, http.StatusCreated, map[string]any{"id": id, "scope": in.Scope, "name": name})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func parseSnippetFolderPath(raw string) (int64, error) {
	tail := strings.Trim(strings.TrimPrefix(raw, "/api/snippet-folders/"), "/")
	id, err := strconv.ParseInt(tail, 10, 64)
	if err != nil || id <= 0 || strings.Contains(tail, "/") {
		return 0, errors.New("invalid folder id")
	}
	return id, nil
}

func (a *App) snippetFolderByID(w http.ResponseWriter, r *http.Request) {
	id, err := parseSnippetFolderPath(r.URL.Path)
	if err != nil {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	folder, _, err := a.folderPermissionsFor(id, uid(r), role(r))
	if errors.Is(err, sql.ErrNoRows) {
		jsonOut(w, http.StatusNotFound, map[string]string{"error": "folder not found"})
		return
	}
	if err != nil {
		a.internalError(w, "snippets", err)
		return
	}
	if folder.Scope == "shared" && normalizeUserRole(role(r)) != "admin" {
		jsonOut(w, http.StatusForbidden, map[string]string{"error": "administrator required to manage shared folders"})
		return
	}
	switch r.Method {
	case http.MethodPatch:
		var in snippetFolderMutation
		if decode(r, &in) != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		name, err := normalizeSnippetFolderName(in.Name)
		if err != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if _, err := a.DB.Exec(`UPDATE snippet_folders SET name=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, name, id); err != nil {
			a.internalError(w, "snippets", err)
			return
		}
		a.audit(uid(r), "snippet.folder.update", fmt.Sprintf("folder=%d scope=%s", id, folder.Scope))
		jsonOut(w, http.StatusOK, map[string]any{"id": id, "scope": folder.Scope, "name": name})
	case http.MethodDelete:
		var count int
		if err := a.DB.QueryRow(`SELECT COUNT(*) FROM code_snippets WHERE folder_id=?`, id).Scan(&count); err != nil {
			a.internalError(w, "snippets", err)
			return
		}
		if folder.Scope == "shared" && count > 0 {
			jsonOut(w, http.StatusConflict, map[string]string{"error": "folder is not empty"})
			return
		}
		tx, err := a.DB.Begin()
		if err != nil {
			a.internalError(w, "snippets", err)
			return
		}
		defer tx.Rollback()
		if folder.Scope == "private" && count > 0 {
			if _, err := tx.Exec(`UPDATE code_snippets SET folder_id=NULL,updated_at=CURRENT_TIMESTAMP WHERE folder_id=?`, id); err != nil {
				a.internalError(w, "snippets", err)
				return
			}
		}
		if _, err := tx.Exec(`DELETE FROM snippet_folders WHERE id=?`, id); err != nil {
			a.internalError(w, "snippets", err)
			return
		}
		if err := tx.Commit(); err != nil {
			a.internalError(w, "snippets", err)
			return
		}
		a.audit(uid(r), "snippet.folder.delete", fmt.Sprintf("folder=%d scope=%s", id, folder.Scope))
		jsonOut(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *App) adminSnippetFolderPermissions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if rawFolderID := strings.TrimSpace(r.URL.Query().Get("folderId")); rawFolderID != "" {
			folderID, err := strconv.ParseInt(rawFolderID, 10, 64)
			if err != nil || folderID <= 0 {
				jsonOut(w, http.StatusBadRequest, map[string]string{"error": "bad folder id"})
				return
			}
			var folderName, scope string
			if err := a.DB.QueryRow(`SELECT name,scope FROM snippet_folders WHERE id=?`, folderID).Scan(&folderName, &scope); errors.Is(err, sql.ErrNoRows) {
				jsonOut(w, http.StatusNotFound, map[string]string{"error": "folder not found"})
				return
			} else if err != nil {
				a.internalError(w, "snippets", err)
				return
			}
			if scope != "shared" {
				jsonOut(w, http.StatusBadRequest, map[string]string{"error": "shared folder required"})
				return
			}
			rows, err := a.DB.Query(`SELECT u.id,u.name,u.email,u.active,CASE WHEN p.user_id IS NULL THEN 0 ELSE 1 END,
				COALESCE(p.can_use,0),COALESCE(p.can_create,0),COALESCE(p.can_edit,0),COALESCE(p.can_delete,0)
				FROM users u LEFT JOIN snippet_folder_permissions p ON p.user_id=u.id AND p.folder_id=?
				WHERE u.role<>'admin'
				ORDER BY CASE WHEN p.user_id IS NULL THEN 1 ELSE 0 END,lower(u.name),lower(u.email),u.id`, folderID)
			if err != nil {
				a.internalError(w, "snippets", err)
				return
			}
			defer rows.Close()
			out := []snippetFolderPermissionUser{}
			for rows.Next() {
				var item snippetFolderPermissionUser
				var active, assigned, use, create, edit, del int
				if err := rows.Scan(&item.UserID, &item.Name, &item.Email, &active, &assigned, &use, &create, &edit, &del); err != nil {
					a.internalError(w, "snippets", err)
					return
				}
				item.Active, item.Assigned = active != 0, assigned != 0
				item.CanUse, item.CanCreate, item.CanEdit, item.CanDelete = use != 0, create != 0, edit != 0, del != 0
				out = append(out, item)
			}
			if err := rows.Err(); err != nil {
				a.internalError(w, "snippets", err)
				return
			}
			jsonOut(w, http.StatusOK, map[string]any{"folderId": folderID, "name": folderName, "users": out})
			return
		}
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
			a.internalError(w, "snippets", err)
			return
		}
		rows, err := a.DB.Query(`SELECT f.id,f.name,CASE WHEN p.user_id IS NULL THEN 0 ELSE 1 END,COALESCE(p.can_use,0),COALESCE(p.can_create,0),COALESCE(p.can_edit,0),COALESCE(p.can_delete,0)
			FROM snippet_folders f LEFT JOIN snippet_folder_permissions p ON p.folder_id=f.id AND p.user_id=?
			WHERE f.scope='shared' ORDER BY lower(f.name),f.id`, userID)
		if err != nil {
			a.internalError(w, "snippets", err)
			return
		}
		defer rows.Close()
		out := []snippetFolderPermissionItem{}
		for rows.Next() {
			var item snippetFolderPermissionItem
			var assigned, use, create, edit, del int
			if err := rows.Scan(&item.FolderID, &item.Name, &assigned, &use, &create, &edit, &del); err != nil {
				a.internalError(w, "snippets", err)
				return
			}
			item.Assigned = assigned != 0
			item.CanUse, item.CanCreate, item.CanEdit, item.CanDelete = use != 0, create != 0, edit != 0, del != 0
			out = append(out, item)
		}
		jsonOut(w, http.StatusOK, map[string]any{"userId": userID, "admin": normalizeUserRole(userRole) == "admin", "folders": out})
	case http.MethodPatch:
		var in snippetFolderPermissionMutation
		if decode(r, &in) != nil || in.UserID <= 0 || in.FolderID <= 0 {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		var userRole, scope string
		if err := a.DB.QueryRow(`SELECT role FROM users WHERE id=?`, in.UserID).Scan(&userRole); errors.Is(err, sql.ErrNoRows) {
			jsonOut(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		} else if err != nil {
			a.internalError(w, "snippets", err)
			return
		}
		if normalizeUserRole(userRole) == "admin" {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "administrator permissions are implicit"})
			return
		}
		if err := a.DB.QueryRow(`SELECT scope FROM snippet_folders WHERE id=?`, in.FolderID).Scan(&scope); errors.Is(err, sql.ErrNoRows) {
			jsonOut(w, http.StatusNotFound, map[string]string{"error": "folder not found"})
			return
		} else if err != nil {
			a.internalError(w, "snippets", err)
			return
		}
		if scope != "shared" {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "shared folder required"})
			return
		}
		if !in.Assigned {
			if _, err := a.DB.Exec(`DELETE FROM snippet_folder_permissions WHERE folder_id=? AND user_id=?`, in.FolderID, in.UserID); err != nil {
				a.internalError(w, "snippets", err)
				return
			}
		} else {
			if !anySnippetPermission(in.snippetPermissions) {
				in.CanUse = true
			}
			_, err := a.DB.Exec(`INSERT INTO snippet_folder_permissions(folder_id,user_id,can_use,can_create,can_edit,can_delete) VALUES(?,?,?,?,?,?)
				ON CONFLICT(folder_id,user_id) DO UPDATE SET can_use=excluded.can_use,can_create=excluded.can_create,can_edit=excluded.can_edit,can_delete=excluded.can_delete`,
				in.FolderID, in.UserID, boolInt(in.CanUse), boolInt(in.CanCreate), boolInt(in.CanEdit), boolInt(in.CanDelete))
			if err != nil {
				a.internalError(w, "snippets", err)
				return
			}
		}
		a.audit(uid(r), "snippet.folder.permissions.update", fmt.Sprintf("user=%d folder=%d assigned=%t use=%t create=%t edit=%t delete=%t", in.UserID, in.FolderID, in.Assigned, in.CanUse, in.CanCreate, in.CanEdit, in.CanDelete))
		jsonOut(w, http.StatusOK, map[string]any{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// Legacy aggregate permission endpoints remain available for API compatibility.
func (a *App) adminCodeSnippetPermissions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	rows, err := a.DB.Query(`SELECT id,name,email,role,active FROM users WHERE role<>'admin' ORDER BY lower(name),lower(email),id`)
	if err != nil {
		a.internalError(w, "snippets", err)
		return
	}
	defer rows.Close()
	out := []snippetPermissionUser{}
	for rows.Next() {
		var item snippetPermissionUser
		var active int
		if err := rows.Scan(&item.UserID, &item.Name, &item.Email, &item.Role, &active); err != nil {
			a.internalError(w, "snippets", err)
			return
		}
		item.Active = active != 0
		p, _, _, err := a.aggregateSnippetPermissions(item.UserID, item.Role)
		if err != nil {
			a.internalError(w, "snippets", err)
			return
		}
		item.snippetPermissions = p
		out = append(out, item)
	}
	jsonOut(w, http.StatusOK, out)
}

func (a *App) adminCodeSnippetPermissionByUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id, err := parseID(r.URL.Path, "/api/admin/snippet-permissions/")
	if err != nil || id <= 0 {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "bad user id"})
		return
	}
	var userRole string
	if err := a.DB.QueryRow(`SELECT role FROM users WHERE id=?`, id).Scan(&userRole); errors.Is(err, sql.ErrNoRows) {
		jsonOut(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	} else if err != nil {
		a.internalError(w, "snippets", err)
		return
	}
	if normalizeUserRole(userRole) == "admin" {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "administrator permissions are implicit"})
		return
	}
	var in snippetPermissions
	if decode(r, &in) != nil {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	_, err = a.DB.Exec(`INSERT INTO snippet_folder_permissions(folder_id,user_id,can_use,can_create,can_edit,can_delete)
		SELECT id,?,?,?,?,? FROM snippet_folders WHERE scope='shared'
		ON CONFLICT(folder_id,user_id) DO UPDATE SET can_use=excluded.can_use,can_create=excluded.can_create,can_edit=excluded.can_edit,can_delete=excluded.can_delete`,
		id, boolInt(in.CanUse), boolInt(in.CanCreate), boolInt(in.CanEdit), boolInt(in.CanDelete))
	if err != nil {
		a.internalError(w, "snippets", err)
		return
	}
	a.audit(uid(r), "snippet.permissions.update.legacy", fmt.Sprintf("user=%d", id))
	jsonOut(w, http.StatusOK, map[string]any{"userId": id, "canUse": in.CanUse, "canCreate": in.CanCreate, "canEdit": in.CanEdit, "canDelete": in.CanDelete})
}
