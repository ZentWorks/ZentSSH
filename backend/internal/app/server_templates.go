package app

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

type serverTemplate struct {
	ID                 int64   `json:"id"`
	Name               string  `json:"name"`
	Host               string  `json:"host"`
	Port               int     `json:"port"`
	Color              string  `json:"color"`
	Kind               string  `json:"kind"`
	TerminalEditorMode string  `json:"terminalEditorMode"`
	CrontabEditorMode  string  `json:"crontabEditorMode"`
	JumpTemplateID     *int64  `json:"jumpTemplateId"`
	JumpTemplateName   string  `json:"jumpTemplateName,omitempty"`
	Description        string  `json:"description"`
	VisibleToAll       bool    `json:"visibleToAll"`
	Active             bool    `json:"active"`
	UserIDs            []int64 `json:"userIds,omitempty"`
	WorkspaceIDs       []int64 `json:"workspaceIds,omitempty"`
	UsageCount         int     `json:"usageCount,omitempty"`
	AdoptedServerID    *int64  `json:"adoptedServerId,omitempty"`
}

type serverTemplateMutation struct {
	Name               string  `json:"name"`
	Host               string  `json:"host"`
	Port               int     `json:"port"`
	Color              string  `json:"color"`
	Kind               string  `json:"kind"`
	TerminalEditorMode string  `json:"terminalEditorMode"`
	CrontabEditorMode  string  `json:"crontabEditorMode"`
	JumpTemplateID     *int64  `json:"jumpTemplateId"`
	Description        *string `json:"description,omitempty"`
	VisibleToAll       *bool   `json:"visibleToAll,omitempty"`
	Active             *bool   `json:"active,omitempty"`
	UserIDs            []int64 `json:"userIds,omitempty"`
	WorkspaceIDs       []int64 `json:"workspaceIds,omitempty"`
}

type serverTemplateUserAccessMutation struct {
	TemplateID int64 `json:"templateId"`
	UserID     int64 `json:"userId"`
	Assigned   bool  `json:"assigned"`
}

type serverTemplateUserAccessItem struct {
	UserID   int64  `json:"userId"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Active   bool   `json:"active"`
	Assigned bool   `json:"assigned"`
}

type serverTemplateAccessItem struct {
	TemplateID   int64  `json:"templateId"`
	Name         string `json:"name"`
	Active       bool   `json:"active"`
	VisibleToAll bool   `json:"visibleToAll"`
	Assigned     bool   `json:"assigned"`
	ViaWorkspace bool   `json:"viaWorkspace"`
}

func normalizeServerTemplate(in *serverTemplateMutation) error {
	in.Name = strings.TrimSpace(in.Name)
	in.Host = strings.TrimSpace(in.Host)
	if in.Description != nil {
		description := strings.TrimSpace(*in.Description)
		in.Description = &description
	}
	if in.Name == "" || len([]byte(in.Name)) > 120 {
		return errors.New("template name must contain 1-120 bytes")
	}
	if in.Host == "" || len([]byte(in.Host)) > 255 {
		return errors.New("template host is required")
	}
	if in.Port == 0 {
		in.Port = 22
	}
	if in.Port < 1 || in.Port > 65535 {
		return errors.New("template port must be between 1 and 65535")
	}
	if in.Color == "" {
		in.Color = "#5aa9ff"
	}
	if in.Kind == "" {
		in.Kind = "ssh"
	}
	if in.Kind != "ssh" {
		return errors.New("only SSH server templates are supported")
	}
	in.TerminalEditorMode = normalizeTerminalEditorMode(in.TerminalEditorMode)
	in.CrontabEditorMode = normalizeCrontabEditorMode(in.CrontabEditorMode)
	if in.Description != nil && len([]byte(*in.Description)) > 1000 {
		return errors.New("template description is too long")
	}
	return nil
}

func (a *App) loadServerTemplate(id int64) (serverTemplate, error) {
	var t serverTemplate
	var jump sql.NullInt64
	var jumpName sql.NullString
	var visible, active int
	err := a.DB.QueryRow(`SELECT t.id,t.name,t.host,t.port,t.color,t.kind,t.terminal_editor_mode,t.crontab_editor_mode,t.jump_template_id,COALESCE(j.name,''),t.description,t.visible_to_all,t.active,
		(SELECT COUNT(*) FROM servers s WHERE s.template_id=t.id)
		FROM server_templates t LEFT JOIN server_templates j ON j.id=t.jump_template_id WHERE t.id=?`, id).
		Scan(&t.ID, &t.Name, &t.Host, &t.Port, &t.Color, &t.Kind, &t.TerminalEditorMode, &t.CrontabEditorMode, &jump, &jumpName, &t.Description, &visible, &active, &t.UsageCount)
	if jump.Valid {
		t.JumpTemplateID = &jump.Int64
	}
	if jumpName.Valid {
		t.JumpTemplateName = jumpName.String
	}
	t.VisibleToAll = visible != 0
	t.Active = active != 0
	return t, err
}

func (a *App) serverTemplateVisibleToUser(userID int64, userRole string, templateID int64) (serverTemplate, bool, error) {
	t, err := a.loadServerTemplate(templateID)
	if err != nil {
		return t, false, err
	}
	if normalizeUserRole(userRole) == "admin" || t.VisibleToAll {
		return t, true, nil
	}
	var allowed int
	err = a.DB.QueryRow(`SELECT EXISTS(
		SELECT 1 FROM server_template_user_access a WHERE a.template_id=? AND a.user_id=?
		UNION ALL
		SELECT 1 FROM server_template_workspace_access a
		JOIN workspace_memberships m ON m.workspace_id=a.workspace_id
		JOIN workspaces w ON w.id=a.workspace_id AND w.active=1
		WHERE a.template_id=? AND m.user_id=? AND (m.can_use=1 OR m.can_create=1 OR m.can_edit=1 OR m.can_delete=1)
	)`, templateID, userID, templateID, userID).Scan(&allowed)
	if err != nil {
		return t, false, err
	}
	return t, allowed != 0, nil
}

func (a *App) publicServerTemplates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	rows, err := a.DB.Query(`SELECT id FROM server_templates ORDER BY lower(name),id`)
	if err != nil {
		a.internalError(w, "server_templates", err)
		return
	}
	defer rows.Close()
	out := []serverTemplate{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			a.internalError(w, "server_templates", err)
			return
		}
		t, visible, err := a.serverTemplateVisibleToUser(uid(r), role(r), id)
		if err != nil {
			a.internalError(w, "server_templates", err)
			return
		}
		if !visible {
			continue
		}
		var adopted sql.NullInt64
		if err := a.DB.QueryRow(`SELECT id FROM servers WHERE owner_user_id=? AND workspace_id IS NULL AND template_id=? LIMIT 1`, uid(r), id).Scan(&adopted); err != nil && !errors.Is(err, sql.ErrNoRows) {
			a.internalError(w, "server_templates", err)
			return
		}
		if adopted.Valid {
			t.AdoptedServerID = &adopted.Int64
		}
		// Access lists are administrative details and are never exposed here.
		t.UserIDs, t.WorkspaceIDs = nil, nil
		out = append(out, t)
	}
	jsonOut(w, http.StatusOK, out)
}

func (a *App) adminServerTemplateUserAccess(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if rawUserID := strings.TrimSpace(r.URL.Query().Get("userId")); rawUserID != "" {
			userID, err := strconv.ParseInt(rawUserID, 10, 64)
			if err != nil || userID <= 0 {
				jsonOut(w, http.StatusBadRequest, map[string]string{"error": "bad user id"})
				return
			}
			var userRole string
			if err := a.DB.QueryRow(`SELECT role FROM users WHERE id=?`, userID).Scan(&userRole); errors.Is(err, sql.ErrNoRows) {
				jsonOut(w, http.StatusNotFound, map[string]string{"error": "user not found"})
				return
			} else if err != nil {
				a.internalError(w, "server_templates", err)
				return
			}
			rows, err := a.DB.Query(`SELECT t.id,t.name,t.active,t.visible_to_all,
				CASE WHEN ua.user_id IS NULL THEN 0 ELSE 1 END,
				EXISTS(
					SELECT 1 FROM server_template_workspace_access wa
					JOIN workspace_memberships m ON m.workspace_id=wa.workspace_id AND m.user_id=?
					JOIN workspaces w ON w.id=wa.workspace_id AND w.active=1
					WHERE wa.template_id=t.id AND (m.can_use=1 OR m.can_create=1 OR m.can_edit=1 OR m.can_delete=1)
				)
				FROM server_templates t
				LEFT JOIN server_template_user_access ua ON ua.template_id=t.id AND ua.user_id=?
				ORDER BY CASE WHEN ua.user_id IS NULL THEN 1 ELSE 0 END,lower(t.name),t.id`, userID, userID)
			if err != nil {
				a.internalError(w, "server_templates", err)
				return
			}
			defer rows.Close()
			out := []serverTemplateAccessItem{}
			for rows.Next() {
				var item serverTemplateAccessItem
				var active, visible, assigned, viaWorkspace int
				if err := rows.Scan(&item.TemplateID, &item.Name, &active, &visible, &assigned, &viaWorkspace); err != nil {
					a.internalError(w, "server_templates", err)
					return
				}
				item.Active = active != 0
				item.VisibleToAll = visible != 0
				item.Assigned = assigned != 0
				item.ViaWorkspace = viaWorkspace != 0
				out = append(out, item)
			}
			if err := rows.Err(); err != nil {
				a.internalError(w, "server_templates", err)
				return
			}
			jsonOut(w, http.StatusOK, map[string]any{"userId": userID, "admin": normalizeUserRole(userRole) == "admin", "templates": out})
			return
		}

		templateID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("templateId")), 10, 64)
		if err != nil || templateID <= 0 {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "bad server template id"})
			return
		}
		template, err := a.loadServerTemplate(templateID)
		if errors.Is(err, sql.ErrNoRows) {
			jsonOut(w, http.StatusNotFound, map[string]string{"error": "server template not found"})
			return
		}
		if err != nil {
			a.internalError(w, "server_templates", err)
			return
		}
		rows, err := a.DB.Query(`SELECT u.id,u.name,u.email,u.active,CASE WHEN a.user_id IS NULL THEN 0 ELSE 1 END
			FROM users u LEFT JOIN server_template_user_access a ON a.user_id=u.id AND a.template_id=?
			WHERE u.role<>'admin'
			ORDER BY CASE WHEN a.user_id IS NULL THEN 1 ELSE 0 END,lower(u.name),lower(u.email),u.id`, templateID)
		if err != nil {
			a.internalError(w, "server_templates", err)
			return
		}
		defer rows.Close()
		out := []serverTemplateUserAccessItem{}
		for rows.Next() {
			var item serverTemplateUserAccessItem
			var active, assigned int
			if err := rows.Scan(&item.UserID, &item.Name, &item.Email, &active, &assigned); err != nil {
				a.internalError(w, "server_templates", err)
				return
			}
			item.Active, item.Assigned = active != 0, assigned != 0
			out = append(out, item)
		}
		if err := rows.Err(); err != nil {
			a.internalError(w, "server_templates", err)
			return
		}
		jsonOut(w, http.StatusOK, map[string]any{"templateId": templateID, "name": template.Name, "visibleToAll": template.VisibleToAll, "users": out})
	case http.MethodPatch:
		var in serverTemplateUserAccessMutation
		if decode(r, &in) != nil || in.TemplateID <= 0 || in.UserID <= 0 {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		if _, err := a.loadServerTemplate(in.TemplateID); errors.Is(err, sql.ErrNoRows) {
			jsonOut(w, http.StatusNotFound, map[string]string{"error": "server template not found"})
			return
		} else if err != nil {
			a.internalError(w, "server_templates", err)
			return
		}
		var userRole string
		if err := a.DB.QueryRow(`SELECT role FROM users WHERE id=?`, in.UserID).Scan(&userRole); errors.Is(err, sql.ErrNoRows) {
			jsonOut(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		} else if err != nil {
			a.internalError(w, "server_templates", err)
			return
		}
		if normalizeUserRole(userRole) == "admin" {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "administrator template access is implicit"})
			return
		}
		if in.Assigned {
			if _, err := a.DB.Exec(`INSERT INTO server_template_user_access(template_id,user_id) VALUES(?,?) ON CONFLICT(template_id,user_id) DO NOTHING`, in.TemplateID, in.UserID); err != nil {
				a.internalError(w, "server_templates", err)
				return
			}
		} else {
			if _, err := a.DB.Exec(`DELETE FROM server_template_user_access WHERE template_id=? AND user_id=?`, in.TemplateID, in.UserID); err != nil {
				a.internalError(w, "server_templates", err)
				return
			}
		}
		dependents, _ := a.dependentTemplateIDs(in.TemplateID)
		a.revalidateTemplateRuntimeAccess(in.TemplateID)
		for _, dependentID := range dependents {
			a.revalidateTemplateRuntimeAccess(dependentID)
		}
		a.audit(uid(r), "server_template.user_access.update", fmt.Sprintf("template=%d user=%d assigned=%t", in.TemplateID, in.UserID, in.Assigned))
		jsonOut(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *App) adminServerTemplates(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rows, err := a.DB.Query(`SELECT id FROM server_templates ORDER BY lower(name),id`)
		if err != nil {
			a.internalError(w, "server_templates", err)
			return
		}
		defer rows.Close()
		out := []serverTemplate{}
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				a.internalError(w, "server_templates", err)
				return
			}
			t, err := a.loadServerTemplate(id)
			if err != nil {
				a.internalError(w, "server_templates", err)
				return
			}
			t.UserIDs, err = a.serverTemplateUserIDs(id)
			if err != nil {
				a.internalError(w, "server_templates", err)
				return
			}
			t.WorkspaceIDs, err = a.serverTemplateWorkspaceIDs(id)
			if err != nil {
				a.internalError(w, "server_templates", err)
				return
			}
			out = append(out, t)
		}
		jsonOut(w, http.StatusOK, out)
	case http.MethodPost:
		var in serverTemplateMutation
		if decode(r, &in) != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		if err := normalizeServerTemplate(&in); err != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := a.validateTemplateJump(0, in.JumpTemplateID); err != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		description := ""
		if in.Description != nil {
			description = *in.Description
		}
		visible, active := true, true
		if in.VisibleToAll != nil {
			visible = *in.VisibleToAll
		}
		if in.Active != nil {
			active = *in.Active
		}
		tx, err := a.DB.Begin()
		if err != nil {
			a.internalError(w, "server_templates", err)
			return
		}
		defer tx.Rollback()
		res, err := tx.Exec(`INSERT INTO server_templates(name,host,port,color,kind,terminal_editor_mode,crontab_editor_mode,jump_template_id,description,visible_to_all,active,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
			in.Name, in.Host, in.Port, in.Color, in.Kind, in.TerminalEditorMode, in.CrontabEditorMode, in.JumpTemplateID, description, boolInt(visible), boolInt(active), uid(r))
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				jsonOut(w, http.StatusConflict, map[string]string{"error": "server template name already exists"})
			} else {
				a.internalError(w, "server_templates", err)
			}
			return
		}
		id, _ := res.LastInsertId()
		if err := replaceTemplateAccessTx(tx, id, in.UserIDs, in.WorkspaceIDs); err != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := tx.Commit(); err != nil {
			a.internalError(w, "server_templates", err)
			return
		}
		a.audit(uid(r), "server_template.create", fmt.Sprintf("template=%d name=%s", id, in.Name))
		t, _ := a.loadServerTemplate(id)
		jsonOut(w, http.StatusCreated, t)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *App) adminServerTemplateByID(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.URL.Path, "/api/admin/server-templates/")
	if err != nil || id <= 0 {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "bad server template id"})
		return
	}
	old, err := a.loadServerTemplate(id)
	if errors.Is(err, sql.ErrNoRows) {
		jsonOut(w, http.StatusNotFound, map[string]string{"error": "server template not found"})
		return
	}
	if err != nil {
		a.internalError(w, "server_templates", err)
		return
	}
	switch r.Method {
	case http.MethodGet:
		old.UserIDs, _ = a.serverTemplateUserIDs(id)
		old.WorkspaceIDs, _ = a.serverTemplateWorkspaceIDs(id)
		jsonOut(w, http.StatusOK, old)
	case http.MethodPatch:
		var in serverTemplateMutation
		if decode(r, &in) != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		if strings.TrimSpace(in.Name) == "" {
			in.Name = old.Name
		}
		if strings.TrimSpace(in.Host) == "" {
			in.Host = old.Host
		}
		if in.Port == 0 {
			in.Port = old.Port
		}
		if in.Color == "" {
			in.Color = old.Color
		}
		if in.Kind == "" {
			in.Kind = old.Kind
		}
		if in.TerminalEditorMode == "" {
			in.TerminalEditorMode = old.TerminalEditorMode
		}
		if in.CrontabEditorMode == "" {
			in.CrontabEditorMode = old.CrontabEditorMode
		}
		if err := normalizeServerTemplate(&in); err != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := a.validateTemplateJump(id, in.JumpTemplateID); err != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		newDescription := old.Description
		if in.Description != nil {
			newDescription = *in.Description
		}
		visible, active := old.VisibleToAll, old.Active
		if in.VisibleToAll != nil {
			visible = *in.VisibleToAll
		}
		if in.Active != nil {
			active = *in.Active
		}
		if in.UserIDs == nil {
			in.UserIDs, _ = a.serverTemplateUserIDs(id)
		}
		if in.WorkspaceIDs == nil {
			in.WorkspaceIDs, _ = a.serverTemplateWorkspaceIDs(id)
		}
		tx, err := a.DB.Begin()
		if err != nil {
			a.internalError(w, "server_templates", err)
			return
		}
		defer tx.Rollback()
		if _, err := tx.Exec(`UPDATE server_templates SET name=?,host=?,port=?,color=?,kind=?,terminal_editor_mode=?,crontab_editor_mode=?,jump_template_id=?,description=?,visible_to_all=?,active=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`,
			in.Name, in.Host, in.Port, in.Color, in.Kind, in.TerminalEditorMode, in.CrontabEditorMode, in.JumpTemplateID, newDescription, boolInt(visible), boolInt(active), id); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				jsonOut(w, http.StatusConflict, map[string]string{"error": "server template name already exists"})
			} else {
				a.internalError(w, "server_templates", err)
			}
			return
		}
		if err := replaceTemplateAccessTx(tx, id, in.UserIDs, in.WorkspaceIDs); err != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := syncTemplateDerivedServersTx(tx, id); err != nil {
			a.internalError(w, "server_templates", err)
			return
		}
		if err := tx.Commit(); err != nil {
			a.internalError(w, "server_templates", err)
			return
		}
		routeChanged := old.Host != in.Host || old.Port != in.Port || int64PtrValue(old.JumpTemplateID) != int64PtrValue(in.JumpTemplateID) || old.Kind != in.Kind
		dependents, _ := a.dependentTemplateIDs(id)
		if routeChanged {
			_, _ = a.DB.Exec(`DELETE FROM known_host_keys WHERE server_id IN (SELECT id FROM servers WHERE template_id=?)`, id)
			a.terminateTemplateSessions(id, "server_template_changed")
			a.terminateTemplateTransfers(id)
			for _, dependentID := range dependents {
				a.terminateTemplateSessions(dependentID, "jump_server_template_changed")
				a.terminateTemplateTransfers(dependentID)
			}
		} else if old.Active && !active {
			a.terminateTemplateSessions(id, "server_template_disabled")
			a.terminateTemplateTransfers(id)
		}
		// Access/activation changes can also invalidate templates that inherit this
		// template as their jump route.
		a.revalidateTemplateRuntimeAccess(id)
		for _, dependentID := range dependents {
			a.revalidateTemplateRuntimeAccess(dependentID)
		}
		a.audit(uid(r), "server_template.update", fmt.Sprintf("template=%d name=%s", id, in.Name))
		updated, _ := a.loadServerTemplate(id)
		updated.UserIDs, _ = a.serverTemplateUserIDs(id)
		updated.WorkspaceIDs, _ = a.serverTemplateWorkspaceIDs(id)
		jsonOut(w, http.StatusOK, updated)
	case http.MethodDelete:
		dependents, depErr := a.dependentTemplateIDs(id)
		if depErr != nil {
			a.internalError(w, "server_templates", depErr)
			return
		}
		if len(dependents) > 0 {
			jsonOut(w, http.StatusConflict, map[string]any{"error": "server template is used as a jump template", "dependentTemplateCount": len(dependents)})
			return
		}
		if old.UsageCount > 0 && r.URL.Query().Get("convert") != "1" {
			jsonOut(w, http.StatusConflict, map[string]any{"error": "server template is still used", "usageCount": old.UsageCount})
			return
		}
		if old.UsageCount > 0 {
			if old.JumpTemplateID != nil {
				missingJumpCount, checkErr := a.templateConversionMissingJumpCount(id, *old.JumpTemplateID)
				if checkErr != nil {
					a.internalError(w, "server_templates", checkErr)
					return
				}
				if missingJumpCount > 0 {
					jsonOut(w, http.StatusConflict, map[string]any{
						"error":         "server template cannot be converted while required jump template adoptions are missing",
						"code":          "missing_jump_template_adoption",
						"affectedCount": missingJumpCount,
					})
					return
				}
			}
			a.terminateTemplateSessions(id, "server_template_removed")
			a.terminateTemplateTransfers(id)
			tx, err := a.DB.Begin()
			if err != nil {
				a.internalError(w, "server_templates", err)
				return
			}
			defer tx.Rollback()
			if err := syncTemplateDerivedServersTx(tx, id); err != nil {
				a.internalError(w, "server_templates", err)
				return
			}
			if _, err := tx.Exec(`UPDATE servers SET template_id=NULL WHERE template_id=?`, id); err != nil {
				a.internalError(w, "server_templates", err)
				return
			}
			if _, err := tx.Exec(`DELETE FROM server_templates WHERE id=?`, id); err != nil {
				a.internalError(w, "server_templates", err)
				return
			}
			if err := tx.Commit(); err != nil {
				a.internalError(w, "server_templates", err)
				return
			}
		} else if _, err := a.DB.Exec(`DELETE FROM server_templates WHERE id=?`, id); err != nil {
			a.internalError(w, "server_templates", err)
			return
		}
		a.audit(uid(r), "server_template.delete", fmt.Sprintf("template=%d name=%s converted=%t", id, old.Name, old.UsageCount > 0))
		jsonOut(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *App) adoptServerTemplate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id, err := parseID(r.URL.Path, "/api/server-templates/")
	if err != nil || !strings.HasSuffix(strings.TrimRight(r.URL.Path, "/"), "/adopt") {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "bad server template id"})
		return
	}
	t, visible, err := a.serverTemplateVisibleToUser(uid(r), role(r), id)
	if errors.Is(err, sql.ErrNoRows) || !visible {
		jsonOut(w, http.StatusNotFound, map[string]string{"error": "server template not found"})
		return
	}
	if err != nil {
		a.internalError(w, "server_templates", err)
		return
	}
	if !t.Active {
		jsonOut(w, http.StatusConflict, map[string]string{"error": "server template is disabled"})
		return
	}
	var s Server
	if decode(r, &s) != nil {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if err := a.validatePersonalFolder(uid(r), s.FolderID); err != nil {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := a.prepareServerCredentials(uid(r), &s); err != nil {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if strings.TrimSpace(s.Username) == "" {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "username is required"})
		return
	}
	if s.CredentialProfileID != nil {
		p, _, _, _, err := a.loadCredentialProfileRaw(*s.CredentialProfileID)
		if err != nil || p.OwnerUserID != uid(r) {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "template-derived servers require your own credential profile"})
			return
		}
	}
	if s.CredentialProfileID == nil && strings.TrimSpace(s.Secret) == "" {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "personal server credentials are required"})
		return
	}
	enc := ""
	if s.CredentialProfileID == nil {
		enc, err = a.Box.Encrypt(s.Secret)
		if err != nil {
			jsonOut(w, http.StatusInternalServerError, map[string]string{"error": "credential encryption failed"})
			return
		}
	}
	var jumpServerID any
	if t.JumpTemplateID != nil {
		var jumpID int64
		if err := a.DB.QueryRow(`SELECT id FROM servers WHERE owner_user_id=? AND workspace_id IS NULL AND template_id=? LIMIT 1`, uid(r), *t.JumpTemplateID).Scan(&jumpID); err == nil {
			jumpServerID = jumpID
		} else {
			jumpServerID = nil
		}
	}
	res, err := a.DB.Exec(`INSERT INTO servers(owner_user_id,name,host,port,username,auth_type,secret_enc,folder_id,color,kind,credential_profile_id,jump_host_id,terminal_editor_mode,crontab_editor_mode,workspace_id,template_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,?)`,
		uid(r), t.Name, t.Host, t.Port, s.Username, s.AuthType, enc, s.FolderID, t.Color, t.Kind, s.CredentialProfileID, jumpServerID, t.TerminalEditorMode, t.CrontabEditorMode, t.ID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			jsonOut(w, http.StatusConflict, map[string]string{"error": "this server template has already been adopted"})
		} else {
			a.internalError(w, "server_templates", err)
		}
		return
	}
	serverID, _ := res.LastInsertId()
	a.audit(uid(r), "server_template.adopt", fmt.Sprintf("template=%d server=%d", t.ID, serverID))
	server, _, _ := a.loadServer(serverID)
	server.Secret = ""
	server.CanUse, server.CanCreate, server.CanEdit, server.CanDelete = true, true, true, true
	jsonOut(w, http.StatusCreated, server)
}

func (a *App) validateTemplateJump(templateID int64, jumpID *int64) error {
	if jumpID == nil {
		return nil
	}
	if *jumpID <= 0 || *jumpID == templateID {
		return errors.New("invalid jump template")
	}
	var nested sql.NullInt64
	var kind string
	if err := a.DB.QueryRow(`SELECT kind,jump_template_id FROM server_templates WHERE id=?`, *jumpID).Scan(&kind, &nested); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("jump template not found")
		}
		return err
	}
	if kind != "ssh" {
		return errors.New("only SSH templates can be used as jump templates")
	}
	if nested.Valid {
		return errors.New("nested jump templates are not supported")
	}
	return nil
}

func (a *App) templateConversionMissingJumpCount(templateID, jumpTemplateID int64) (int, error) {
	if templateID <= 0 || jumpTemplateID <= 0 {
		return 0, nil
	}
	var count int
	err := a.DB.QueryRow(`SELECT COUNT(*)
		FROM servers s
		WHERE s.template_id=?
		  AND NOT EXISTS (
			SELECT 1 FROM servers jump
			WHERE jump.owner_user_id=s.owner_user_id
			  AND jump.workspace_id IS NULL
			  AND jump.template_id=?
		  )`, templateID, jumpTemplateID).Scan(&count)
	return count, err
}

func (a *App) dependentTemplateIDs(templateID int64) ([]int64, error) {
	rows, err := a.DB.Query(`SELECT id FROM server_templates WHERE jump_template_id=? ORDER BY id`, templateID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (a *App) revalidateAllTemplateRuntimeAccess() {
	rows, err := a.DB.Query(`SELECT id FROM server_templates`)
	if err != nil {
		return
	}
	ids := []int64{}
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		a.revalidateTemplateRuntimeAccess(id)
	}
}

func (a *App) serverTemplateUserIDs(templateID int64) ([]int64, error) {
	rows, err := a.DB.Query(`SELECT user_id FROM server_template_user_access WHERE template_id=? ORDER BY user_id`, templateID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (a *App) serverTemplateWorkspaceIDs(templateID int64) ([]int64, error) {
	rows, err := a.DB.Query(`SELECT workspace_id FROM server_template_workspace_access WHERE template_id=? ORDER BY workspace_id`, templateID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func replaceTemplateAccessTx(tx *sql.Tx, templateID int64, userIDs, workspaceIDs []int64) error {
	if _, err := tx.Exec(`DELETE FROM server_template_user_access WHERE template_id=?`, templateID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM server_template_workspace_access WHERE template_id=?`, templateID); err != nil {
		return err
	}
	userSet := map[int64]bool{}
	for _, id := range userIDs {
		if id <= 0 || userSet[id] {
			continue
		}
		userSet[id] = true
		var role string
		if err := tx.QueryRow(`SELECT role FROM users WHERE id=?`, id).Scan(&role); err != nil {
			return fmt.Errorf("template user %d not found", id)
		}
		if normalizeUserRole(role) == "admin" {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO server_template_user_access(template_id,user_id) VALUES(?,?)`, templateID, id); err != nil {
			return err
		}
	}
	workspaceSet := map[int64]bool{}
	for _, id := range workspaceIDs {
		if id <= 0 || workspaceSet[id] {
			continue
		}
		workspaceSet[id] = true
		var one int
		if err := tx.QueryRow(`SELECT 1 FROM workspaces WHERE id=?`, id).Scan(&one); err != nil {
			return fmt.Errorf("template workspace %d not found", id)
		}
		if _, err := tx.Exec(`INSERT INTO server_template_workspace_access(template_id,workspace_id) VALUES(?,?)`, templateID, id); err != nil {
			return err
		}
	}
	return nil
}

func syncTemplateDerivedServersTx(tx *sql.Tx, templateID int64) error {
	// Keep snapshots current so a template can later be removed without losing the
	// last centrally managed connection data. Effective reads still use the live
	// template, so inheritance is immediate even before a user reloads the UI.
	_, err := tx.Exec(`UPDATE servers SET
		name=(SELECT name FROM server_templates WHERE id=?),
		host=(SELECT host FROM server_templates WHERE id=?),
		port=(SELECT port FROM server_templates WHERE id=?),
		color=(SELECT color FROM server_templates WHERE id=?),
		kind=(SELECT kind FROM server_templates WHERE id=?),
		terminal_editor_mode=(SELECT terminal_editor_mode FROM server_templates WHERE id=?),
		crontab_editor_mode=(SELECT crontab_editor_mode FROM server_templates WHERE id=?),
		jump_host_id=(SELECT js.id FROM server_templates t LEFT JOIN servers js ON js.owner_user_id=servers.owner_user_id AND js.workspace_id IS NULL AND js.template_id=t.jump_template_id WHERE t.id=? LIMIT 1)
		WHERE template_id=?`, templateID, templateID, templateID, templateID, templateID, templateID, templateID, templateID, templateID)
	return err
}

func (a *App) decorateTemplateServerAccess(userID int64, userRole string, server *Server) {
	if server == nil || server.TemplateID == nil {
		return
	}
	t, visible, err := a.serverTemplateVisibleToUser(userID, userRole, *server.TemplateID)
	if err != nil {
		server.TemplateAccessible = false
		server.TemplateActive = false
		server.CanUse = false
		return
	}
	server.TemplateAccessible = visible
	server.TemplateActive = t.Active
	server.TemplateName = t.Name
	if !visible || !t.Active || server.TemplateJumpMissing {
		server.CanUse = false
	}
}

func (a *App) revalidateTemplateRuntimeAccess(templateID int64) {
	if templateID <= 0 {
		return
	}
	type liveRef struct {
		id       string
		userID   int64
		serverID int64
	}
	a.mu.Lock()
	liveSnapshot := make([]liveRef, 0, len(a.live))
	for id, s := range a.live {
		liveSnapshot = append(liveSnapshot, liveRef{id: id, userID: s.UserID, serverID: s.ServerID})
	}
	a.mu.Unlock()
	for _, item := range liveSnapshot {
		if !a.serverUsesTemplate(item.serverID, templateID) {
			continue
		}
		if _, _, err := a.loadServerForUser(item.userID, item.serverID); err != nil {
			a.terminateLiveSession(item.id, "server_template_access_revoked")
		}
	}

	transfers := a.activeTransferSnapshot()
	for _, t := range transfers {
		if _, _, err := a.loadServerForUser(t.UserID, t.SourceServerID); err != nil {
			t.stop()
			continue
		}
		if _, _, err := a.loadServerForUser(t.UserID, t.TargetServerID); err != nil {
			t.stop()
		}
	}
}

func int64PtrValue(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}
