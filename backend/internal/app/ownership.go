package app

import (
	"database/sql"
	"errors"
)

// loadServerForUser is the authorization boundary for operations that actively
// use a server (SSH, SFTP, crontab, status/connect checks and transfers). It
// deliberately returns sql.ErrNoRows for inaccessible resources so callers do
// not leak whether an id exists in another user's scope.
func (a *App) loadServerForUser(userID, serverID int64) (Server, string, error) {
	return a.loadServerForPermission(userID, serverID, "use")
}

func (a *App) loadServerForPermission(userID, serverID int64, need string) (Server, string, error) {
	server, secret, err := a.loadServer(serverID)
	if err != nil {
		return server, "", err
	}
	if server.WorkspaceID == nil {
		if server.OwnerUserID != userID {
			return Server{}, "", sql.ErrNoRows
		}
		server.CanUse, server.CanCreate, server.CanEdit, server.CanDelete = true, true, true, true
	} else {
		workspace, permissions, accessErr := a.requireWorkspacePermission(userID, *server.WorkspaceID, need)
		if accessErr != nil {
			if errors.Is(accessErr, sql.ErrNoRows) {
				return Server{}, "", sql.ErrNoRows
			}
			return Server{}, "", accessErr
		}
		server.WorkspaceName = workspace.Name
		server.CanUse, server.CanCreate, server.CanEdit, server.CanDelete = permissions.CanUse, permissions.CanCreate, permissions.CanEdit, permissions.CanDelete
	}

	if need == "use" && server.TemplateID != nil {
		userRole, roleErr := a.roleForUser(userID)
		if roleErr != nil {
			return Server{}, "", roleErr
		}
		t, visible, templateErr := a.serverTemplateVisibleToUser(userID, userRole, *server.TemplateID)
		if templateErr != nil {
			if errors.Is(templateErr, sql.ErrNoRows) {
				return Server{}, "", sql.ErrNoRows
			}
			return Server{}, "", templateErr
		}
		server.TemplateAccessible = visible
		server.TemplateActive = t.Active
		if !visible {
			return Server{}, "", errors.New("server template access has been revoked")
		}
		if !t.Active {
			return Server{}, "", errors.New("server template is disabled")
		}
		if server.TemplateJumpMissing {
			return Server{}, "", errors.New("the required jump server template has not been adopted yet")
		}
	}
	if need == "use" && server.JumpHostID != nil {
		rawJump, _, rawErr := a.loadServer(*server.JumpHostID)
		if rawErr != nil || rawJump.JumpHostID != nil {
			return Server{}, "", errors.New("jump host is not available")
		}
		jump, _, jumpErr := a.loadServerForPermission(userID, *server.JumpHostID, "use")
		if jumpErr != nil {
			return Server{}, "", errors.New("jump host is not available")
		}
		if !sameServerScope(server, jump) {
			return Server{}, "", errors.New("jump host is not available in this server scope")
		}
	}
	return server, secret, nil
}

func (a *App) serverVisibleToUser(userID, serverID int64) (Server, error) {
	server, _, err := a.loadServerForPermission(userID, serverID, "read")
	return server, err
}

func (a *App) folderAccessForUser(userID, folderID int64, need string) (Folder, error) {
	if folderID <= 0 || userID <= 0 {
		return Folder{}, sql.ErrNoRows
	}
	var folder Folder
	var parent, workspace sql.NullInt64
	if err := a.DB.QueryRow(`SELECT id,owner_user_id,name,parent_id,sort_order,workspace_id FROM folders WHERE id=?`, folderID).
		Scan(&folder.ID, &folder.OwnerUserID, &folder.Name, &parent, &folder.SortOrder, &workspace); err != nil {
		return Folder{}, err
	}
	if parent.Valid {
		value := parent.Int64
		folder.ParentID = &value
	}
	if workspace.Valid {
		folder.WorkspaceID = &workspace.Int64
		item, permissions, err := a.requireWorkspacePermission(userID, workspace.Int64, need)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return Folder{}, sql.ErrNoRows
			}
			return Folder{}, err
		}
		folder.WorkspaceName = item.Name
		folder.CanUse, folder.CanCreate, folder.CanEdit, folder.CanDelete = permissions.CanUse, permissions.CanCreate, permissions.CanEdit, permissions.CanDelete
		return folder, nil
	}
	if folder.OwnerUserID != userID {
		return Folder{}, sql.ErrNoRows
	}
	folder.CanUse, folder.CanCreate, folder.CanEdit, folder.CanDelete = true, true, true, true
	return folder, nil
}

func (a *App) folderOwnedByUser(userID, folderID int64) (bool, error) {
	folder, err := a.folderAccessForUser(userID, folderID, "read")
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return folder.WorkspaceID == nil && err == nil, err
}

func (a *App) validatePersonalFolder(userID int64, folderID *int64) error {
	return a.validateFolderForScope(userID, 0, folderID, "read")
}

func (a *App) validateFolderForUser(userID int64, folderID *int64) error {
	return a.validatePersonalFolder(userID, folderID)
}

func (a *App) validateFolderForScope(userID, workspaceID int64, folderID *int64, need string) error {
	if folderID == nil {
		return nil
	}
	folder, err := a.folderAccessForUser(userID, *folderID, need)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("folder not found")
		}
		return err
	}
	if workspaceID == 0 {
		if folder.WorkspaceID != nil || folder.OwnerUserID != userID {
			return errors.New("folder not found")
		}
		return nil
	}
	if folder.WorkspaceID == nil || *folder.WorkspaceID != workspaceID {
		return errors.New("folder belongs to another workspace")
	}
	return nil
}

func sameServerScope(a, b Server) bool {
	if a.WorkspaceID != nil || b.WorkspaceID != nil {
		return a.WorkspaceID != nil && b.WorkspaceID != nil && *a.WorkspaceID == *b.WorkspaceID
	}
	return a.OwnerUserID == b.OwnerUserID
}

func (a *App) validateJumpHostForServer(userID, serverID, workspaceID int64, jumpID *int64) error {
	if jumpID == nil {
		return nil
	}
	if serverID != 0 && *jumpID == serverID {
		return errors.New("a server cannot use itself as jump host")
	}
	jump, err := a.serverVisibleToUser(userID, *jumpID)
	if err != nil {
		return errors.New("jump host not found")
	}
	if workspaceID == 0 {
		if jump.WorkspaceID != nil || jump.OwnerUserID != userID {
			return errors.New("jump host not found")
		}
	} else if jump.WorkspaceID == nil || *jump.WorkspaceID != workspaceID {
		return errors.New("jump host must belong to the same workspace")
	}
	if jump.Kind != "ssh" {
		return errors.New("only SSH servers can be used as jump hosts")
	}
	if jump.JumpHostID != nil {
		return errors.New("nested jump hosts are not supported in this version")
	}
	if serverID != 0 {
		var reverse sql.NullInt64
		if err := a.DB.QueryRow(`SELECT jump_host_id FROM servers WHERE id=?`, *jumpID).Scan(&reverse); err == nil && reverse.Valid && reverse.Int64 == serverID {
			return errors.New("jump host cycle detected")
		}
	}
	return nil
}

func (a *App) validateJumpHostForQuickConnect(userID int64, jumpID *int64) error {
	if jumpID == nil {
		return nil
	}
	jump, _, err := a.loadServerForUser(userID, *jumpID)
	if err != nil {
		return errors.New("jump host not found")
	}
	if jump.Kind != "ssh" {
		return errors.New("only SSH servers can be used as jump hosts")
	}
	if jump.JumpHostID != nil {
		return errors.New("nested jump hosts are not supported in this version")
	}
	return nil
}

// Backwards-compatible wrapper used by older call sites until their scope is
// known. It intentionally means a private/personal server scope.
func (a *App) validateJumpHostForUser(userID, serverID int64, jumpID *int64) error {
	return a.validateJumpHostForServer(userID, serverID, 0, jumpID)
}

func (a *App) serverJumpDependencyCount(serverID int64) (int, error) {
	if serverID <= 0 {
		return 0, nil
	}
	var count int
	err := a.DB.QueryRow(`SELECT COUNT(*) FROM (
		SELECT s.id FROM servers s WHERE s.jump_host_id=? AND s.id<>?
		UNION
		SELECT s.id
		FROM servers s
		JOIN server_templates t ON t.id=s.template_id
		JOIN servers jump ON jump.id=?
		WHERE s.id<>jump.id
		  AND s.workspace_id IS NULL
		  AND jump.workspace_id IS NULL
		  AND s.owner_user_id=jump.owner_user_id
		  AND jump.template_id IS NOT NULL
		  AND t.jump_template_id=jump.template_id
	)`, serverID, serverID, serverID).Scan(&count)
	return count, err
}
