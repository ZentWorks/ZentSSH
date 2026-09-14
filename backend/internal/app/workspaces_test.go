package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	zcrypto "zentssh.local/backend/internal/crypto"
	zdb "zentssh.local/backend/internal/db"
)

func workspaceTestApp(t *testing.T) (*App, int64, int64, int64) {
	t.Helper()
	database, err := zdb.Open(t.TempDir() + "/zentssh-workspaces.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	box, err := zcrypto.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	addUser := func(name, email, role string) int64 {
		res, err := database.Exec("INSERT INTO users(name,email,password_hash,role,active) VALUES(?,?,?,?,1)", name, email, hashPass("very-secret-password"), role)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	return &App{DB: database, Box: box}, addUser("Admin", "admin@example.test", "admin"), addUser("One", "one@example.test", "user"), addUser("Two", "two@example.test", "user")
}

func requestAs(method, target, body string, userID int64, userRole string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	ctx := context.WithValue(req.Context(), userCtxKey{}, userID)
	ctx = context.WithValue(ctx, roleCtxKey{}, userRole)
	return req.WithContext(ctx)
}

func TestWorkspacePermissionsGateSharedServer(t *testing.T) {
	a, adminID, one, two := workspaceTestApp(t)
	workspaceRes, err := a.DB.Exec(`INSERT INTO workspaces(name,created_by) VALUES('Production',?)`, adminID)
	if err != nil {
		t.Fatal(err)
	}
	workspaceID, _ := workspaceRes.LastInsertId()
	if _, err := a.DB.Exec(`INSERT INTO workspace_memberships(workspace_id,user_id,can_use,can_create,can_edit,can_delete) VALUES(?,?,1,0,0,0)`, workspaceID, one); err != nil {
		t.Fatal(err)
	}
	serverRes, err := a.DB.Exec(`INSERT INTO servers(owner_user_id,name,host,username,workspace_id) VALUES(?,?,?,?,?)`, adminID, "prod-db-1", "10.0.0.10", "shared", workspaceID)
	if err != nil {
		t.Fatal(err)
	}
	serverID, _ := serverRes.LastInsertId()

	if _, _, err := a.loadServerForPermission(one, serverID, "use"); err != nil {
		t.Fatalf("workspace use permission rejected: %v", err)
	}
	if _, _, err := a.loadServerForPermission(one, serverID, "edit"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("workspace edit unexpectedly allowed: %v", err)
	}
	if _, _, err := a.loadServerForPermission(two, serverID, "read"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unassigned user unexpectedly sees workspace server: %v", err)
	}
	if _, err := a.DB.Exec(`UPDATE workspace_memberships SET can_edit=1 WHERE workspace_id=? AND user_id=?`, workspaceID, one); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.loadServerForPermission(one, serverID, "edit"); err != nil {
		t.Fatalf("workspace edit permission rejected after grant: %v", err)
	}
}

func TestWorkspaceListAndSearchOnlyExposeAssignedScopes(t *testing.T) {
	a, adminID, one, two := workspaceTestApp(t)
	production, _ := a.DB.Exec(`INSERT INTO workspaces(name,created_by) VALUES('Production',?)`, adminID)
	staging, _ := a.DB.Exec(`INSERT INTO workspaces(name,created_by) VALUES('Staging',?)`, adminID)
	prodID, _ := production.LastInsertId()
	stageID, _ := staging.LastInsertId()
	_, _ = a.DB.Exec(`INSERT INTO workspace_memberships(workspace_id,user_id,can_use) VALUES(?,?,1)`, prodID, one)
	_, _ = a.DB.Exec(`INSERT INTO workspace_memberships(workspace_id,user_id,can_use) VALUES(?,?,1)`, stageID, two)
	_, _ = a.DB.Exec(`INSERT INTO servers(owner_user_id,name,host,username) VALUES(?,?,?,?)`, one, "Personal Match", "personal.example", "one")
	_, _ = a.DB.Exec(`INSERT INTO servers(owner_user_id,name,host,username,workspace_id) VALUES(?,?,?,?,?)`, adminID, "Production Match", "prod.example", "shared", prodID)
	_, _ = a.DB.Exec(`INSERT INTO servers(owner_user_id,name,host,username,workspace_id) VALUES(?,?,?,?,?)`, adminID, "Staging Match", "stage.example", "shared", stageID)

	rec := httptest.NewRecorder()
	a.serverSearch(rec, requestAs(http.MethodGet, "/api/server-search?q=Match", "", one, "user"))
	if rec.Code != http.StatusOK {
		t.Fatalf("search status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Personal Match") || !strings.Contains(body, "Production Match") || strings.Contains(body, "Staging Match") {
		t.Fatalf("unexpected scoped search response: %s", body)
	}
}

func TestWorkspaceJumpHostMustStayInSameScope(t *testing.T) {
	a, adminID, one, _ := workspaceTestApp(t)
	workspaceRes, _ := a.DB.Exec(`INSERT INTO workspaces(name,created_by) VALUES('Production',?)`, adminID)
	workspaceID, _ := workspaceRes.LastInsertId()
	_, _ = a.DB.Exec(`INSERT INTO workspace_memberships(workspace_id,user_id,can_use,can_edit) VALUES(?,?,0,1)`, workspaceID, one)
	personalRes, _ := a.DB.Exec(`INSERT INTO servers(owner_user_id,name,host,username) VALUES(?,?,?,?)`, one, "Personal Jump", "jump.local", "one")
	personalID, _ := personalRes.LastInsertId()
	workspaceJumpRes, _ := a.DB.Exec(`INSERT INTO servers(owner_user_id,name,host,username,workspace_id) VALUES(?,?,?,?,?)`, adminID, "Workspace Jump", "jump.prod", "shared", workspaceID)
	workspaceJumpID, _ := workspaceJumpRes.LastInsertId()

	if err := a.validateJumpHostForServer(one, 0, workspaceID, &personalID); err == nil {
		t.Fatal("personal jump host accepted for workspace server")
	}
	if err := a.validateJumpHostForServer(one, 0, workspaceID, &workspaceJumpID); err != nil {
		t.Fatalf("same-workspace jump host rejected: %v", err)
	}
}

func TestDeletingCreatorKeepsWorkspaceResources(t *testing.T) {
	a, adminID, one, _ := workspaceTestApp(t)
	workspaceRes, _ := a.DB.Exec(`INSERT INTO workspaces(name,created_by) VALUES('Production',?)`, adminID)
	workspaceID, _ := workspaceRes.LastInsertId()
	folderRes, _ := a.DB.Exec(`INSERT INTO folders(owner_user_id,name,workspace_id) VALUES(?,?,?)`, one, "Shared Folder", workspaceID)
	folderID, _ := folderRes.LastInsertId()
	serverRes, _ := a.DB.Exec(`INSERT INTO servers(owner_user_id,name,host,username,workspace_id,folder_id) VALUES(?,?,?,?,?,?)`, one, "Shared Server", "prod.example", "shared", workspaceID, folderID)
	serverID, _ := serverRes.LastInsertId()

	rec := httptest.NewRecorder()
	a.adminUserByID(rec, requestAs(http.MethodDelete, "/api/admin/users/"+itoa(one), "", adminID, "admin"))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete user status=%d body=%s", rec.Code, rec.Body.String())
	}
	var serverOwner, serverWorkspace int64
	if err := a.DB.QueryRow(`SELECT owner_user_id,workspace_id FROM servers WHERE id=?`, serverID).Scan(&serverOwner, &serverWorkspace); err != nil {
		t.Fatalf("shared server was deleted: %v", err)
	}
	if serverOwner != adminID || serverWorkspace != workspaceID {
		t.Fatalf("shared server owner/workspace=%d/%d want=%d/%d", serverOwner, serverWorkspace, adminID, workspaceID)
	}
	var folderOwner int64
	if err := a.DB.QueryRow(`SELECT owner_user_id FROM folders WHERE id=?`, folderID).Scan(&folderOwner); err != nil {
		t.Fatalf("shared folder was deleted: %v", err)
	}
	if folderOwner != adminID {
		t.Fatalf("shared folder owner=%d want=%d", folderOwner, adminID)
	}
}

func TestDeletingUsedJumpHostIsBlocked(t *testing.T) {
	a, _, one, _ := workspaceTestApp(t)
	jumpRes, err := a.DB.Exec(`INSERT INTO servers(owner_user_id,name,host,username) VALUES(?,?,?,?)`, one, "Personal Jump", "jump.example", "one")
	if err != nil {
		t.Fatal(err)
	}
	jumpID, _ := jumpRes.LastInsertId()
	targetRes, err := a.DB.Exec(`INSERT INTO servers(owner_user_id,name,host,username,jump_host_id) VALUES(?,?,?,?,?)`, one, "Target", "target.example", "one", jumpID)
	if err != nil {
		t.Fatal(err)
	}
	targetID, _ := targetRes.LastInsertId()

	rec := httptest.NewRecorder()
	a.serverByID(rec, requestAs(http.MethodDelete, "/api/servers/"+itoa(jumpID), "", one, "user"))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "jump_host_in_use") {
		t.Fatalf("used jump host delete status=%d body=%s", rec.Code, rec.Body.String())
	}
	var storedJump sql.NullInt64
	if err := a.DB.QueryRow(`SELECT jump_host_id FROM servers WHERE id=?`, targetID).Scan(&storedJump); err != nil {
		t.Fatal(err)
	}
	if !storedJump.Valid || storedJump.Int64 != jumpID {
		t.Fatalf("dependent server silently lost jump host: %+v", storedJump)
	}
}

func TestDeletingTemplateJumpAdoptionUsedDynamicallyIsBlocked(t *testing.T) {
	a, _, one, _ := workspaceTestApp(t)
	jumpTemplateID := insertTemplate(t, a, "Jump Template", "jump.example", true, true, nil)
	targetTemplateID := insertTemplate(t, a, "Target Template", "target.example", true, true, &jumpTemplateID)
	jumpServerID := insertDerivedServer(t, a, one, jumpTemplateID, "jump snapshot", "old-jump")
	_ = insertDerivedServer(t, a, one, targetTemplateID, "target snapshot", "old-target")

	rec := httptest.NewRecorder()
	a.serverByID(rec, requestAs(http.MethodDelete, "/api/servers/"+itoa(jumpServerID), "", one, "user"))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "jump_host_in_use") {
		t.Fatalf("dynamic template jump delete status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSharedCredentialProfileCannotBecomePrivateWhileWorkspaceServerUsesIt(t *testing.T) {
	a, adminID, one, _ := workspaceTestApp(t)
	profileRes, err := a.DB.Exec(`INSERT INTO credential_profiles(owner_user_id,name,username,auth_type,secret_enc,shared) VALUES(?,?,?,?,?,1)`, one, "Workspace Login", "deploy", "password", "encrypted-placeholder")
	if err != nil {
		t.Fatal(err)
	}
	profileID, _ := profileRes.LastInsertId()
	workspaceRes, _ := a.DB.Exec(`INSERT INTO workspaces(name,created_by) VALUES('Production',?)`, adminID)
	workspaceID, _ := workspaceRes.LastInsertId()
	if _, err := a.DB.Exec(`INSERT INTO servers(owner_user_id,name,host,username,workspace_id,credential_profile_id) VALUES(?,?,?,?,?,?)`, adminID, "Shared Server", "prod.example", "deploy", workspaceID, profileID); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	a.credentialProfileByID(rec, requestAs(http.MethodPatch, "/api/credential-profiles/"+itoa(profileID), `{"name":"Workspace Login","username":"deploy","authType":"password","shared":false}`, one, "user"))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "credential_profile_used_by_workspace") {
		t.Fatalf("unshare used workspace credential status=%d body=%s", rec.Code, rec.Body.String())
	}
	var shared int
	if err := a.DB.QueryRow(`SELECT shared FROM credential_profiles WHERE id=?`, profileID).Scan(&shared); err != nil {
		t.Fatal(err)
	}
	if shared != 1 {
		t.Fatal("blocked credential profile update still changed shared state")
	}
}

func TestAdminWorkspaceMembershipsListsAllWorkspacesAndPreservesRights(t *testing.T) {
	a, adminID, one, _ := workspaceTestApp(t)
	prodRes, err := a.DB.Exec(`INSERT INTO workspaces(name,created_by) VALUES('Production',?)`, adminID)
	if err != nil {
		t.Fatal(err)
	}
	stageRes, err := a.DB.Exec(`INSERT INTO workspaces(name,created_by) VALUES('Staging',?)`, adminID)
	if err != nil {
		t.Fatal(err)
	}
	prodID, _ := prodRes.LastInsertId()
	stageID, _ := stageRes.LastInsertId()
	if _, err := a.DB.Exec(`INSERT INTO workspace_memberships(workspace_id,user_id,can_use,can_create,can_edit,can_delete) VALUES(?,?,1,0,1,0)`, prodID, one); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	a.adminWorkspaceMemberships(rec, requestAs(http.MethodGet, "/api/admin/workspace-memberships?userId="+itoa(one), "", adminID, "admin"))
	if rec.Code != http.StatusOK {
		t.Fatalf("workspace membership GET status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		UserID     int64                     `json:"userId"`
		Admin      bool                      `json:"admin"`
		Workspaces []workspaceMembershipItem `json:"workspaces"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.UserID != one || response.Admin || len(response.Workspaces) != 2 {
		t.Fatalf("unexpected workspace membership response: %+v", response)
	}
	byID := map[int64]workspaceMembershipItem{}
	for _, item := range response.Workspaces {
		byID[item.WorkspaceID] = item
	}
	prod := byID[prodID]
	if !prod.Assigned || !prod.CanUse || !prod.CanEdit || prod.CanCreate || prod.CanDelete {
		t.Fatalf("production membership rights changed: %+v", prod)
	}
	stage := byID[stageID]
	if stage.Assigned || stage.CanUse || stage.CanCreate || stage.CanEdit || stage.CanDelete {
		t.Fatalf("unassigned staging workspace has rights: %+v", stage)
	}
}

func TestAdminWorkspaceMembershipNewAssignmentDefaultsToUseOnly(t *testing.T) {
	a, adminID, one, _ := workspaceTestApp(t)
	workspaceRes, err := a.DB.Exec(`INSERT INTO workspaces(name,created_by) VALUES('Production',?)`, adminID)
	if err != nil {
		t.Fatal(err)
	}
	workspaceID, _ := workspaceRes.LastInsertId()

	rec := httptest.NewRecorder()
	body := `{"workspaceId":` + itoa(workspaceID) + `,"userId":` + itoa(one) + `,"assigned":true,"canUse":false,"canCreate":false,"canEdit":false,"canDelete":false}`
	a.adminWorkspaceMemberships(rec, requestAs(http.MethodPatch, "/api/admin/workspace-memberships", body, adminID, "admin"))
	if rec.Code != http.StatusOK {
		t.Fatalf("workspace membership PATCH status=%d body=%s", rec.Code, rec.Body.String())
	}
	var use, create, edit, del int
	if err := a.DB.QueryRow(`SELECT can_use,can_create,can_edit,can_delete FROM workspace_memberships WHERE workspace_id=? AND user_id=?`, workspaceID, one).Scan(&use, &create, &edit, &del); err != nil {
		t.Fatal(err)
	}
	if use != 1 || create != 0 || edit != 0 || del != 0 {
		t.Fatalf("new membership rights=%d/%d/%d/%d want use-only", use, create, edit, del)
	}
}
