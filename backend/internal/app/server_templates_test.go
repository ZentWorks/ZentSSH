package app

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func insertTemplate(t *testing.T, a *App, name, host string, visible, active bool, jumpTemplateID *int64) int64 {
	t.Helper()
	res, err := a.DB.Exec(`INSERT INTO server_templates(name,host,port,color,kind,terminal_editor_mode,crontab_editor_mode,jump_template_id,visible_to_all,active) VALUES(?,?,22,'#5aa9ff','ssh','ask','ask',?,?,?)`, name, host, jumpTemplateID, boolInt(visible), boolInt(active))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return id
}

func insertDerivedServer(t *testing.T, a *App, userID, templateID int64, name, host string) int64 {
	t.Helper()
	res, err := a.DB.Exec(`INSERT INTO servers(owner_user_id,name,host,port,username,auth_type,secret_enc,color,kind,terminal_editor_mode,crontab_editor_mode,template_id) VALUES(?,?,?,22,'personal','password','','#111111','ssh','ask','ask',?)`, userID, name, host, templateID)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return id
}

func TestServerTemplateInheritanceUsesLiveInfrastructure(t *testing.T) {
	a, _, one, _ := workspaceTestApp(t)
	templateID := insertTemplate(t, a, "Prod DB", "10.0.0.10", true, true, nil)
	serverID := insertDerivedServer(t, a, one, templateID, "Old Name", "10.0.0.1")

	server, _, err := a.loadServer(serverID)
	if err != nil {
		t.Fatal(err)
	}
	if server.Name != "Prod DB" || server.Host != "10.0.0.10" || server.TemplateID == nil || *server.TemplateID != templateID {
		t.Fatalf("initial inherited server=%+v", server)
	}
	if _, err := a.DB.Exec(`UPDATE server_templates SET name='Prod DB Primary',host='10.0.0.20',port=2222,color='#abcdef' WHERE id=?`, templateID); err != nil {
		t.Fatal(err)
	}
	server, _, err = a.loadServer(serverID)
	if err != nil {
		t.Fatal(err)
	}
	if server.Name != "Prod DB Primary" || server.Host != "10.0.0.20" || server.Port != 2222 || server.Color != "#abcdef" {
		t.Fatalf("template changes were not inherited: %+v", server)
	}
}

func TestTemplateDerivedUseRequiresCurrentVisibilityAndActiveState(t *testing.T) {
	a, _, one, _ := workspaceTestApp(t)
	templateID := insertTemplate(t, a, "Restricted", "restricted.example", false, true, nil)
	serverID := insertDerivedServer(t, a, one, templateID, "snapshot", "old.example")
	if _, err := a.DB.Exec(`INSERT INTO server_template_user_access(template_id,user_id) VALUES(?,?)`, templateID, one); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.loadServerForUser(one, serverID); err != nil {
		t.Fatalf("explicitly allowed template use rejected: %v", err)
	}
	if _, err := a.DB.Exec(`DELETE FROM server_template_user_access WHERE template_id=? AND user_id=?`, templateID, one); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.loadServerForUser(one, serverID); err == nil || !strings.Contains(err.Error(), "access has been revoked") {
		t.Fatalf("revoked template remained usable: %v", err)
	}
	if _, err := a.DB.Exec(`INSERT INTO server_template_user_access(template_id,user_id) VALUES(?,?)`, templateID, one); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DB.Exec(`UPDATE server_templates SET active=0 WHERE id=?`, templateID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.loadServerForUser(one, serverID); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("disabled template remained usable: %v", err)
	}
}

func TestTemplateWorkspaceGrantIsContinuous(t *testing.T) {
	a, adminID, one, _ := workspaceTestApp(t)
	workspaceRes, _ := a.DB.Exec(`INSERT INTO workspaces(name,created_by) VALUES('DB Team',?)`, adminID)
	workspaceID, _ := workspaceRes.LastInsertId()
	_, _ = a.DB.Exec(`INSERT INTO workspace_memberships(workspace_id,user_id,can_use) VALUES(?,?,1)`, workspaceID, one)
	templateID := insertTemplate(t, a, "Workspace Template", "db.example", false, true, nil)
	_, _ = a.DB.Exec(`INSERT INTO server_template_workspace_access(template_id,workspace_id) VALUES(?,?)`, templateID, workspaceID)
	serverID := insertDerivedServer(t, a, one, templateID, "snapshot", "snapshot.example")

	if _, _, err := a.loadServerForUser(one, serverID); err != nil {
		t.Fatalf("workspace-granted template rejected: %v", err)
	}
	if _, err := a.DB.Exec(`DELETE FROM workspace_memberships WHERE workspace_id=? AND user_id=?`, workspaceID, one); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.loadServerForUser(one, serverID); err == nil {
		t.Fatal("template remained usable after workspace membership removal")
	}
}

func TestTemplateJumpRequiresUsersOwnAdoptedJumpTemplate(t *testing.T) {
	a, _, one, _ := workspaceTestApp(t)
	jumpTemplateID := insertTemplate(t, a, "Bastion", "bastion.example", true, true, nil)
	targetTemplateID := insertTemplate(t, a, "Production", "prod.example", true, true, &jumpTemplateID)
	targetServerID := insertDerivedServer(t, a, one, targetTemplateID, "snapshot-target", "old-target")

	if _, _, err := a.loadServerForUser(one, targetServerID); err == nil || !strings.Contains(err.Error(), "jump server template has not been adopted") {
		t.Fatalf("missing adopted jump template did not block use: %v", err)
	}
	jumpServerID := insertDerivedServer(t, a, one, jumpTemplateID, "snapshot-jump", "old-jump")
	server, _, err := a.loadServerForUser(one, targetServerID)
	if err != nil {
		t.Fatalf("target remained blocked after jump template adoption: %v", err)
	}
	if server.JumpHostID == nil || *server.JumpHostID != jumpServerID {
		t.Fatalf("effective jump server=%v want=%d", server.JumpHostID, jumpServerID)
	}
}

func TestDeletingUsedTemplateRequiresConversionAndPreservesLatestSnapshot(t *testing.T) {
	a, adminID, one, _ := workspaceTestApp(t)
	templateID := insertTemplate(t, a, "Production", "10.20.30.40", true, true, nil)
	serverID := insertDerivedServer(t, a, one, templateID, "old", "old.example")
	if _, err := a.DB.Exec(`UPDATE server_templates SET name='Production Primary',host='10.20.30.41',port=2200 WHERE id=?`, templateID); err != nil {
		t.Fatal(err)
	}

	conflict := httptest.NewRecorder()
	a.adminServerTemplateByID(conflict, requestAs(http.MethodDelete, "/api/admin/server-templates/"+itoa(templateID), "", adminID, "admin"))
	if conflict.Code != http.StatusConflict {
		t.Fatalf("used template delete status=%d body=%s", conflict.Code, conflict.Body.String())
	}

	converted := httptest.NewRecorder()
	a.adminServerTemplateByID(converted, requestAs(http.MethodDelete, "/api/admin/server-templates/"+itoa(templateID)+"?convert=1", "", adminID, "admin"))
	if converted.Code != http.StatusOK {
		t.Fatalf("template conversion delete status=%d body=%s", converted.Code, converted.Body.String())
	}
	var template sql.NullInt64
	var name, host string
	var port int
	if err := a.DB.QueryRow(`SELECT template_id,name,host,port FROM servers WHERE id=?`, serverID).Scan(&template, &name, &host, &port); err != nil {
		t.Fatal(err)
	}
	if template.Valid || name != "Production Primary" || host != "10.20.30.41" || port != 2200 {
		t.Fatalf("converted server template=%v name=%q host=%q port=%d", template, name, host, port)
	}
}

func TestTemplateConversionRequiresAndPreservesAdoptedJump(t *testing.T) {
	a, adminID, one, _ := workspaceTestApp(t)
	jumpTemplateID := insertTemplate(t, a, "Bastion", "bastion.example", true, true, nil)
	targetTemplateID := insertTemplate(t, a, "Production", "prod.example", true, true, &jumpTemplateID)
	targetServerID := insertDerivedServer(t, a, one, targetTemplateID, "target snapshot", "old-target")

	blocked := httptest.NewRecorder()
	a.adminServerTemplateByID(blocked, requestAs(http.MethodDelete, "/api/admin/server-templates/"+itoa(targetTemplateID)+"?convert=1", "", adminID, "admin"))
	if blocked.Code != http.StatusConflict || !strings.Contains(blocked.Body.String(), "missing_jump_template_adoption") {
		t.Fatalf("conversion without required jump status=%d body=%s", blocked.Code, blocked.Body.String())
	}
	var stillTemplate sql.NullInt64
	if err := a.DB.QueryRow(`SELECT template_id FROM servers WHERE id=?`, targetServerID).Scan(&stillTemplate); err != nil {
		t.Fatal(err)
	}
	if !stillTemplate.Valid || stillTemplate.Int64 != targetTemplateID {
		t.Fatalf("blocked conversion mutated target template link: %+v", stillTemplate)
	}

	jumpServerID := insertDerivedServer(t, a, one, jumpTemplateID, "jump snapshot", "old-jump")
	converted := httptest.NewRecorder()
	a.adminServerTemplateByID(converted, requestAs(http.MethodDelete, "/api/admin/server-templates/"+itoa(targetTemplateID)+"?convert=1", "", adminID, "admin"))
	if converted.Code != http.StatusOK {
		t.Fatalf("conversion with adopted jump status=%d body=%s", converted.Code, converted.Body.String())
	}
	var templateAfter, jumpAfter sql.NullInt64
	if err := a.DB.QueryRow(`SELECT template_id,jump_host_id FROM servers WHERE id=?`, targetServerID).Scan(&templateAfter, &jumpAfter); err != nil {
		t.Fatal(err)
	}
	if templateAfter.Valid || !jumpAfter.Valid || jumpAfter.Int64 != jumpServerID {
		t.Fatalf("converted target template=%+v jump=%+v want standalone with jump=%d", templateAfter, jumpAfter, jumpServerID)
	}
}

func TestAdminServerTemplateUserAccessAssignsListsAndRevokes(t *testing.T) {
	a, adminID, one, two := workspaceTestApp(t)
	templateID := insertTemplate(t, a, "Restricted", "restricted.example", false, true, nil)
	serverID := insertDerivedServer(t, a, one, templateID, "snapshot", "old.example")

	grant := httptest.NewRecorder()
	grantBody := `{"templateId":` + itoa(templateID) + `,"userId":` + itoa(one) + `,"assigned":true}`
	a.adminServerTemplateUserAccess(grant, requestAs(http.MethodPatch, "/api/admin/server-template-user-access", grantBody, adminID, "admin"))
	if grant.Code != http.StatusOK {
		t.Fatalf("template user grant status=%d body=%s", grant.Code, grant.Body.String())
	}
	if _, _, err := a.loadServerForUser(one, serverID); err != nil {
		t.Fatalf("granted template-derived server is unusable: %v", err)
	}

	list := httptest.NewRecorder()
	a.adminServerTemplateUserAccess(list, requestAs(http.MethodGet, "/api/admin/server-template-user-access?templateId="+itoa(templateID), "", adminID, "admin"))
	if list.Code != http.StatusOK {
		t.Fatalf("template user access GET status=%d body=%s", list.Code, list.Body.String())
	}
	var response struct {
		TemplateID int64                          `json:"templateId"`
		Name       string                         `json:"name"`
		Users      []serverTemplateUserAccessItem `json:"users"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.TemplateID != templateID || response.Name != "Restricted" || len(response.Users) != 2 {
		t.Fatalf("unexpected template user response: %+v", response)
	}
	if response.Users[0].UserID != one || !response.Users[0].Assigned {
		t.Fatalf("assigned template user was not first: %+v", response.Users)
	}
	if response.Users[1].UserID != two || response.Users[1].Assigned {
		t.Fatalf("unassigned template user response unexpected: %+v", response.Users[1])
	}

	revoke := httptest.NewRecorder()
	revokeBody := `{"templateId":` + itoa(templateID) + `,"userId":` + itoa(one) + `,"assigned":false}`
	a.adminServerTemplateUserAccess(revoke, requestAs(http.MethodPatch, "/api/admin/server-template-user-access", revokeBody, adminID, "admin"))
	if revoke.Code != http.StatusOK {
		t.Fatalf("template user revoke status=%d body=%s", revoke.Code, revoke.Body.String())
	}
	if _, _, err := a.loadServerForUser(one, serverID); err == nil || !strings.Contains(err.Error(), "access has been revoked") {
		t.Fatalf("revoked template-derived server remained usable: %v", err)
	}
}

func TestAdminServerTemplateUserAccessListsTemplatesForUser(t *testing.T) {
	a, adminID, one, _ := workspaceTestApp(t)
	directID := insertTemplate(t, a, "Direct", "direct.example", false, true, nil)
	globalID := insertTemplate(t, a, "Global", "global.example", true, true, nil)
	workspaceIDTemplate := insertTemplate(t, a, "Workspace", "workspace.example", false, true, nil)
	hiddenID := insertTemplate(t, a, "Hidden", "hidden.example", false, false, nil)

	if _, err := a.DB.Exec(`INSERT INTO server_template_user_access(template_id,user_id) VALUES(?,?)`, directID, one); err != nil {
		t.Fatal(err)
	}
	workspaceRes, err := a.DB.Exec(`INSERT INTO workspaces(name,created_by) VALUES('Production',?)`, adminID)
	if err != nil {
		t.Fatal(err)
	}
	workspaceID, _ := workspaceRes.LastInsertId()
	if _, err := a.DB.Exec(`INSERT INTO workspace_memberships(workspace_id,user_id,can_use) VALUES(?,?,1)`, workspaceID, one); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DB.Exec(`INSERT INTO server_template_workspace_access(template_id,workspace_id) VALUES(?,?)`, workspaceIDTemplate, workspaceID); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	a.adminServerTemplateUserAccess(rec, requestAs(http.MethodGet, "/api/admin/server-template-user-access?userId="+itoa(one), "", adminID, "admin"))
	if rec.Code != http.StatusOK {
		t.Fatalf("template access by user GET status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		UserID    int64                      `json:"userId"`
		Admin     bool                       `json:"admin"`
		Templates []serverTemplateAccessItem `json:"templates"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.UserID != one || response.Admin || len(response.Templates) != 4 {
		t.Fatalf("unexpected template access by user response: %+v", response)
	}
	byID := map[int64]serverTemplateAccessItem{}
	for _, item := range response.Templates {
		byID[item.TemplateID] = item
	}
	if item := byID[directID]; !item.Assigned || item.VisibleToAll || item.ViaWorkspace || !item.Active {
		t.Fatalf("direct access flags unexpected: %+v", item)
	}
	if item := byID[globalID]; item.Assigned || !item.VisibleToAll || item.ViaWorkspace || !item.Active {
		t.Fatalf("global access flags unexpected: %+v", item)
	}
	if item := byID[workspaceIDTemplate]; item.Assigned || item.VisibleToAll || !item.ViaWorkspace || !item.Active {
		t.Fatalf("workspace access flags unexpected: %+v", item)
	}
	if item := byID[hiddenID]; item.Assigned || item.VisibleToAll || item.ViaWorkspace || item.Active {
		t.Fatalf("hidden template flags unexpected: %+v", item)
	}
}
