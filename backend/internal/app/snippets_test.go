package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizeSnippetInputPreservesMultilineShell(t *testing.T) {
	name, content, err := normalizeSnippetInput(" Deploy ", "cd /opt/app\r\ndocker compose pull\r\ndocker compose up -d\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if name != "Deploy" {
		t.Fatalf("name = %q", name)
	}
	want := "cd /opt/app\ndocker compose pull\ndocker compose up -d\n"
	if content != want {
		t.Fatalf("content = %q, want %q", content, want)
	}
}

func TestNormalizeSnippetScope(t *testing.T) {
	for input, want := range map[string]string{"": "private", "private": "private", " Private ": "private", "shared": "shared", "SHARED": "shared", "invalid": ""} {
		if got := normalizeSnippetScope(input); got != want {
			t.Fatalf("normalizeSnippetScope(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestParseSnippetPath(t *testing.T) {
	id, action, err := parseSnippetPath("/api/code-snippets/42/use")
	if err != nil || id != 42 || action != "use" {
		t.Fatalf("parseSnippetPath = id=%d action=%q err=%v", id, action, err)
	}
	if _, _, err := parseSnippetPath("/api/code-snippets/nope/use"); err == nil {
		t.Fatal("invalid snippet id accepted")
	}
}

func TestNormalizeSnippetFolderName(t *testing.T) {
	got, err := normalizeSnippetFolderName("  Docker  ")
	if err != nil {
		t.Fatal(err)
	}
	if got != "Docker" {
		t.Fatalf("folder name = %q", got)
	}
	if _, err := normalizeSnippetFolderName("   "); err == nil {
		t.Fatal("empty folder name accepted")
	}
}

func TestParseSnippetFolderPath(t *testing.T) {
	id, err := parseSnippetFolderPath("/api/snippet-folders/17")
	if err != nil || id != 17 {
		t.Fatalf("parseSnippetFolderPath = id=%d err=%v", id, err)
	}
	if _, err := parseSnippetFolderPath("/api/snippet-folders/nope"); err == nil {
		t.Fatal("invalid folder id accepted")
	}
}

func TestAdminSnippetFolderPermissionsByFolderListsAssignedUsersFirst(t *testing.T) {
	a, adminID, one, two := workspaceTestApp(t)
	folderRes, err := a.DB.Exec(`INSERT INTO snippet_folders(name,scope,owner_user_id) VALUES('Operations','shared',NULL)`)
	if err != nil {
		t.Fatal(err)
	}
	folderID, _ := folderRes.LastInsertId()
	if _, err := a.DB.Exec(`INSERT INTO snippet_folder_permissions(folder_id,user_id,can_use,can_create,can_edit,can_delete) VALUES(?,?,1,1,0,0)`, folderID, two); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	a.adminSnippetFolderPermissions(rec, requestAs(http.MethodGet, "/api/admin/snippet-folder-permissions?folderId="+itoa(folderID), "", adminID, "admin"))
	if rec.Code != http.StatusOK {
		t.Fatalf("snippet folder permission GET status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		FolderID int64                         `json:"folderId"`
		Name     string                        `json:"name"`
		Users    []snippetFolderPermissionUser `json:"users"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.FolderID != folderID || response.Name != "Operations" || len(response.Users) != 2 {
		t.Fatalf("unexpected snippet folder access response: %+v", response)
	}
	if response.Users[0].UserID != two || !response.Users[0].Assigned || !response.Users[0].CanUse || !response.Users[0].CanCreate {
		t.Fatalf("assigned user was not first or rights changed: %+v", response.Users)
	}
	if response.Users[1].UserID != one || response.Users[1].Assigned {
		t.Fatalf("unassigned user response unexpected: %+v", response.Users[1])
	}
}

func TestAdminSnippetFolderPermissionsByUserListsAllFoldersAndPreservesRights(t *testing.T) {
	a, adminID, one, _ := workspaceTestApp(t)
	assignedRes, err := a.DB.Exec(`INSERT INTO snippet_folders(name,scope,owner_user_id) VALUES('Operations','shared',NULL)`)
	if err != nil {
		t.Fatal(err)
	}
	otherRes, err := a.DB.Exec(`INSERT INTO snippet_folders(name,scope,owner_user_id) VALUES('Deploy','shared',NULL)`)
	if err != nil {
		t.Fatal(err)
	}
	assignedID, _ := assignedRes.LastInsertId()
	otherID, _ := otherRes.LastInsertId()
	if _, err := a.DB.Exec(`INSERT INTO snippet_folder_permissions(folder_id,user_id,can_use,can_create,can_edit,can_delete) VALUES(?,?,1,0,1,0)`, assignedID, one); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	a.adminSnippetFolderPermissions(rec, requestAs(http.MethodGet, "/api/admin/snippet-folder-permissions?userId="+itoa(one), "", adminID, "admin"))
	if rec.Code != http.StatusOK {
		t.Fatalf("snippet folder permission by user GET status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		UserID  int64                         `json:"userId"`
		Admin   bool                          `json:"admin"`
		Folders []snippetFolderPermissionItem `json:"folders"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.UserID != one || response.Admin || len(response.Folders) != 2 {
		t.Fatalf("unexpected snippet folder access by user response: %+v", response)
	}
	byID := map[int64]snippetFolderPermissionItem{}
	for _, item := range response.Folders {
		byID[item.FolderID] = item
	}
	if item := byID[assignedID]; !item.Assigned || !item.CanUse || item.CanCreate || !item.CanEdit || item.CanDelete {
		t.Fatalf("assigned snippet rights changed: %+v", item)
	}
	if item := byID[otherID]; item.Assigned || item.CanUse || item.CanCreate || item.CanEdit || item.CanDelete {
		t.Fatalf("unassigned snippet folder unexpected: %+v", item)
	}
}
