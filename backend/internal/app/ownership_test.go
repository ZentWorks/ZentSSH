package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	zcrypto "zentssh.local/backend/internal/crypto"
	zdb "zentssh.local/backend/internal/db"
)

func ownershipTestApp(t *testing.T) (*App, int64, int64) {
	t.Helper()
	database, err := zdb.Open(t.TempDir() + "/zentssh-ownership.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	box, err := zcrypto.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	addUser := func(name, email string) int64 {
		res, err := database.Exec("INSERT INTO users(name,email,password_hash,role,active) VALUES(?,?,?,?,1)", name, email, hashPass("very-secret-password"), "user")
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	return &App{DB: database, Box: box}, addUser("One", "one@example.test"), addUser("Two", "two@example.test")
}

func ownedRequest(method, target, body string, userID int64) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	ctx := context.WithValue(req.Context(), userCtxKey{}, userID)
	ctx = context.WithValue(ctx, roleCtxKey{}, "user")
	return req.WithContext(ctx)
}

func TestPrivateServerAndFolderListsAreUserScoped(t *testing.T) {
	a, one, two := ownershipTestApp(t)
	folderOne, _ := a.DB.Exec("INSERT INTO folders(owner_user_id,name) VALUES(?,?)", one, "One Folder")
	folderTwo, _ := a.DB.Exec("INSERT INTO folders(owner_user_id,name) VALUES(?,?)", two, "Two Folder")
	f1, _ := folderOne.LastInsertId()
	f2, _ := folderTwo.LastInsertId()
	_, _ = a.DB.Exec("INSERT INTO servers(owner_user_id,name,host,username,folder_id) VALUES(?,?,?,?,?)", one, "One Server", "one.test", "root", f1)
	_, _ = a.DB.Exec("INSERT INTO servers(owner_user_id,name,host,username,folder_id) VALUES(?,?,?,?,?)", two, "Two Server", "two.test", "root", f2)

	serverRec := httptest.NewRecorder()
	a.servers(serverRec, ownedRequest(http.MethodGet, "/api/servers", "", one))
	if serverRec.Code != http.StatusOK {
		t.Fatalf("server list status=%d body=%s", serverRec.Code, serverRec.Body.String())
	}
	var servers []Server
	if err := json.Unmarshal(serverRec.Body.Bytes(), &servers); err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 || servers[0].Name != "One Server" {
		t.Fatalf("user-scoped servers=%#v", servers)
	}

	folderRec := httptest.NewRecorder()
	a.folders(folderRec, ownedRequest(http.MethodGet, "/api/folders", "", one))
	if folderRec.Code != http.StatusOK {
		t.Fatalf("folder list status=%d body=%s", folderRec.Code, folderRec.Body.String())
	}
	var folders []Folder
	if err := json.Unmarshal(folderRec.Body.Bytes(), &folders); err != nil {
		t.Fatal(err)
	}
	if len(folders) != 1 || folders[0].Name != "One Folder" {
		t.Fatalf("user-scoped folders=%#v", folders)
	}
}

func TestForeignServerAndFolderIDsReturnNotFound(t *testing.T) {
	a, one, two := ownershipTestApp(t)
	folderRes, _ := a.DB.Exec("INSERT INTO folders(owner_user_id,name) VALUES(?,?)", two, "Foreign")
	folderID, _ := folderRes.LastInsertId()
	serverRes, _ := a.DB.Exec("INSERT INTO servers(owner_user_id,name,host,username,folder_id) VALUES(?,?,?,?,?)", two, "Foreign", "foreign.test", "root", folderID)
	serverID, _ := serverRes.LastInsertId()

	serverRec := httptest.NewRecorder()
	a.serverByID(serverRec, ownedRequest(http.MethodDelete, "/api/servers/"+itoa(serverID), "", one))
	if serverRec.Code != http.StatusNotFound {
		t.Fatalf("foreign server status=%d body=%s", serverRec.Code, serverRec.Body.String())
	}
	folderRec := httptest.NewRecorder()
	a.folderByID(folderRec, ownedRequest(http.MethodDelete, "/api/folders/"+itoa(folderID), "", one))
	if folderRec.Code != http.StatusNotFound {
		t.Fatalf("foreign folder status=%d body=%s", folderRec.Code, folderRec.Body.String())
	}
}

func TestNormalUserCanCreatePrivateFolderAndServer(t *testing.T) {
	a, one, _ := ownershipTestApp(t)
	folderRec := httptest.NewRecorder()
	a.folders(folderRec, ownedRequest(http.MethodPost, "/api/folders", `{"name":"Private"}`, one))
	if folderRec.Code != http.StatusCreated {
		t.Fatalf("folder create status=%d body=%s", folderRec.Code, folderRec.Body.String())
	}
	var folder Folder
	if err := json.Unmarshal(folderRec.Body.Bytes(), &folder); err != nil {
		t.Fatal(err)
	}
	serverRec := httptest.NewRecorder()
	body := `{"name":"Private Server","host":"127.0.0.1","port":22,"username":"root","authType":"password","secret":"secret","folderId":` + itoa(folder.ID) + `}`
	a.servers(serverRec, ownedRequest(http.MethodPost, "/api/servers", body, one))
	if serverRec.Code != http.StatusCreated {
		t.Fatalf("server create status=%d body=%s", serverRec.Code, serverRec.Body.String())
	}
	var owner int64
	if err := a.DB.QueryRow("SELECT owner_user_id FROM servers WHERE name='Private Server'").Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if owner != one {
		t.Fatalf("server owner=%d want=%d", owner, one)
	}
}

func TestForeignJumpHostIsRejected(t *testing.T) {
	a, one, two := ownershipTestApp(t)
	res, _ := a.DB.Exec("INSERT INTO servers(owner_user_id,name,host,username) VALUES(?,?,?,?)", two, "Foreign Jump", "jump.test", "root")
	jumpID, _ := res.LastInsertId()
	if err := a.validateJumpHostForUser(one, 0, &jumpID); err == nil {
		t.Fatal("foreign jump host was accepted")
	}
}

func TestForeignServerBlockedBeforeFilesSessionAndTransfer(t *testing.T) {
	a, one, two := ownershipTestApp(t)
	foreignRes, _ := a.DB.Exec("INSERT INTO servers(owner_user_id,name,host,username) VALUES(?,?,?,?)", two, "Foreign", "127.0.0.1", "root")
	foreignID, _ := foreignRes.LastInsertId()
	localRes, _ := a.DB.Exec("INSERT INTO servers(owner_user_id,name,host,username) VALUES(?,?,?,?)", one, "Local", "127.0.0.1", "root")
	localID, _ := localRes.LastInsertId()

	fileRec := httptest.NewRecorder()
	a.files(fileRec, ownedRequest(http.MethodGet, "/api/files/"+itoa(foreignID)+"?path=.", "", one))
	if fileRec.Code != http.StatusNotFound {
		t.Fatalf("foreign file access status=%d body=%s", fileRec.Code, fileRec.Body.String())
	}
	if _, err := a.createLiveSession(one, foreignID, 120, 36); err == nil {
		t.Fatal("foreign server SSH session was accepted")
	}
	if _, err := a.startTransfer(one, localID, "/tmp/source", foreignID, "/tmp/target"); err == nil || err.Error() != "target server not found" {
		t.Fatalf("foreign transfer target err=%v", err)
	}
}

func TestForeignFolderCannotBeUsedAsParentOrServerTarget(t *testing.T) {
	a, one, two := ownershipTestApp(t)
	foreignRes, _ := a.DB.Exec("INSERT INTO folders(owner_user_id,name) VALUES(?,?)", two, "Foreign Folder")
	foreignID, _ := foreignRes.LastInsertId()

	folderRec := httptest.NewRecorder()
	a.folders(folderRec, ownedRequest(http.MethodPost, "/api/folders", `{"name":"Child","parentId":`+itoa(foreignID)+`}`, one))
	if folderRec.Code != http.StatusBadRequest {
		t.Fatalf("foreign parent folder status=%d body=%s", folderRec.Code, folderRec.Body.String())
	}

	serverRec := httptest.NewRecorder()
	body := `{"name":"Bad Folder Server","host":"127.0.0.1","port":22,"username":"root","authType":"password","secret":"secret","folderId":` + itoa(foreignID) + `}`
	a.servers(serverRec, ownedRequest(http.MethodPost, "/api/servers", body, one))
	if serverRec.Code != http.StatusBadRequest {
		t.Fatalf("foreign server folder status=%d body=%s", serverRec.Code, serverRec.Body.String())
	}
}

func TestLegacyReadOnlyRoleNormalizesToUser(t *testing.T) {
	if got := normalizeUserRole("readonly"); got != "user" {
		t.Fatalf("normalize readonly=%q", got)
	}
	if got := normalizeUserRole("read-only"); got != "user" {
		t.Fatalf("normalize read-only=%q", got)
	}
}

func itoa(v int64) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = digits[v%10]
		v /= 10
	}
	return string(buf[i:])
}
