package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	zcrypto "zentssh.local/backend/internal/crypto"
	zdb "zentssh.local/backend/internal/db"
)

func TestFreshSetupRequiresBootstrapToken(t *testing.T) {
	a := loginTestApp(t)
	a.cfg.SetupToken = "bootstrap-secret"

	wrong := httptest.NewRecorder()
	a.setup(wrong, httptest.NewRequest(http.MethodPost, "/api/setup", strings.NewReader(`{"name":"Admin","email":"admin@example.test","password":"very-secret-password","setupToken":"wrong"}`)))
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong setup token status=%d body=%s", wrong.Code, wrong.Body.String())
	}
	var count int
	if err := a.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("wrong setup token created %d users", count)
	}

	missingConfig := loginTestApp(t)
	missingConfig.cfg.SetupToken = ""
	unavailable := httptest.NewRecorder()
	missingConfig.setup(unavailable, httptest.NewRequest(http.MethodPost, "/api/setup", strings.NewReader(`{"name":"Admin","email":"admin@example.test","password":"very-secret-password","setupToken":"anything"}`)))
	if unavailable.Code != http.StatusServiceUnavailable {
		t.Fatalf("setup without initialized token status=%d body=%s", unavailable.Code, unavailable.Body.String())
	}
}

func TestNewGeneratesSetupTokenForFreshDatabase(t *testing.T) {
	t.Setenv("SETUP_TOKEN", "")
	database, err := zdb.Open(t.TempDir() + "/zentssh.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	box, err := zcrypto.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	a := New(database, box, t.TempDir())
	defer a.Close()
	if len(strings.TrimSpace(a.cfg.SetupToken)) < 20 {
		t.Fatalf("generated setup token is unexpectedly short: %q", a.cfg.SetupToken)
	}
}

func TestSharedCredentialProfileIsNotGloballyVisibleOrAssignable(t *testing.T) {
	a, owner, member := ownershipTestApp(t)
	secret, err := a.Box.Encrypt("top-secret")
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.DB.Exec(`INSERT INTO credential_profiles(owner_user_id,name,username,auth_type,secret_enc,shared) VALUES(?,?,?,?,?,1)`, owner, "Production", "deploy", "password", secret)
	if err != nil {
		t.Fatal(err)
	}
	profileID, _ := res.LastInsertId()

	if _, err := a.credentialProfileOwnedBy(member, profileID); err == nil {
		t.Fatal("non-owner could assign a shared credential profile")
	}

	rec := httptest.NewRecorder()
	a.credentialProfiles(rec, ownedRequest(http.MethodGet, "/api/credential-profiles", "", member))
	if rec.Code != http.StatusOK {
		t.Fatalf("credential list status=%d body=%s", rec.Code, rec.Body.String())
	}
	var profiles []credentialProfile
	if err := json.Unmarshal(rec.Body.Bytes(), &profiles); err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 0 {
		t.Fatalf("foreign shared profiles leaked into member list: %#v", profiles)
	}

	s := Server{Name: "Private", Host: "example.test", Port: 22, CredentialProfileID: &profileID}
	if err := a.prepareServerCredentials(member, &s); err == nil {
		t.Fatal("non-owner could assign shared profile to a private server")
	}
}

func TestCredentialProfileRuntimeBindingRejectsUnsafeExistingLinks(t *testing.T) {
	a, owner, member := ownershipTestApp(t)
	secret, err := a.Box.Encrypt("top-secret")
	if err != nil {
		t.Fatal(err)
	}
	profileRes, err := a.DB.Exec(`INSERT INTO credential_profiles(owner_user_id,name,username,auth_type,secret_enc,shared) VALUES(?,?,?,?,?,1)`, owner, "Production", "deploy", "password", secret)
	if err != nil {
		t.Fatal(err)
	}
	profileID, _ := profileRes.LastInsertId()

	privateRes, err := a.DB.Exec(`INSERT INTO servers(owner_user_id,name,host,port,username,auth_type,credential_profile_id) VALUES(?,?,?,?,?,?,?)`, member, "Unsafe private", "private.example", 22, "deploy", "password", profileID)
	if err != nil {
		t.Fatal(err)
	}
	privateID, _ := privateRes.LastInsertId()
	privateServer, _, err := a.loadServer(privateID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.sshConfigForServer(privateServer); err == nil {
		t.Fatal("private server could still use another user's shared credential profile")
	}

	workspaceRes, err := a.DB.Exec(`INSERT INTO workspaces(name,created_by) VALUES(?,?)`, "Production", owner)
	if err != nil {
		t.Fatal(err)
	}
	workspaceID, _ := workspaceRes.LastInsertId()
	workspaceServerRes, err := a.DB.Exec(`INSERT INTO servers(owner_user_id,name,host,port,username,auth_type,credential_profile_id,workspace_id) VALUES(?,?,?,?,?,?,?,?)`, owner, "Shared", "shared.example", 22, "deploy", "password", profileID, workspaceID)
	if err != nil {
		t.Fatal(err)
	}
	workspaceServerID, _ := workspaceServerRes.LastInsertId()
	workspaceServer, _, err := a.loadServer(workspaceServerID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.sshConfigForServer(workspaceServer); err != nil {
		t.Fatalf("valid workspace-bound shared profile was rejected: %v", err)
	}

	if _, err := a.DB.Exec(`UPDATE credential_profiles SET shared=0 WHERE id=?`, profileID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.sshConfigForServer(workspaceServer); err == nil {
		t.Fatal("workspace server could use a profile after sharing was revoked")
	}
}

func TestWorkspaceEditorCannotRebindStoredCredentialsToNewRoute(t *testing.T) {
	a, adminID, editorID, _ := workspaceTestApp(t)
	workspaceRes, err := a.DB.Exec(`INSERT INTO workspaces(name,created_by) VALUES('Production',?)`, adminID)
	if err != nil {
		t.Fatal(err)
	}
	workspaceID, _ := workspaceRes.LastInsertId()
	if _, err := a.DB.Exec(`INSERT INTO workspace_memberships(workspace_id,user_id,can_use,can_edit) VALUES(?,?,1,1)`, workspaceID, editorID); err != nil {
		t.Fatal(err)
	}

	directSecret, err := a.Box.Encrypt("shared-password")
	if err != nil {
		t.Fatal(err)
	}
	directRes, err := a.DB.Exec(`INSERT INTO servers(owner_user_id,name,host,port,username,auth_type,secret_enc,workspace_id) VALUES(?,?,?,?,?,?,?,?)`, adminID, "Direct", "prod.example", 22, "deploy", "password", directSecret, workspaceID)
	if err != nil {
		t.Fatal(err)
	}
	directID, _ := directRes.LastInsertId()
	existingDirect, _, err := a.loadServerForPermission(editorID, directID, "edit")
	if err != nil {
		t.Fatal(err)
	}
	changedDirect := existingDirect
	changedDirect.Host = "attacker.example"
	changedDirect.Secret = ""
	if err := a.updateServer(directID, editorID, existingDirect, &changedDirect); err == nil {
		t.Fatal("workspace editor rebound an existing direct secret to a new target")
	}
	changedDirect.Secret = "editor-owned-replacement"
	if err := a.updateServer(directID, editorID, existingDirect, &changedDirect); err != nil {
		t.Fatalf("workspace editor could not change route with new direct credentials: %v", err)
	}

	profileSecret, err := a.Box.Encrypt("profile-password")
	if err != nil {
		t.Fatal(err)
	}
	profileRes, err := a.DB.Exec(`INSERT INTO credential_profiles(owner_user_id,name,username,auth_type,secret_enc,shared) VALUES(?,?,?,?,?,1)`, adminID, "Shared profile", "deploy", "password", profileSecret)
	if err != nil {
		t.Fatal(err)
	}
	profileID, _ := profileRes.LastInsertId()
	profileServerRes, err := a.DB.Exec(`INSERT INTO servers(owner_user_id,name,host,port,username,auth_type,credential_profile_id,workspace_id) VALUES(?,?,?,?,?,?,?,?)`, adminID, "Profile", "profile-prod.example", 22, "deploy", "password", profileID, workspaceID)
	if err != nil {
		t.Fatal(err)
	}
	profileServerID, _ := profileServerRes.LastInsertId()
	existingProfile, _, err := a.loadServerForPermission(editorID, profileServerID, "edit")
	if err != nil {
		t.Fatal(err)
	}

	metadataOnly := existingProfile
	metadataOnly.Name = "Profile renamed"
	if err := a.updateServer(profileServerID, editorID, existingProfile, &metadataOnly); err != nil {
		t.Fatalf("metadata-only edit unexpectedly lost existing workspace credential: %v", err)
	}

	changedProfile := existingProfile
	changedProfile.Host = "profile-attacker.example"
	if err := a.updateServer(profileServerID, editorID, existingProfile, &changedProfile); err == nil {
		t.Fatal("workspace editor rebound another user's credential profile to a new target")
	}
}
