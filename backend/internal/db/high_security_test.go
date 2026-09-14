package db

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"

	_ "modernc.org/sqlite"
)

func TestHighOpenUpgradesLegacyServerSchemaBeforeCreatingDependentIndexes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-pre-credentials.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`
CREATE TABLE users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'admin',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE sessions(id TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires_at DATETIME NOT NULL);
CREATE TABLE user_settings(user_id INTEGER PRIMARY KEY,ssh_session_retention TEXT NOT NULL DEFAULT 'inherit');
CREATE TABLE folders(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,parent_id INTEGER NULL,sort_order INTEGER DEFAULT 0);
CREATE TABLE servers(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 22,
  username TEXT NOT NULL,
  auth_type TEXT NOT NULL DEFAULT 'password',
  secret_enc TEXT NOT NULL DEFAULT '',
  folder_id INTEGER NULL,
  color TEXT NOT NULL DEFAULT '#5aa9ff',
  kind TEXT NOT NULL DEFAULT 'ssh',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE oidc_providers(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  issuer_url TEXT NOT NULL,
  client_id TEXT NOT NULL,
  client_secret_enc TEXT NOT NULL DEFAULT '',
  redirect_url TEXT NOT NULL,
  scopes TEXT NOT NULL DEFAULT 'openid email profile',
  group_claim TEXT NOT NULL DEFAULT 'groups',
  token_auth_method TEXT NOT NULL DEFAULT 'client_secret_basic',
  enabled INTEGER NOT NULL DEFAULT 1,
  auto_create INTEGER NOT NULL DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO users(name,email,password_hash,role) VALUES('Admin','admin@example.test','fixture','admin');
INSERT INTO folders(name) VALUES('Legacy');
INSERT INTO servers(name,host,username,folder_id) VALUES('Legacy Server','legacy.example','root',1);
`)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	d, err := Open(path)
	if err != nil {
		t.Fatalf("Open failed on legacy schema: %v", err)
	}
	defer d.Close()
	for _, column := range []string{"credential_profile_id", "jump_host_id", "owner_user_id", "workspace_id", "template_id"} {
		ok, err := hasColumn(d, "servers", column)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("servers.%s was not migrated", column)
		}
	}
	var indexes int
	if err := d.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN ('idx_servers_credential_profile','idx_servers_jump_host')`).Scan(&indexes); err != nil {
		t.Fatal(err)
	}
	if indexes != 2 {
		t.Fatalf("dependent server indexes=%d want=2", indexes)
	}
	var ownerID int64
	if err := d.QueryRow(`SELECT owner_user_id FROM servers WHERE name='Legacy Server'`).Scan(&ownerID); err != nil {
		t.Fatal(err)
	}
	if ownerID != 1 {
		t.Fatalf("legacy server owner=%d want=1", ownerID)
	}
}

func TestHighAdminSafetyTriggersProtectLastActiveAdministrator(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "admin-safety.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	first, err := d.Exec(`INSERT INTO users(name,email,password_hash,role,active) VALUES('Admin One','one@example.test','fixture','admin',1)`)
	if err != nil {
		t.Fatal(err)
	}
	firstID, _ := first.LastInsertId()
	if _, err := d.Exec(`UPDATE users SET role='user' WHERE id=?`, firstID); err == nil {
		t.Fatal("last active administrator could be demoted")
	}
	if _, err := d.Exec(`DELETE FROM users WHERE id=?`, firstID); err == nil {
		t.Fatal("last active administrator could be deleted")
	}

	second, err := d.Exec(`INSERT INTO users(name,email,password_hash,role,active) VALUES('Admin Two','two@example.test','fixture','admin',1)`)
	if err != nil {
		t.Fatal(err)
	}
	secondID, _ := second.LastInsertId()
	if _, err := d.Exec(`UPDATE users SET role='user' WHERE id=?`, firstID); err != nil {
		t.Fatalf("demoting one of two administrators failed: %v", err)
	}
	if _, err := d.Exec(`DELETE FROM users WHERE id=?`, secondID); err == nil {
		t.Fatal("remaining active administrator could be deleted")
	}
}

func TestHighAdminSafetyTriggersHoldUnderConcurrentDemotion(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "admin-concurrency.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.SetMaxOpenConns(2)

	ids := make([]int64, 0, 2)
	for _, email := range []string{"one@example.test", "two@example.test"} {
		res, err := d.Exec(`INSERT INTO users(name,email,password_hash,role,active) VALUES(?,?,?,'admin',1)`, "Admin", email, "fixture")
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		ids = append(ids, id)
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(userID int64) {
			defer wg.Done()
			<-start
			_, err := d.Exec(`UPDATE users SET role='user' WHERE id=?`, userID)
			errs <- err
		}(id)
	}
	close(start)
	wg.Wait()
	close(errs)

	successes, failures := 0, 0
	for err := range errs {
		if err == nil {
			successes++
		} else {
			failures++
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("concurrent demotions successes=%d failures=%d want=1/1", successes, failures)
	}
	var activeAdmins int
	if err := d.QueryRow(`SELECT COUNT(*) FROM users WHERE role='admin' AND active=1`).Scan(&activeAdmins); err != nil {
		t.Fatal(err)
	}
	if activeAdmins != 1 {
		t.Fatalf("active administrators after concurrent demotion=%d want=1", activeAdmins)
	}
}
