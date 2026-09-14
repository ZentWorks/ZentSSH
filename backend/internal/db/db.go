package db

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

func sqliteDSN(path string) string {
	dsn := path
	if !strings.HasPrefix(strings.ToLower(dsn), "file:") {
		if dsn == ":memory:" {
			dsn = "file::memory:"
		} else {
			dsn = "file:" + dsn
		}
	}
	separator := "?"
	if strings.Contains(dsn, "?") {
		separator = "&"
	}
	return dsn + separator + "_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
}

func Open(path string) (*sql.DB, error) {
	// SQLite foreign-key enforcement is connection-local. Put the pragma in the
	// modernc.org/sqlite DSN so database/sql applies it to every physical
	// connection opened by the pool, not only to whichever connection happens to
	// execute the schema initialization below.
	d, e := sql.Open("sqlite", sqliteDSN(path))
	if e != nil {
		return nil, e
	}
	d.SetMaxOpenConns(16)
	d.SetMaxIdleConns(8)
	_, e = d.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'admin',
  active INTEGER NOT NULL DEFAULT 1,
  last_login_at DATETIME NULL,
  mfa_enabled INTEGER NOT NULL DEFAULT 0,
  mfa_secret_enc TEXT NOT NULL DEFAULT '',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS workspaces(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL COLLATE NOCASE UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1,
  created_by INTEGER NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS workspace_memberships(
  workspace_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  can_use INTEGER NOT NULL DEFAULT 1,
  can_create INTEGER NOT NULL DEFAULT 0,
  can_edit INTEGER NOT NULL DEFAULT 0,
  can_delete INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(workspace_id,user_id),
  FOREIGN KEY(workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_workspace_memberships_user ON workspace_memberships(user_id,workspace_id);
CREATE TABLE IF NOT EXISTS server_templates(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL COLLATE NOCASE UNIQUE,
  host TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 22,
  color TEXT NOT NULL DEFAULT '#5aa9ff',
  kind TEXT NOT NULL DEFAULT 'ssh',
  terminal_editor_mode TEXT NOT NULL DEFAULT 'ask',
  crontab_editor_mode TEXT NOT NULL DEFAULT 'ask',
  jump_template_id INTEGER NULL,
  description TEXT NOT NULL DEFAULT '',
  visible_to_all INTEGER NOT NULL DEFAULT 1,
  active INTEGER NOT NULL DEFAULT 1,
  created_by INTEGER NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(jump_template_id) REFERENCES server_templates(id) ON DELETE SET NULL,
  FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS server_template_user_access(
  template_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  PRIMARY KEY(template_id,user_id),
  FOREIGN KEY(template_id) REFERENCES server_templates(id) ON DELETE CASCADE,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_server_template_user_access_user ON server_template_user_access(user_id,template_id);
CREATE TABLE IF NOT EXISTS server_template_workspace_access(
  template_id INTEGER NOT NULL,
  workspace_id INTEGER NOT NULL,
  PRIMARY KEY(template_id,workspace_id),
  FOREIGN KEY(template_id) REFERENCES server_templates(id) ON DELETE CASCADE,
  FOREIGN KEY(workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_server_template_workspace_access_workspace ON server_template_workspace_access(workspace_id,template_id);
CREATE TABLE IF NOT EXISTS sessions(
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS user_settings(
  user_id INTEGER PRIMARY KEY,
  ssh_session_retention TEXT NOT NULL DEFAULT 'inherit',
  show_hidden_files INTEGER NOT NULL DEFAULT 0,
  ui_language TEXT NOT NULL DEFAULT '',
  collapsed_folder_ids TEXT NOT NULL DEFAULT '[]',
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS folders(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  parent_id INTEGER NULL,
  sort_order INTEGER DEFAULT 0,
  workspace_id INTEGER NULL,
  FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(parent_id) REFERENCES folders(id) ON DELETE CASCADE,
  FOREIGN KEY(workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS credential_profiles(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  username TEXT NOT NULL,
  auth_type TEXT NOT NULL DEFAULT 'password',
  secret_enc TEXT NOT NULL DEFAULT '',
  passphrase_enc TEXT NOT NULL DEFAULT '',
  certificate_enc TEXT NOT NULL DEFAULT '',
  shared INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(owner_user_id,name),
  FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS servers(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 22,
  username TEXT NOT NULL,
  auth_type TEXT NOT NULL DEFAULT 'password',
  secret_enc TEXT NOT NULL DEFAULT '',
  folder_id INTEGER NULL,
  color TEXT NOT NULL DEFAULT '#5aa9ff',
  kind TEXT NOT NULL DEFAULT 'ssh',
  credential_profile_id INTEGER NULL,
  jump_host_id INTEGER NULL,
  terminal_editor_mode TEXT NOT NULL DEFAULT 'ask',
  crontab_editor_mode TEXT NOT NULL DEFAULT 'ask',
  workspace_id INTEGER NULL,
  template_id INTEGER NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE SET NULL,
  FOREIGN KEY(credential_profile_id) REFERENCES credential_profiles(id) ON DELETE SET NULL,
  FOREIGN KEY(jump_host_id) REFERENCES servers(id) ON DELETE SET NULL,
  FOREIGN KEY(workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
  FOREIGN KEY(template_id) REFERENCES server_templates(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS known_host_keys(
  server_id INTEGER PRIMARY KEY,
  algorithm TEXT NOT NULL,
  key_base64 TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  trusted_by INTEGER,
  trusted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE,
  FOREIGN KEY(trusted_by) REFERENCES users(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS quick_known_host_keys(
  user_id INTEGER NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  route_key TEXT NOT NULL DEFAULT 'direct',
  algorithm TEXT NOT NULL,
  key_base64 TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  trusted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(user_id,host,port,route_key),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_quick_known_host_keys_user ON quick_known_host_keys(user_id);
CREATE TABLE IF NOT EXISTS mfa_setups(
  user_id INTEGER PRIMARY KEY,
  secret_enc TEXT NOT NULL,
  expires_at DATETIME NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS mfa_recovery_codes(
  user_id INTEGER NOT NULL,
  code_hash TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(user_id,code_hash),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS mfa_challenges(
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires_at DATETIME NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires ON mfa_challenges(expires_at);
CREATE TABLE IF NOT EXISTS audit_logs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);
CREATE TABLE IF NOT EXISTS snippet_folders(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_user_id INTEGER NULL,
  scope TEXT NOT NULL DEFAULT 'private' CHECK(scope IN ('private','shared')),
  name TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_snippet_folders_owner_scope_name ON snippet_folders(owner_user_id,scope,name);
CREATE TABLE IF NOT EXISTS code_snippets(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_user_id INTEGER NULL,
  scope TEXT NOT NULL DEFAULT 'private' CHECK(scope IN ('private','shared')),
  folder_id INTEGER NULL,
  name TEXT NOT NULL,
  content_enc TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY(folder_id) REFERENCES snippet_folders(id) ON DELETE SET NULL
);
CREATE TRIGGER IF NOT EXISTS trg_delete_private_snippets_with_user BEFORE DELETE ON users BEGIN
  DELETE FROM code_snippets WHERE owner_user_id=OLD.id AND scope='private';
END;
CREATE INDEX IF NOT EXISTS idx_code_snippets_owner_scope_name ON code_snippets(owner_user_id,scope,name);
CREATE INDEX IF NOT EXISTS idx_code_snippets_scope_name ON code_snippets(scope,name);
CREATE TABLE IF NOT EXISTS snippet_folder_permissions(
  folder_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  can_use INTEGER NOT NULL DEFAULT 1,
  can_create INTEGER NOT NULL DEFAULT 0,
  can_edit INTEGER NOT NULL DEFAULT 0,
  can_delete INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(folder_id,user_id),
  FOREIGN KEY(folder_id) REFERENCES snippet_folders(id) ON DELETE CASCADE,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_snippet_folder_permissions_user ON snippet_folder_permissions(user_id,folder_id);
-- Legacy table kept so upgrades from 0.2.2 can migrate old global Shared permissions once.
CREATE TABLE IF NOT EXISTS shared_snippet_permissions(
  user_id INTEGER PRIMARY KEY,
  can_use INTEGER NOT NULL DEFAULT 1,
  can_create INTEGER NOT NULL DEFAULT 0,
  can_edit INTEGER NOT NULL DEFAULT 0,
  can_delete INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS transfers(
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  source_server_id INTEGER NOT NULL,
  source_path TEXT NOT NULL,
  target_server_id INTEGER NOT NULL,
  target_path TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  bytes_total INTEGER NOT NULL DEFAULT 0,
  bytes_done INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT '',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  started_at DATETIME NULL,
  finished_at DATETIME NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(source_server_id) REFERENCES servers(id) ON DELETE CASCADE,
  FOREIGN KEY(target_server_id) REFERENCES servers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_transfers_user_created ON transfers(user_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_transfers_status ON transfers(status);
CREATE TABLE IF NOT EXISTS oidc_providers(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sso_id TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL,
  issuer_url TEXT NOT NULL,
  client_id TEXT NOT NULL,
  client_secret_enc TEXT NOT NULL DEFAULT '',
  redirect_url TEXT NOT NULL,
  scopes TEXT NOT NULL DEFAULT 'openid email profile',
  group_claim TEXT NOT NULL DEFAULT 'groups',
  required_group TEXT NOT NULL DEFAULT '',
  admin_group TEXT NOT NULL DEFAULT '',
  token_auth_method TEXT NOT NULL DEFAULT 'client_secret_basic',
  enabled INTEGER NOT NULL DEFAULT 1,
  auto_create INTEGER NOT NULL DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS oidc_identities(
  provider_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  subject TEXT NOT NULL,
  email_claim TEXT NOT NULL DEFAULT '',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(provider_id, subject),
  UNIQUE(provider_id, user_id),
  FOREIGN KEY(provider_id) REFERENCES oidc_providers(id) ON DELETE RESTRICT,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS oidc_states(
  state TEXT PRIMARY KEY,
  provider_id INTEGER NOT NULL,
  nonce TEXT NOT NULL,
  code_verifier TEXT NOT NULL,
  link_user_id INTEGER NULL,
  expires_at DATETIME NOT NULL,
  FOREIGN KEY(provider_id) REFERENCES oidc_providers(id) ON DELETE CASCADE,
  FOREIGN KEY(link_user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_oidc_states_expires ON oidc_states(expires_at);
CREATE INDEX IF NOT EXISTS idx_oidc_identities_user ON oidc_identities(user_id);
`)
	if e != nil {
		_ = d.Close()
		return nil, e
	}

	// Safe additive migrations for installations created by earlier ZentSSH builds.
	migrations := []struct{ table, column, ddl string }{
		{"servers", "credential_profile_id", "ALTER TABLE servers ADD COLUMN credential_profile_id INTEGER NULL REFERENCES credential_profiles(id) ON DELETE SET NULL"},
		{"servers", "jump_host_id", "ALTER TABLE servers ADD COLUMN jump_host_id INTEGER NULL REFERENCES servers(id) ON DELETE SET NULL"},
		{"servers", "terminal_editor_mode", "ALTER TABLE servers ADD COLUMN terminal_editor_mode TEXT NOT NULL DEFAULT 'ask'"},
		{"servers", "crontab_editor_mode", "ALTER TABLE servers ADD COLUMN crontab_editor_mode TEXT NOT NULL DEFAULT 'ask'"},
		{"servers", "owner_user_id", "ALTER TABLE servers ADD COLUMN owner_user_id INTEGER NULL REFERENCES users(id) ON DELETE CASCADE"},
		{"servers", "workspace_id", "ALTER TABLE servers ADD COLUMN workspace_id INTEGER NULL REFERENCES workspaces(id) ON DELETE CASCADE"},
		{"servers", "template_id", "ALTER TABLE servers ADD COLUMN template_id INTEGER NULL REFERENCES server_templates(id) ON DELETE SET NULL"},
		{"folders", "owner_user_id", "ALTER TABLE folders ADD COLUMN owner_user_id INTEGER NULL REFERENCES users(id) ON DELETE CASCADE"},
		{"folders", "workspace_id", "ALTER TABLE folders ADD COLUMN workspace_id INTEGER NULL REFERENCES workspaces(id) ON DELETE CASCADE"},
		{"sessions", "created_at", "ALTER TABLE sessions ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP"},
		{"users", "active", "ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1"},
		{"users", "last_login_at", "ALTER TABLE users ADD COLUMN last_login_at DATETIME NULL"},
		{"users", "mfa_enabled", "ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0"},
		{"users", "mfa_secret_enc", "ALTER TABLE users ADD COLUMN mfa_secret_enc TEXT NOT NULL DEFAULT ''"},
		{"user_settings", "show_hidden_files", "ALTER TABLE user_settings ADD COLUMN show_hidden_files INTEGER NOT NULL DEFAULT 0"},
		{"user_settings", "ui_language", "ALTER TABLE user_settings ADD COLUMN ui_language TEXT NOT NULL DEFAULT ''"},
		{"user_settings", "collapsed_folder_ids", "ALTER TABLE user_settings ADD COLUMN collapsed_folder_ids TEXT NOT NULL DEFAULT '[]'"},
		{"code_snippets", "folder_id", "ALTER TABLE code_snippets ADD COLUMN folder_id INTEGER NULL REFERENCES snippet_folders(id) ON DELETE SET NULL"},
		{"oidc_providers", "sso_id", "ALTER TABLE oidc_providers ADD COLUMN sso_id TEXT NOT NULL DEFAULT ''"},
		{"oidc_providers", "required_group", "ALTER TABLE oidc_providers ADD COLUMN required_group TEXT NOT NULL DEFAULT ''"},
		{"oidc_providers", "admin_group", "ALTER TABLE oidc_providers ADD COLUMN admin_group TEXT NOT NULL DEFAULT ''"},
	}
	for _, m := range migrations {
		ok, err := hasColumn(d, m.table, m.column)
		if err != nil {
			_ = d.Close()
			return nil, err
		}
		if !ok {
			if _, err = d.Exec(m.ddl); err != nil {
				_ = d.Close()
				return nil, fmt.Errorf("migration %s.%s: %w", m.table, m.column, err)
			}
		}
	}
	if err := cleanupOrphanedOIDCRecords(d); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("cleanup orphaned OIDC records: %w", err)
	}
	if err := ensureOIDCProviderSSOIDs(d); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("migrate OIDC provider SSO ids: %w", err)
	}
	if _, err := d.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_providers_sso_id ON oidc_providers(sso_id) WHERE sso_id<>''`); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("create OIDC provider SSO id index: %w", err)
	}
	if err := migratePrivateServerOwnership(d); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("migrate private server ownership: %w", err)
	}
	if _, err := d.Exec(`CREATE INDEX IF NOT EXISTS idx_servers_owner_name ON servers(owner_user_id,name); CREATE INDEX IF NOT EXISTS idx_folders_owner_parent_name ON folders(owner_user_id,parent_id,name); CREATE INDEX IF NOT EXISTS idx_servers_workspace_name ON servers(workspace_id,name); CREATE INDEX IF NOT EXISTS idx_servers_template_owner ON servers(template_id,owner_user_id); CREATE INDEX IF NOT EXISTS idx_servers_credential_profile ON servers(credential_profile_id); CREATE INDEX IF NOT EXISTS idx_servers_jump_host ON servers(jump_host_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_servers_owner_template_unique ON servers(owner_user_id,template_id) WHERE template_id IS NOT NULL; CREATE INDEX IF NOT EXISTS idx_folders_workspace_parent_name ON folders(workspace_id,parent_id,name); CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at); CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id); CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at)`); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("create private server ownership indexes: %w", err)
	}
	if err := ensureAdminSafetyTriggers(d); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("create administrator safety triggers: %w", err)
	}
	if _, err := d.Exec(`CREATE INDEX IF NOT EXISTS idx_code_snippets_folder_name ON code_snippets(folder_id,name)`); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("create code snippet folder index: %w", err)
	}
	if err := migrateSnippetFolders(d); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("migrate snippet folders: %w", err)
	}
	return d, nil
}

func ensureAdminSafetyTriggers(d *sql.DB) error {
	_, err := d.Exec(`
CREATE TRIGGER IF NOT EXISTS trg_users_keep_active_admin_update
BEFORE UPDATE OF role, active ON users
WHEN OLD.role='admin' AND OLD.active=1
 AND (NEW.role<>'admin' OR NEW.active<>1)
 AND NOT EXISTS (SELECT 1 FROM users WHERE id<>OLD.id AND role='admin' AND active=1)
BEGIN
  SELECT RAISE(ABORT, 'cannot disable or demote the last active administrator');
END;
CREATE TRIGGER IF NOT EXISTS trg_users_keep_active_admin_delete
BEFORE DELETE ON users
WHEN OLD.role='admin' AND OLD.active=1
 AND NOT EXISTS (SELECT 1 FROM users WHERE id<>OLD.id AND role='admin' AND active=1)
BEGIN
  SELECT RAISE(ABORT, 'cannot delete the last active administrator');
END;
`)
	return err
}

func cleanupOrphanedOIDCRecords(d *sql.DB) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err = tx.Exec(`DELETE FROM oidc_identities
		WHERE NOT EXISTS (SELECT 1 FROM users u WHERE u.id=oidc_identities.user_id)
		   OR NOT EXISTS (SELECT 1 FROM oidc_providers p WHERE p.id=oidc_identities.provider_id)`); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM oidc_states
		WHERE NOT EXISTS (SELECT 1 FROM oidc_providers p WHERE p.id=oidc_states.provider_id)
		   OR (link_user_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id=oidc_states.link_user_id))`); err != nil {
		return err
	}
	return tx.Commit()
}

func migratePrivateServerOwnership(d *sql.DB) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// ZentSSH 0.2.2 and earlier had one global server tree. There is no creator
	// metadata to recover, so existing data is deterministically assigned to the
	// oldest administrator (or the oldest account as a fallback). New data always
	// receives an explicit owner at insert time.
	var ownerID int64
	err = tx.QueryRow(`SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1`).Scan(&ownerID)
	if errors.Is(err, sql.ErrNoRows) {
		err = tx.QueryRow(`SELECT id FROM users ORDER BY id LIMIT 1`).Scan(&ownerID)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if ownerID > 0 {
		if _, err = tx.Exec(`UPDATE folders SET owner_user_id=? WHERE owner_user_id IS NULL OR owner_user_id=0`, ownerID); err != nil {
			return err
		}
		if _, err = tx.Exec(`UPDATE servers SET owner_user_id=? WHERE owner_user_id IS NULL OR owner_user_id=0`, ownerID); err != nil {
			return err
		}
	}
	// The read-only role is intentionally removed. Existing accounts are promoted
	// to normal users so they can manage their own private server tree.
	if _, err = tx.Exec(`UPDATE users SET role='user' WHERE role IN ('readonly','read-only')`); err != nil {
		return err
	}
	return tx.Commit()
}

func migrateSnippetFolders(d *sql.DB) error {
	var orphanShared int
	if err := d.QueryRow(`SELECT COUNT(*) FROM code_snippets WHERE scope='shared' AND COALESCE(folder_id,0)=0`).Scan(&orphanShared); err != nil {
		return err
	}
	if orphanShared == 0 {
		return nil
	}
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var folderID int64
	err = tx.QueryRow(`SELECT id FROM snippet_folders WHERE scope='shared' AND name='Allgemein' ORDER BY id LIMIT 1`).Scan(&folderID)
	if errors.Is(err, sql.ErrNoRows) {
		res, execErr := tx.Exec(`INSERT INTO snippet_folders(owner_user_id,scope,name) VALUES(NULL,'shared','Allgemein')`)
		if execErr != nil {
			return execErr
		}
		folderID, err = res.LastInsertId()
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE code_snippets SET folder_id=? WHERE scope='shared' AND COALESCE(folder_id,0)=0`, folderID); err != nil {
		return err
	}
	// Before folders existed, shared snippets were usable by default. Preserve that access
	// while migrating any explicit create/edit/delete overrides from the legacy table.
	if _, err = tx.Exec(`INSERT OR IGNORE INTO snippet_folder_permissions(folder_id,user_id,can_use,can_create,can_edit,can_delete)
		SELECT ?,u.id,COALESCE(p.can_use,1),COALESCE(p.can_create,0),COALESCE(p.can_edit,0),COALESCE(p.can_delete,0)
		FROM users u LEFT JOIN shared_snippet_permissions p ON p.user_id=u.id WHERE u.role<>'admin'`, folderID); err != nil {
		return err
	}
	return tx.Commit()
}

const ssoIDAlphabet = "abcdefghijkmnpqrstuvwxyz23456789"

func newSSOID() (string, error) {
	b := make([]byte, 8)
	raw := make([]byte, len(b))
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	for i, value := range raw {
		b[i] = ssoIDAlphabet[int(value)%len(ssoIDAlphabet)]
	}
	return string(b), nil
}

func ensureOIDCProviderSSOIDs(d *sql.DB) error {
	rows, err := d.Query(`SELECT id,sso_id FROM oidc_providers ORDER BY id`)
	if err != nil {
		return err
	}
	type providerRow struct {
		id    int64
		ssoID string
	}
	providers := []providerRow{}
	used := map[string]struct{}{}
	for rows.Next() {
		var item providerRow
		if err := rows.Scan(&item.id, &item.ssoID); err != nil {
			rows.Close()
			return err
		}
		item.ssoID = strings.ToLower(strings.TrimSpace(item.ssoID))
		providers = append(providers, item)
		if item.ssoID != "" {
			if _, exists := used[item.ssoID]; exists {
				rows.Close()
				return fmt.Errorf("duplicate OIDC SSO id %q", item.ssoID)
			}
			used[item.ssoID] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	for _, item := range providers {
		if item.ssoID != "" {
			continue
		}
		var candidate string
		for attempts := 0; attempts < 32; attempts++ {
			candidate, err = newSSOID()
			if err != nil {
				return err
			}
			if _, exists := used[candidate]; !exists {
				break
			}
			candidate = ""
		}
		if candidate == "" {
			return errors.New("could not allocate unique OIDC SSO id")
		}
		if _, err := d.Exec(`UPDATE oidc_providers SET sso_id=? WHERE id=? AND TRIM(sso_id)=''`, candidate, item.id); err != nil {
			return err
		}
		used[candidate] = struct{}{}
	}
	return nil
}

func hasColumn(d *sql.DB, table, column string) (bool, error) {
	if strings.ContainsAny(table, "'\"; ") {
		return false, errors.New("invalid table name")
	}
	rows, err := d.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var def any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &def, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// ValidateSnapshot performs read-only integrity and schema checks on a staged
// ZentSSH database before it is allowed to replace the live database.
func ValidateSnapshot(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("database path is required")
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() == 0 {
		return errors.New("database snapshot is not a regular non-empty file")
	}
	dsn := "file:" + filepath.ToSlash(path) + "?mode=ro&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	d, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	defer d.Close()
	var quick string
	if err := d.QueryRow(`PRAGMA quick_check`).Scan(&quick); err != nil {
		return err
	}
	if strings.ToLower(strings.TrimSpace(quick)) != "ok" {
		return fmt.Errorf("sqlite quick_check failed: %s", quick)
	}
	for _, table := range []string{"users", "servers", "sessions", "credential_profiles", "oidc_providers"} {
		var count int
		if err := d.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			return fmt.Errorf("required ZentSSH table %q is missing", table)
		}
	}
	return nil
}
