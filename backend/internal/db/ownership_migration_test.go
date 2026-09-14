package db

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func TestMigratePrivateServerOwnershipAssignsLegacyTreeAndPromotesReadOnly(t *testing.T) {
	d, err := sql.Open("sqlite", t.TempDir()+"/legacy.db")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := d.Exec(`PRAGMA foreign_keys=ON;
CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, role TEXT NOT NULL);
CREATE TABLE folders(id INTEGER PRIMARY KEY AUTOINCREMENT, owner_user_id INTEGER NULL, name TEXT NOT NULL);
CREATE TABLE servers(id INTEGER PRIMARY KEY AUTOINCREMENT, owner_user_id INTEGER NULL, name TEXT NOT NULL);
INSERT INTO users(role) VALUES('admin'),('readonly'),('user');
INSERT INTO folders(owner_user_id,name) VALUES(NULL,'Legacy Folder');
INSERT INTO servers(owner_user_id,name) VALUES(NULL,'Legacy Server');`); err != nil {
		t.Fatal(err)
	}
	if err := migratePrivateServerOwnership(d); err != nil {
		t.Fatal(err)
	}
	var folderOwner, serverOwner int64
	if err := d.QueryRow("SELECT owner_user_id FROM folders WHERE name='Legacy Folder'").Scan(&folderOwner); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow("SELECT owner_user_id FROM servers WHERE name='Legacy Server'").Scan(&serverOwner); err != nil {
		t.Fatal(err)
	}
	if folderOwner != 1 || serverOwner != 1 {
		t.Fatalf("legacy ownership folder=%d server=%d want=1", folderOwner, serverOwner)
	}
	var role string
	if err := d.QueryRow("SELECT role FROM users WHERE id=2").Scan(&role); err != nil {
		t.Fatal(err)
	}
	if role != "user" {
		t.Fatalf("legacy readonly role=%q want=user", role)
	}
}
