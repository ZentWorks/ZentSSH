package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestOpenEnablesForeignKeysOnEveryPooledConnection(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "foreign-keys.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.SetMaxOpenConns(3)

	ctx := context.Background()
	conns := make([]*sql.Conn, 0, 3)
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()
	for i := 0; i < 3; i++ {
		conn, err := d.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
		var enabled int
		if err := conn.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&enabled); err != nil {
			t.Fatal(err)
		}
		if enabled != 1 {
			t.Fatalf("connection %d foreign_keys=%d want=1", i+1, enabled)
		}
	}
}

func TestOpenCleansHistoricalDanglingOIDCRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orphaned-oidc.db")
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	userRes, err := d.Exec(`INSERT INTO users(name,email,password_hash,role) VALUES('Old User','old@example.test','!oidc!fixture','user')`)
	if err != nil {
		d.Close()
		t.Fatal(err)
	}
	userID, err := userRes.LastInsertId()
	if err != nil {
		d.Close()
		t.Fatal(err)
	}
	providerRes, err := d.Exec(`INSERT INTO oidc_providers(name,issuer_url,client_id,redirect_url,enabled,auto_create) VALUES('Authentik','https://auth.example.test','zentssh','https://zentssh.example.test/api/auth/oidc/callback',1,1)`)
	if err != nil {
		d.Close()
		t.Fatal(err)
	}
	providerID, err := providerRes.LastInsertId()
	if err != nil {
		d.Close()
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO oidc_identities(provider_id,user_id,subject,email_claim) VALUES(?,?,?,?)`, providerID, userID, "subject-old", "old@example.test"); err != nil {
		d.Close()
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO oidc_states(state,provider_id,nonce,code_verifier,link_user_id,expires_at) VALUES(?,?,?,?,?,datetime('now','+1 hour'))`, "state-old", providerID, "nonce", "verifier", userID); err != nil {
		d.Close()
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate a database modified by an older pooled connection on which foreign
	// keys were not enabled.
	raw, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(0)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`DELETE FROM users WHERE id=?`, userID); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	d, err = Open(path)
	if err != nil {
		t.Fatalf("reopen with historical orphan: %v", err)
	}
	defer d.Close()
	var identities, states int
	if err := d.QueryRow(`SELECT COUNT(*) FROM oidc_identities WHERE provider_id=? AND subject=?`, providerID, "subject-old").Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT COUNT(*) FROM oidc_states WHERE state=?`, "state-old").Scan(&states); err != nil {
		t.Fatal(err)
	}
	if identities != 0 || states != 0 {
		t.Fatalf("orphan cleanup identities=%d states=%d", identities, states)
	}
}
