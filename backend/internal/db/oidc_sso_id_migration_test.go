package db

import (
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestOpenBackfillsStableOIDCSSOID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zentssh.db")
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO oidc_providers(name,issuer_url,client_id,redirect_url,enabled) VALUES('Authentik','https://auth.example.test','client','https://ssh.example.test/api/auth/oidc/callback',1)`); err != nil {
		d.Close()
		t.Fatal(err)
	}
	d.Close()

	d, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var ssoID string
	if err := d.QueryRow(`SELECT sso_id FROM oidc_providers LIMIT 1`).Scan(&ssoID); err != nil {
		t.Fatal(err)
	}
	if len(ssoID) != 8 {
		t.Fatalf("unexpected SSO id %q", ssoID)
	}
	for _, ch := range ssoID {
		if !strings.ContainsRune(ssoIDAlphabet, ch) {
			t.Fatalf("invalid character %q in SSO id %q", ch, ssoID)
		}
	}

	var indexCount int
	if err := d.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_oidc_providers_sso_id'`).Scan(&indexCount); err != nil {
		t.Fatal(err)
	}
	if indexCount != 1 {
		t.Fatal("unique SSO id index missing")
	}
	d.Close()
	d, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var afterRestart string
	if err := d.QueryRow(`SELECT sso_id FROM oidc_providers LIMIT 1`).Scan(&afterRestart); err != nil {
		t.Fatal(err)
	}
	if afterRestart != ssoID {
		t.Fatalf("SSO id changed across reopen: %q -> %q", ssoID, afterRestart)
	}
}
