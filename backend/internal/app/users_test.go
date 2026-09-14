package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminUserDeleteExplicitlyRemovesOIDCAuthRecords(t *testing.T) {
	a := loginTestApp(t)
	currentUserID := addLoginTestUser(t, a, "operator@example.test", "very-secret-password")
	targetUserID := addLoginTestUser(t, a, "target@example.test", "very-secret-password")

	providerRes, err := a.DB.Exec(`INSERT INTO oidc_providers(name,issuer_url,client_id,redirect_url,enabled,auto_create) VALUES(?,?,?,?,1,1)`, "Authentik", "https://auth.example.test", "zentssh", "https://zentssh.example.test/api/auth/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	providerID, err := providerRes.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.DB.Exec(`INSERT INTO oidc_identities(provider_id,user_id,subject,email_claim) VALUES(?,?,?,?)`, providerID, targetUserID, "target-subject", "target@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DB.Exec(`INSERT INTO oidc_states(state,provider_id,nonce,code_verifier,link_user_id,expires_at) VALUES(?,?,?,?,?,datetime('now','+1 hour'))`, "target-link-state", providerID, "nonce", "verifier", targetUserID); err != nil {
		t.Fatal(err)
	}

	// Force this test through one pooled connection with FK enforcement disabled.
	// The endpoint must still explicitly clear the SSO records instead of relying
	// solely on ON DELETE CASCADE.
	a.DB.SetMaxOpenConns(1)
	conn, err := a.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), `PRAGMA foreign_keys=OFF`); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/admin/users/%d", targetUserID), nil)
	req = req.WithContext(context.WithValue(req.Context(), userCtxKey{}, currentUserID))
	rec := httptest.NewRecorder()
	a.adminUserByID(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", rec.Code, rec.Body.String())
	}

	var users, identities, states int
	if err := a.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE id=?`, targetUserID).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := a.DB.QueryRow(`SELECT COUNT(*) FROM oidc_identities WHERE user_id=?`, targetUserID).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if err := a.DB.QueryRow(`SELECT COUNT(*) FROM oidc_states WHERE link_user_id=?`, targetUserID).Scan(&states); err != nil {
		t.Fatal(err)
	}
	if users != 0 || identities != 0 || states != 0 {
		t.Fatalf("delete left users=%d identities=%d states=%d", users, identities, states)
	}
}
