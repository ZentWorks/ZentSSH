package app

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVerifyIDTokenRS256(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kid := "test-key"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks" {
			http.NotFound(w, r)
			return
		}
		e := big.NewInt(int64(priv.PublicKey.E)).Bytes()
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(e),
		}}})
	}))
	defer server.Close()

	issuer := "https://idp.example.test/application/o/zentssh"
	provider := oidcProvider{IssuerURL: issuer, ClientID: "zentssh-client"}
	discovery := oidcDiscovery{Issuer: issuer, JWKSURI: server.URL + "/jwks"}
	claims := oidcClaims{
		"iss": issuer, "sub": "user-123", "aud": "zentssh-client", "nonce": "nonce-1",
		"exp": float64(time.Now().Add(5 * time.Minute).Unix()), "iat": float64(time.Now().Add(-time.Minute).Unix()),
		"email": "user@example.test", "email_verified": true,
	}
	token := signRS256(t, priv, kid, claims)
	got, err := verifyIDToken(context.Background(), discovery, provider, token, "nonce-1")
	if err != nil {
		t.Fatalf("verifyIDToken: %v", err)
	}
	if claimString(got, "sub") != "user-123" {
		t.Fatalf("unexpected subject: %q", claimString(got, "sub"))
	}

	// email_verified=false is valid OIDC input. Providers such as authentik
	// intentionally emit false by default; account binding is based on provider+sub.
	unverified := oidcClaims{}
	for k, v := range claims {
		unverified[k] = v
	}
	unverified["email_verified"] = false
	if _, err := verifyIDToken(context.Background(), discovery, provider, signRS256(t, priv, kid, unverified), "nonce-1"); err != nil {
		t.Fatalf("expected signed token with email_verified=false to validate, got %v", err)
	}

	if _, err := verifyIDToken(context.Background(), discovery, provider, token, "wrong"); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("expected nonce mismatch, got %v", err)
	}

	badAud := oidcClaims{}
	for k, v := range claims {
		badAud[k] = v
	}
	badAud["aud"] = "other-client"
	if _, err := verifyIDToken(context.Background(), discovery, provider, signRS256(t, priv, kid, badAud), "nonce-1"); err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("expected audience mismatch, got %v", err)
	}

	multi := oidcClaims{}
	for k, v := range claims {
		multi[k] = v
	}
	multi["aud"] = []any{"zentssh-client", "other"}
	if _, err := verifyIDToken(context.Background(), discovery, provider, signRS256(t, priv, kid, multi), "nonce-1"); err == nil || !strings.Contains(err.Error(), "authorized party") {
		t.Fatalf("expected authorized party error, got %v", err)
	}
	multi["azp"] = "zentssh-client"
	if _, err := verifyIDToken(context.Background(), discovery, provider, signRS256(t, priv, kid, multi), "nonce-1"); err != nil {
		t.Fatalf("expected multi-audience token with azp to pass, got %v", err)
	}
}

func TestNormalizeOIDCProvider(t *testing.T) {
	p := oidcProvider{Name: " Authentik ", IssuerURL: "https://auth.example.test/", ClientID: "client", RedirectURL: "https://ssh.example.test/api/auth/oidc/callback", Scopes: "openid email", Enabled: true}
	if err := normalizeOIDCProvider(&p); err != nil {
		t.Fatal(err)
	}
	if p.Name != "Authentik" || p.IssuerURL != "https://auth.example.test" {
		t.Fatalf("normalization failed: %+v", p)
	}
	p.Scopes = "email profile"
	if err := normalizeOIDCProvider(&p); err == nil {
		t.Fatal("expected openid scope validation error")
	}
}

func signRS256(t *testing.T, priv *rsa.PrivateKey, kid string, claims oidcClaims) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	h := base64.RawURLEncoding.EncodeToString(header)
	p := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := h + "." + p
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestNormalizeOIDCSSOIDUsesShortUnprefixedID(t *testing.T) {
	got, ok := normalizeOIDCSSOID("K8M4P2XQ")
	if !ok || got != "k8m4p2xq" {
		t.Fatalf("normalize = %q, %v", got, ok)
	}
	if _, ok := normalizeOIDCSSOID("sso_k8m4p2xq"); ok {
		t.Fatal("prefixed SSO id must not be accepted")
	}
	if _, ok := normalizeOIDCSSOID("too-short"); ok {
		t.Fatal("invalid SSO id must not be accepted")
	}
}

func TestDirectSSOLinkStartsConfiguredProvider(t *testing.T) {
	var issuer string
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/authorize",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/jwks",
		})
	}))
	defer idp.Close()
	issuer = idp.URL

	a := loginTestApp(t)
	if _, err := a.DB.Exec(`INSERT INTO oidc_providers(sso_id,name,issuer_url,client_id,redirect_url,enabled,auto_create) VALUES(?,?,?,?,?,1,1)`, "k8m4p2xq", "Authentik", issuer, "zentssh", "https://zentssh.example.test/api/auth/oidc/callback"); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/?sso=k8m4p2xq", nil)
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, issuer+"/authorize?") {
		t.Fatalf("unexpected redirect: %q", location)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("direct SSO response should not be cached: %q", rec.Header().Get("Cache-Control"))
	}
}

func TestInvalidDirectSSOIDFallsBackToLoginWithNotice(t *testing.T) {
	a := loginTestApp(t)
	req := httptest.NewRequest(http.MethodGet, "/?sso=missing1", nil)
	rec := httptest.NewRecorder()
	a.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d", rec.Code)
	}
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, "/?oidc_error=") || strings.Contains(location, "sso=") {
		t.Fatalf("unexpected fallback redirect: %q", location)
	}
}

func TestResolveOIDCUserAutoCreatesUserFromClaims(t *testing.T) {
	a := loginTestApp(t)
	res, err := a.DB.Exec(`INSERT INTO oidc_providers(name,issuer_url,client_id,redirect_url,enabled,auto_create) VALUES(?,?,?,?,1,1)`, "Authentik", "https://auth.example.test", "zentssh", "https://zentssh.example.test/api/auth/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	providerID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	p := oidcProvider{ID: providerID, AutoCreate: true, GroupClaim: "groups"}
	claims := oidcClaims{"name": "Fresh SSO User", "preferred_username": "fresh-user", "groups": []any{"users"}}

	userID, err := a.resolveOIDCUser(p, "subject-fresh", "fresh@example.test", claims)
	if err != nil {
		t.Fatalf("resolveOIDCUser: %v", err)
	}
	var name, email, role, passwordHash string
	var active int
	if err := a.DB.QueryRow(`SELECT name,email,role,active,password_hash FROM users WHERE id=?`, userID).Scan(&name, &email, &role, &active, &passwordHash); err != nil {
		t.Fatal(err)
	}
	if name != "Fresh SSO User" || email != "fresh@example.test" || role != "user" || active != 1 {
		t.Fatalf("created user = name=%q email=%q role=%q active=%d", name, email, role, active)
	}
	if !strings.HasPrefix(passwordHash, "!oidc!") {
		t.Fatalf("SSO-only password marker missing: %q", passwordHash)
	}
	var linkedUserID int64
	if err := a.DB.QueryRow(`SELECT user_id FROM oidc_identities WHERE provider_id=? AND subject=?`, providerID, "subject-fresh").Scan(&linkedUserID); err != nil {
		t.Fatal(err)
	}
	if linkedUserID != userID {
		t.Fatalf("identity user=%d want=%d", linkedUserID, userID)
	}

	a.cfg.SessionTTL = time.Hour
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback", nil)
	user, err := a.createSession(rec, req, userID)
	if err != nil {
		t.Fatalf("createSession after auto-create: %v", err)
	}
	if got := user["email"]; got != "fresh@example.test" {
		t.Fatalf("session user email = %#v", got)
	}
	if len(rec.Result().Cookies()) < 2 {
		t.Fatalf("expected session and CSRF cookies, got %d", len(rec.Result().Cookies()))
	}
}

func TestResolveOIDCUserRepairsDanglingIdentityAndAutoCreatesReplacement(t *testing.T) {
	a := loginTestApp(t)
	oldUserID := addLoginTestUser(t, a, "old@example.test", "very-secret-password")
	res, err := a.DB.Exec(`INSERT INTO oidc_providers(name,issuer_url,client_id,redirect_url,enabled,auto_create) VALUES(?,?,?,?,1,1)`, "Authentik", "https://auth.example.test", "zentssh", "https://zentssh.example.test/api/auth/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	providerID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.DB.Exec(`INSERT INTO oidc_identities(provider_id,user_id,subject,email_claim) VALUES(?,?,?,?)`, providerID, oldUserID, "subject-stale", "old@example.test"); err != nil {
		t.Fatal(err)
	}

	// Reproduce the state possible in older builds: one SQLite pooled connection
	// had foreign_keys disabled while the user was deleted, leaving the identity.
	ctx := context.Background()
	conn, err := a.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys=OFF`); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	var fk int
	if err := conn.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if fk != 0 {
		conn.Close()
		t.Fatalf("failed to build historical dangling-identity fixture: foreign_keys=%d", fk)
	}
	if _, err := conn.ExecContext(ctx, `DELETE FROM users WHERE id=?`, oldUserID); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys=ON`); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	var staleCount int
	if err := a.DB.QueryRow(`SELECT COUNT(*) FROM oidc_identities WHERE provider_id=? AND subject=? AND user_id=?`, providerID, "subject-stale", oldUserID).Scan(&staleCount); err != nil {
		t.Fatal(err)
	}
	if staleCount != 1 {
		t.Fatalf("fixture did not retain dangling identity: count=%d", staleCount)
	}

	p := oidcProvider{ID: providerID, AutoCreate: true, GroupClaim: "groups"}
	claims := oidcClaims{"name": "Replacement User", "preferred_username": "replacement"}
	newUserID, err := a.resolveOIDCUser(p, "subject-stale", "replacement@example.test", claims)
	if err != nil {
		t.Fatalf("resolveOIDCUser dangling identity: %v", err)
	}
	if newUserID == oldUserID {
		t.Fatalf("dangling identity reused deleted user id %d", oldUserID)
	}
	var linkedUserID int64
	if err := a.DB.QueryRow(`SELECT user_id FROM oidc_identities WHERE provider_id=? AND subject=?`, providerID, "subject-stale").Scan(&linkedUserID); err != nil {
		t.Fatal(err)
	}
	if linkedUserID != newUserID {
		t.Fatalf("repaired identity user=%d want=%d", linkedUserID, newUserID)
	}
	var name, email string
	if err := a.DB.QueryRow(`SELECT name,email FROM users WHERE id=?`, newUserID).Scan(&name, &email); err != nil {
		t.Fatal(err)
	}
	if name != "Replacement User" || email != "replacement@example.test" {
		t.Fatalf("replacement user name=%q email=%q", name, email)
	}
}

func TestResolveOIDCUserKeepsExistingEmailUnlinked(t *testing.T) {
	a := loginTestApp(t)
	existingID := addLoginTestUser(t, a, "existing@example.test", "very-secret-password")
	res, err := a.DB.Exec(`INSERT INTO oidc_providers(name,issuer_url,client_id,redirect_url,enabled,auto_create) VALUES(?,?,?,?,1,1)`, "Authentik", "https://auth.example.test", "zentssh", "https://zentssh.example.test/api/auth/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	providerID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	_, err = a.resolveOIDCUser(oidcProvider{ID: providerID, AutoCreate: true, GroupClaim: "groups"}, "new-subject", "existing@example.test", oidcClaims{"name": "SSO Name"})
	if err == nil || !strings.Contains(err.Error(), "existing ZentSSH account") {
		t.Fatalf("expected existing-account protection, got %v", err)
	}
	var userCount, identityCount int
	if err := a.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE email=? AND id=?`, "existing@example.test", existingID).Scan(&userCount); err != nil {
		t.Fatal(err)
	}
	if err := a.DB.QueryRow(`SELECT COUNT(*) FROM oidc_identities WHERE provider_id=? AND subject=?`, providerID, "new-subject").Scan(&identityCount); err != nil {
		t.Fatal(err)
	}
	if userCount != 1 || identityCount != 0 {
		t.Fatalf("existing user count=%d identity count=%d", userCount, identityCount)
	}
}
