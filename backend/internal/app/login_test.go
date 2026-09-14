package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	zdb "zentssh.local/backend/internal/db"
)

func loginTestApp(t *testing.T) *App {
	t.Helper()
	database, err := zdb.Open(t.TempDir() + "/zentssh-test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return &App{DB: database, loginAttempts: map[string]*loginBucket{}, cfg: runtimeConfig{LoginLimit: 10, LoginWindow: 10 * time.Minute}}
}

func addLoginTestUser(t *testing.T, a *App, email, password string) int64 {
	t.Helper()
	res, err := a.DB.Exec("INSERT INTO users(name,email,password_hash,role,active) VALUES(?,?,?,?,1)", "Test User", normalizeUserEmail(email), hashPass(password), "user")
	if err != nil {
		t.Fatal(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func addLoginTestProvider(t *testing.T, a *App, userID int64, enabled bool, claimEmail string) int64 {
	t.Helper()
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	res, err := a.DB.Exec(`INSERT INTO oidc_providers(name,issuer_url,client_id,redirect_url,enabled) VALUES(?,?,?,?,?)`, "Authentik", "https://auth.example.test", "zentssh", "https://zentssh.example.test/api/auth/oidc/callback", enabledInt)
	if err != nil {
		t.Fatal(err)
	}
	providerID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.DB.Exec(`INSERT INTO oidc_identities(provider_id,user_id,subject,email_claim) VALUES(?,?,?,?)`, providerID, userID, "subject-1", claimEmail); err != nil {
		t.Fatal(err)
	}
	return providerID
}

func TestLoginDiscoverRoutesLinkedUserToSSO(t *testing.T) {
	a := loginTestApp(t)
	userID := addLoginTestUser(t, a, "local@example.test", "very-secret-password")
	providerID := addLoginTestProvider(t, a, userID, true, "sso@example.test")

	for _, email := range []string{"local@example.test", "sso@example.test"} {
		req := httptest.NewRequest(http.MethodPost, "/api/login/discover", strings.NewReader(`{"email":"`+email+`"}`))
		rec := httptest.NewRecorder()
		a.loginDiscover(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("discover(%s) status = %d, body=%s", email, rec.Code, rec.Body.String())
		}
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got["method"] != "sso" || int64(got["providerId"].(float64)) != providerID {
			t.Fatalf("discover(%s) = %#v", email, got)
		}
	}
}

func TestLoginDiscoverRejectsUnknownEmailFromNormalLoginFlow(t *testing.T) {
	a := loginTestApp(t)
	req := httptest.NewRequest(http.MethodPost, "/api/login/discover", strings.NewReader(`{"email":"missing@example.test"}`))
	rec := httptest.NewRecorder()
	a.loginDiscover(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["method"] != "unavailable" {
		t.Fatalf("method = %#v", got["method"])
	}
}

func TestCorrectLocalPasswordCannotBypassActiveSSOLink(t *testing.T) {
	a := loginTestApp(t)
	userID := addLoginTestUser(t, a, "user@example.test", "very-secret-password")
	providerID := addLoginTestProvider(t, a, userID, true, "user@example.test")

	req := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	rec := httptest.NewRecorder()
	a.loginWith(rec, req, "user@example.test", "very-secret-password")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["code"] != "sso_required" || int64(got["providerId"].(float64)) != providerID {
		t.Fatalf("response = %#v", got)
	}
}

func TestLoginDiscoverDoesNotOfferPasswordForSSOOnlyAccountWithoutActiveProvider(t *testing.T) {
	a := loginTestApp(t)
	res, err := a.DB.Exec("INSERT INTO users(name,email,password_hash,role,active) VALUES(?,?,?,?,1)", "SSO Only", "sso-only@example.test", "!oidc!", "user")
	if err != nil {
		t.Fatal(err)
	}
	userID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	addLoginTestProvider(t, a, userID, false, "sso-only@example.test")

	req := httptest.NewRequest(http.MethodPost, "/api/login/discover", strings.NewReader(`{"email":"sso-only@example.test"}`))
	rec := httptest.NewRecorder()
	a.loginDiscover(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["method"] != "unavailable" {
		t.Fatalf("response = %#v", got)
	}
}

func TestLoginDiscoverDoesNotRouteUnknownUserIntoAutoCreateSSO(t *testing.T) {
	a := loginTestApp(t)
	if _, err := a.DB.Exec(`INSERT INTO oidc_providers(name,issuer_url,client_id,redirect_url,enabled,auto_create) VALUES(?,?,?,?,1,1)`, "Authentik", "https://auth.example.test", "zentssh", "https://zentssh.example.test/api/auth/oidc/callback"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/login/discover", strings.NewReader(`{"email":"new@example.test"}`))
	rec := httptest.NewRecorder()
	a.loginDiscover(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["method"] != "unavailable" {
		t.Fatalf("response = %#v", got)
	}
}

func TestLoginDiscoverDoesNotGuessBetweenMultipleAutoCreateProviders(t *testing.T) {
	a := loginTestApp(t)
	for i := 0; i < 2; i++ {
		if _, err := a.DB.Exec(`INSERT INTO oidc_providers(name,issuer_url,client_id,redirect_url,enabled,auto_create) VALUES(?,?,?,?,1,1)`, "Provider", "https://auth.example.test", "zentssh", "https://zentssh.example.test/api/auth/oidc/callback"); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/login/discover", strings.NewReader(`{"email":"new@example.test"}`))
	rec := httptest.NewRecorder()
	a.loginDiscover(rec, req)
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["method"] != "unavailable" {
		t.Fatalf("response = %#v", got)
	}
}

func TestMFAStatusMarksStoredMFAAsPausedBySSO(t *testing.T) {
	a := loginTestApp(t)
	userID := addLoginTestUser(t, a, "mfa@example.test", "very-secret-password")
	addLoginTestProvider(t, a, userID, true, "mfa@example.test")
	if _, err := a.DB.Exec("UPDATE users SET mfa_enabled=1,mfa_secret_enc='encrypted' WHERE id=?", userID); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/me/mfa", nil)
	req = req.WithContext(context.WithValue(req.Context(), userCtxKey{}, userID))
	rec := httptest.NewRecorder()
	a.mfaStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["enabled"] != true || got["paused"] != true || got["ssoManaged"] != true {
		t.Fatalf("response = %#v", got)
	}
}

func TestMFAConfirmIsBlockedWhileSSOManagesLogin(t *testing.T) {
	a := loginTestApp(t)
	userID := addLoginTestUser(t, a, "confirm@example.test", "very-secret-password")
	addLoginTestProvider(t, a, userID, true, "confirm@example.test")

	req := httptest.NewRequest(http.MethodPost, "/api/me/mfa/confirm", strings.NewReader(`{"code":"123456"}`))
	req = req.WithContext(context.WithValue(req.Context(), userCtxKey{}, userID))
	rec := httptest.NewRecorder()
	a.mfaConfirm(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}
