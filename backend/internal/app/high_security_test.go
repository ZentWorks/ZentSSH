package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHighInlinePreviewAllowsOnlyPassiveRasterImages(t *testing.T) {
	allowed := map[string]string{
		"image.png":  "image/png",
		"image.JPG":  "image/jpeg",
		"image.webp": "image/webp",
		"image.avif": "image/avif",
	}
	for name, want := range allowed {
		got, ok := safeInlinePreviewContentType(name)
		if !ok || got != want {
			t.Fatalf("%s: got (%q,%v), want (%q,true)", name, got, ok, want)
		}
	}
	for _, name := range []string{"payload.html", "payload.svg", "payload.js", "payload.xml", "payload.xhtml", "payload.txt"} {
		if got, ok := safeInlinePreviewContentType(name); ok {
			t.Fatalf("active/non-image inline format %s accepted as %s", name, got)
		}
	}
}

func TestHighPasswordHashConcurrencyCanShedLoad(t *testing.T) {
	a := &App{passwordHashSem: make(chan struct{}, 1)}
	a.passwordHashSem <- struct{}{}
	if ok, saturated := a.checkPasswordLimited("invalid", "password"); ok || !saturated {
		t.Fatalf("check result ok=%v saturated=%v", ok, saturated)
	}
	if hash, saturated := a.hashPasswordLimited("very-secret-password"); hash != "" || !saturated {
		t.Fatalf("hash=%q saturated=%v", hash, saturated)
	}
	<-a.passwordHashSem
}

func TestHighMFAChallengeDoesNotResetLoginRateLimit(t *testing.T) {
	a := loginTestApp(t)
	userID := addLoginTestUser(t, a, "mfa-limit@example.test", "very-secret-password")
	if _, err := a.DB.Exec(`UPDATE users SET mfa_enabled=1 WHERE id=?`, userID); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	req.RemoteAddr = "198.51.100.10:4321"
	if ok, _ := a.allowLoginAttempt(req); !ok {
		t.Fatal("initial login rate-limit reservation was unexpectedly blocked")
	}
	key := a.clientIP(req)
	before := a.loginAttempts[key]
	if before == nil || before.Count != 1 {
		t.Fatalf("initial bucket=%#v", before)
	}
	rec := httptest.NewRecorder()
	a.loginWith(rec, req, "mfa-limit@example.test", "very-secret-password")
	if rec.Code != http.StatusOK {
		t.Fatalf("loginWith status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["mfaRequired"] != true {
		t.Fatalf("response=%#v", out)
	}
	a.rateMu.Lock()
	after := a.loginAttempts[key]
	a.rateMu.Unlock()
	if after == nil || after.Count != 1 {
		t.Fatalf("MFA challenge reset login limiter: %#v", after)
	}
}

func TestHighSensitiveAuthRateLimitIsIndependentAndResettable(t *testing.T) {
	a := &App{cfg: runtimeConfig{LoginLimit: 2, LoginWindow: time.Minute}, loginAttempts: map[string]*loginBucket{}}
	req := httptest.NewRequest(http.MethodPost, "/api/me/oidc/start", nil)
	req.RemoteAddr = "198.51.100.25:4444"
	if ok, _ := a.allowSensitiveAuthAttempt(req, 42); !ok {
		t.Fatal("first sensitive verification attempt was blocked")
	}
	if ok, _ := a.allowSensitiveAuthAttempt(req, 42); !ok {
		t.Fatal("second sensitive verification attempt was blocked")
	}
	if ok, _ := a.allowSensitiveAuthAttempt(req, 42); ok {
		t.Fatal("sensitive verification rate limit was not enforced")
	}
	if ok, _ := a.allowLoginAttempt(req); !ok {
		t.Fatal("sensitive verification attempts unexpectedly consumed the login bucket")
	}
	a.resetSensitiveAuthAttempts(req, 42)
	if ok, _ := a.allowSensitiveAuthAttempt(req, 42); !ok {
		t.Fatal("sensitive verification bucket was not reset")
	}
}

func TestHighOIDCCallbackRejectsStateNotBoundToBrowser(t *testing.T) {
	a := &App{cfg: runtimeConfig{CookieSecure: "false"}}
	for _, cookie := range []string{"", "other-state"} {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?state=expected-state&code=code", nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "zentssh_oidc_state", Value: cookie})
		}
		rec := httptest.NewRecorder()
		a.oidcCallback(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("cookie=%q status=%d body=%s", cookie, rec.Code, rec.Body.String())
		}
		if location := rec.Header().Get("Location"); !strings.Contains(location, "oidc_error=") {
			t.Fatalf("cookie=%q unexpected redirect=%q", cookie, location)
		}
	}
}

func TestHighOIDCLinkRequiresCurrentPasswordBeforeProviderAccess(t *testing.T) {
	a := loginTestApp(t)
	userID := addLoginTestUser(t, a, "link@example.test", "very-secret-password")
	req := requestAs(http.MethodPost, "/api/me/oidc/start", `{"providerId":999,"password":"wrong-password"}`, userID, "user")
	req.RemoteAddr = "198.51.100.30:5555"
	rec := httptest.NewRecorder()
	a.oidcLinkStart(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("OIDC link without valid step-up status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "current password") {
		t.Fatalf("unexpected step-up response: %s", rec.Body.String())
	}
}

func TestHighHostKeyTrustRequiresWorkspaceEditPermission(t *testing.T) {
	a, adminID, userID, _ := workspaceTestApp(t)
	workspaceRes, err := a.DB.Exec(`INSERT INTO workspaces(name,created_by) VALUES('Production',?)`, adminID)
	if err != nil {
		t.Fatal(err)
	}
	workspaceID, _ := workspaceRes.LastInsertId()
	if _, err := a.DB.Exec(`INSERT INTO workspace_memberships(workspace_id,user_id,can_use,can_edit) VALUES(?,?,1,0)`, workspaceID, userID); err != nil {
		t.Fatal(err)
	}
	serverRes, err := a.DB.Exec(`INSERT INTO servers(owner_user_id,name,host,username,workspace_id) VALUES(?,?,?,?,?)`, adminID, "Shared", "127.0.0.1", "shared", workspaceID)
	if err != nil {
		t.Fatal(err)
	}
	serverID, _ := serverRes.LastInsertId()

	rec := httptest.NewRecorder()
	a.serverByID(rec, requestAs(http.MethodPost, "/api/servers/"+itoa(serverID)+"/trust-host-key", `{"fingerprint":"SHA256:test"}`, userID, "user"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("use-only member host-key trust status=%d body=%s", rec.Code, rec.Body.String())
	}
}
