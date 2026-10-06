package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func responseCookieByName(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func TestWebSessionSlidesWhenNearExpiry(t *testing.T) {
	a := loginTestApp(t)
	a.cfg.SessionTTL = 10 * time.Minute
	userID := addLoginTestUser(t, a, "sliding@example.test", "very-secret-password")

	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	if _, err := a.createSession(loginRec, loginReq, userID); err != nil {
		t.Fatal(err)
	}
	sessionCookie := responseCookieByName(t, loginRec, "zentssh_session")
	if sessionCookie == nil {
		t.Fatal("session cookie missing")
	}
	nearExpiry := time.Now().Add(2 * time.Minute)
	if _, err := a.DB.Exec("UPDATE sessions SET expires_at=? WHERE id=?", nearExpiry, sessionDBID(sessionCookie.Value)); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.AddCookie(sessionCookie)
	rec := httptest.NewRecorder()
	a.auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var renewed time.Time
	if err := a.DB.QueryRow("SELECT expires_at FROM sessions WHERE id=?", sessionDBID(sessionCookie.Value)).Scan(&renewed); err != nil {
		t.Fatal(err)
	}
	if renewed.Before(time.Now().Add(9 * time.Minute)) {
		t.Fatalf("session was not renewed far enough: %v", renewed)
	}
	setSession := responseCookieByName(t, rec, "zentssh_session")
	if setSession == nil || setSession.Value != sessionCookie.Value || setSession.Expires.Before(time.Now().Add(9*time.Minute)) {
		t.Fatalf("renewed session cookie missing or invalid: %#v", setSession)
	}
	csrf := responseCookieByName(t, rec, "zentssh_csrf")
	if csrf == nil || csrf.Value == "" || csrf.Expires.Before(time.Now().Add(9*time.Minute)) {
		t.Fatalf("renewed csrf cookie missing or invalid: %#v", csrf)
	}
}

func TestWebSessionDoesNotWriteWhenExpiryIsStillFresh(t *testing.T) {
	a := loginTestApp(t)
	a.cfg.SessionTTL = 10 * time.Minute
	userID := addLoginTestUser(t, a, "fresh@example.test", "very-secret-password")

	loginRec := httptest.NewRecorder()
	if _, err := a.createSession(loginRec, httptest.NewRequest(http.MethodPost, "/api/login", nil), userID); err != nil {
		t.Fatal(err)
	}
	sessionCookie := responseCookieByName(t, loginRec, "zentssh_session")
	if sessionCookie == nil {
		t.Fatal("session cookie missing")
	}
	var before time.Time
	if err := a.DB.QueryRow("SELECT expires_at FROM sessions WHERE id=?", sessionDBID(sessionCookie.Value)).Scan(&before); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.AddCookie(sessionCookie)
	rec := httptest.NewRecorder()
	a.auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var after time.Time
	if err := a.DB.QueryRow("SELECT expires_at FROM sessions WHERE id=?", sessionDBID(sessionCookie.Value)).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !after.Equal(before) {
		t.Fatalf("fresh session was unexpectedly rewritten: before=%v after=%v", before, after)
	}
	if responseCookieByName(t, rec, "zentssh_session") != nil {
		t.Fatal("fresh session unexpectedly emitted a replacement session cookie")
	}
}

func TestExpiredWebSessionReturnsUnauthorizedAndIsDeleted(t *testing.T) {
	a := loginTestApp(t)
	a.cfg.SessionTTL = 10 * time.Minute
	userID := addLoginTestUser(t, a, "expired@example.test", "very-secret-password")

	loginRec := httptest.NewRecorder()
	if _, err := a.createSession(loginRec, httptest.NewRequest(http.MethodPost, "/api/login", nil), userID); err != nil {
		t.Fatal(err)
	}
	sessionCookie := responseCookieByName(t, loginRec, "zentssh_session")
	if _, err := a.DB.Exec("UPDATE sessions SET expires_at=? WHERE id=?", time.Now().Add(-time.Minute), sessionDBID(sessionCookie.Value)); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.AddCookie(sessionCookie)
	rec := httptest.NewRecorder()
	a.auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var count int
	if err := a.DB.QueryRow("SELECT COUNT(*) FROM sessions WHERE id=?", sessionDBID(sessionCookie.Value)).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expired session still exists: count=%d", count)
	}
}

func TestSessionKeepaliveRenewsAuthenticatedSession(t *testing.T) {
	a := loginTestApp(t)
	a.cfg.SessionTTL = 10 * time.Minute
	userID := addLoginTestUser(t, a, "keepalive@example.test", "very-secret-password")

	loginRec := httptest.NewRecorder()
	if _, err := a.createSession(loginRec, httptest.NewRequest(http.MethodPost, "/api/login", nil), userID); err != nil {
		t.Fatal(err)
	}
	sessionCookie := responseCookieByName(t, loginRec, "zentssh_session")
	csrfCookie := responseCookieByName(t, loginRec, "zentssh_csrf")
	if sessionCookie == nil || csrfCookie == nil {
		t.Fatal("authentication cookies missing")
	}
	if _, err := a.DB.Exec("UPDATE sessions SET expires_at=? WHERE id=?", time.Now().Add(2*time.Minute), sessionDBID(sessionCookie.Value)); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/session/keepalive", nil)
	req.AddCookie(sessionCookie)
	req.AddCookie(csrfCookie)
	req.Header.Set("X-CSRF-Token", csrfCookie.Value)
	rec := httptest.NewRecorder()
	a.auth(http.HandlerFunc(a.sessionKeepalive)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var renewed time.Time
	if err := a.DB.QueryRow("SELECT expires_at FROM sessions WHERE id=?", sessionDBID(sessionCookie.Value)).Scan(&renewed); err != nil {
		t.Fatal(err)
	}
	if renewed.Before(time.Now().Add(9 * time.Minute)) {
		t.Fatalf("keepalive did not renew session: %v", renewed)
	}
}

func TestDisabledUserSessionIsNotRenewed(t *testing.T) {
	a := loginTestApp(t)
	a.cfg.SessionTTL = 10 * time.Minute
	userID := addLoginTestUser(t, a, "disabled@example.test", "very-secret-password")

	loginRec := httptest.NewRecorder()
	if _, err := a.createSession(loginRec, httptest.NewRequest(http.MethodPost, "/api/login", nil), userID); err != nil {
		t.Fatal(err)
	}
	sessionCookie := responseCookieByName(t, loginRec, "zentssh_session")
	nearExpiry := time.Now().Add(2 * time.Minute)
	if _, err := a.DB.Exec("UPDATE sessions SET expires_at=? WHERE id=?", nearExpiry, sessionDBID(sessionCookie.Value)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DB.Exec("UPDATE users SET active=0 WHERE id=?", userID); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.AddCookie(sessionCookie)
	rec := httptest.NewRecorder()
	a.auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var count int
	if err := a.DB.QueryRow("SELECT COUNT(*) FROM sessions WHERE id=?", sessionDBID(sessionCookie.Value)).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("disabled user's web session was not revoked: count=%d", count)
	}
	setSession := responseCookieByName(t, rec, "zentssh_session")
	if setSession == nil || setSession.MaxAge >= 0 {
		t.Fatalf("disabled user did not receive a clearing session cookie: %#v", setSession)
	}
}
