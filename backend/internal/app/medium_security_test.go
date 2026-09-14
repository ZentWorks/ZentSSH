package app

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type mediumDeadlineRecorder struct {
	*httptest.ResponseRecorder
	readDeadline  time.Time
	writeDeadline time.Time
}

func (r *mediumDeadlineRecorder) SetReadDeadline(deadline time.Time) error {
	r.readDeadline = deadline
	return nil
}

func (r *mediumDeadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	r.writeDeadline = deadline
	return nil
}

func TestMediumSFTPOperationLimits(t *testing.T) {
	a := &App{
		cfg:              runtimeConfig{MaxSFTPOperationsPerUser: 1, MaxTotalSFTPOperations: 2},
		sftpActiveByUser: map[int64]int{},
	}
	if err := a.reserveSFTPOperation(1); err != nil {
		t.Fatal(err)
	}
	if err := a.reserveSFTPOperation(1); err == nil {
		t.Fatal("per-user SFTP concurrency limit not enforced")
	}
	if err := a.reserveSFTPOperation(2); err != nil {
		t.Fatal(err)
	}
	if err := a.reserveSFTPOperation(3); err == nil {
		t.Fatal("global SFTP concurrency limit not enforced")
	}
	a.releaseSFTPOperation(1)
	a.releaseSFTPOperation(2)
}

func TestMediumStreamingSFTPIdleDeadlinesRefresh(t *testing.T) {
	recorder := &mediumDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	controller := http.NewResponseController(recorder)
	reader := &idleDeadlineReader{reader: strings.NewReader("payload"), controller: controller, timeout: 2 * time.Minute}
	buf := make([]byte, 4)
	if _, err := reader.Read(buf); err != nil {
		t.Fatal(err)
	}
	if recorder.readDeadline.IsZero() {
		t.Fatal("upload idle read deadline was not set")
	}
	writer := &idleDeadlineWriter{writer: recorder, controller: controller, timeout: 2 * time.Minute}
	if _, err := writer.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if recorder.writeDeadline.IsZero() {
		t.Fatal("download idle write deadline was not set")
	}
}

func TestMediumWebSessionCountIsBoundedPerUser(t *testing.T) {
	a := loginTestApp(t)
	a.cfg.MaxWebSessionsPerUser = 3
	userID := addLoginTestUser(t, a, "sessions-medium@example.test", "very-secret-password")
	for i := 0; i < 7; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/login", nil)
		if _, err := a.createSession(rec, req, userID); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := a.DB.QueryRow(`SELECT COUNT(*) FROM sessions WHERE user_id=?`, userID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("web sessions=%d want=3", count)
	}
}

func TestMediumPasswordChangeRevokesOtherWebSessions(t *testing.T) {
	a := loginTestApp(t)
	userID := addLoginTestUser(t, a, "password-medium@example.test", "very-secret-password")
	currentRaw := "current-session-token"
	if _, err := a.DB.Exec(`INSERT INTO sessions(id,user_id,expires_at,created_at) VALUES(?,?,?,CURRENT_TIMESTAMP)`, sessionDBID(currentRaw), userID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"old-one", "old-two"} {
		if _, err := a.DB.Exec(`INSERT INTO sessions(id,user_id,expires_at,created_at) VALUES(?,?,?,CURRENT_TIMESTAMP)`, id, userID, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	req := ownedRequest(http.MethodPatch, "/api/me", `{"currentPassword":"very-secret-password","newPassword":"different-secret-password"}`, userID)
	req.AddCookie(&http.Cookie{Name: "zentssh_session", Value: currentRaw})
	rec := httptest.NewRecorder()
	a.me(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var count int
	if err := a.DB.QueryRow(`SELECT COUNT(*) FROM sessions WHERE user_id=?`, userID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("sessions after password change=%d want=1", count)
	}
}

func TestMediumSessionRevocationRequiresCurrentSession(t *testing.T) {
	a := loginTestApp(t)
	userID := addLoginTestUser(t, a, "revoke-medium@example.test", "very-secret-password")
	if _, err := a.DB.Exec(`INSERT INTO sessions(id,user_id,expires_at,created_at) VALUES(?,?,?,CURRENT_TIMESTAMP),(?,?,?,CURRENT_TIMESTAMP)`, "one", userID, time.Now().Add(time.Hour), "two", userID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	tx, err := a.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := revokeOtherWebSessionsTx(tx, httptest.NewRequest(http.MethodPost, "/api/me", nil), userID); err == nil {
		t.Fatal("session revocation proceeded without the current authenticated session cookie")
	}
	var count int
	if err := a.DB.QueryRow(`SELECT COUNT(*) FROM sessions WHERE user_id=?`, userID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("sessions changed after refused revocation: %d", count)
	}
}

func TestMediumInternalErrorsDoNotLeakDetails(t *testing.T) {
	a := &App{}
	rec := httptest.NewRecorder()
	a.internalError(rec, "test", errors.New("sqlite path=/data/secret.db token=super-secret"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "secret.db") || strings.Contains(body, "super-secret") {
		t.Fatalf("internal detail leaked to response: %s", body)
	}
	if !strings.Contains(body, "requestId") {
		t.Fatalf("response has no requestId: %s", body)
	}
}

func TestMediumCSPRestrictsWebSocketsToEffectiveHost(t *testing.T) {
	a := &App{}
	h := a.security(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	req := httptest.NewRequest(http.MethodGet, "http://zentssh.example.test/", nil)
	req.Host = "zentssh.example.test"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	csp := rec.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "connect-src 'self' ws: wss:") {
		t.Fatalf("CSP still permits arbitrary websocket origins: %s", csp)
	}
	if !strings.Contains(csp, "ws://zentssh.example.test") || !strings.Contains(csp, "wss://zentssh.example.test") {
		t.Fatalf("CSP missing same-host websocket sources: %s", csp)
	}
}

func TestMediumLoadServersForScopeReturnsEffectiveTemplateValues(t *testing.T) {
	a, owner, _ := ownershipTestApp(t)
	tr, err := a.DB.Exec(`INSERT INTO server_templates(name,host,port,color,kind,terminal_editor_mode,crontab_editor_mode,visible_to_all,active) VALUES(?,?,?,?,?,?,?,?,?)`, "Template Name", "template.example", 2222, "#123456", "ssh", "nano", "vi", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	templateID, _ := tr.LastInsertId()
	if _, err := a.DB.Exec(`INSERT INTO servers(owner_user_id,name,host,port,username,auth_type,secret_enc,color,kind,terminal_editor_mode,crontab_editor_mode,template_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, owner, "Snapshot", "old.example", 22, "root", "password", "not-decrypted-by-list", "#000000", "ssh", "ask", "ask", templateID); err != nil {
		t.Fatal(err)
	}
	servers, err := a.loadServersForScope(owner, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 || servers[0].Name != "Template Name" || servers[0].Host != "template.example" || servers[0].Port != 2222 {
		t.Fatalf("effective servers=%#v", servers)
	}
}
