package app

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/argon2"
	zcrypto "zentssh.local/backend/internal/crypto"
	"zentssh.local/backend/internal/sshx"
)

const Version = "0.2.2-dev"

type App struct {
	DB                  *sql.DB
	Box                 *zcrypto.Box
	WebDir              string
	upgrader            websocket.Upgrader
	mu                  sync.Mutex
	setupMu             sync.Mutex
	mfaMu               sync.Mutex
	live                map[string]*LiveSession
	cfg                 runtimeConfig
	rateMu              sync.Mutex
	loginAttempts       map[string]*loginBucket
	sessionReservations int
	sessionReserveUser  map[int64]int
	sessionStop         chan struct{}
	sessionStopOnce     sync.Once
	transferMu          sync.Mutex
	activeTransfers     map[string]*activeTransfer
	passwordHashSem     chan struct{}
	sftpMu              sync.Mutex
	sftpActiveTotal     int
	sftpActiveByUser    map[int64]int
	backupMu            sync.Mutex
	dataDir             string
	masterKey           []byte
	externalMasterKey   bool
	restartFn           func()
}
type userCtxKey struct{}

type Server struct {
	ID                  int64  `json:"id"`
	OwnerUserID         int64  `json:"-"`
	Name                string `json:"name"`
	Host                string `json:"host"`
	Port                int    `json:"port"`
	Username            string `json:"username"`
	AuthType            string `json:"authType"`
	Secret              string `json:"secret,omitempty"`
	FolderID            *int64 `json:"folderId"`
	Color               string `json:"color"`
	Kind                string `json:"kind"`
	CredentialProfileID *int64 `json:"credentialProfileId"`
	JumpHostID          *int64 `json:"jumpHostId"`
	TerminalEditorMode  string `json:"terminalEditorMode"`
	CrontabEditorMode   string `json:"crontabEditorMode"`
	HostKeyTrusted      bool   `json:"hostKeyTrusted"`
	Status              string `json:"status,omitempty"`
	WorkspaceID         *int64 `json:"workspaceId,omitempty"`
	WorkspaceName       string `json:"workspaceName,omitempty"`
	TemplateID          *int64 `json:"templateId,omitempty"`
	TemplateName        string `json:"templateName,omitempty"`
	TemplateActive      bool   `json:"templateActive"`
	TemplateAccessible  bool   `json:"templateAccessible"`
	TemplateJumpMissing bool   `json:"templateJumpMissing,omitempty"`
	CanUse              bool   `json:"canUse"`
	CanCreate           bool   `json:"canCreate"`
	CanEdit             bool   `json:"canEdit"`
	CanDelete           bool   `json:"canDelete"`
}
type Folder struct {
	ID            int64  `json:"id"`
	OwnerUserID   int64  `json:"-"`
	Name          string `json:"name"`
	ParentID      *int64 `json:"parentId"`
	SortOrder     int    `json:"sortOrder"`
	WorkspaceID   *int64 `json:"workspaceId,omitempty"`
	WorkspaceName string `json:"workspaceName,omitempty"`
	CanUse        bool   `json:"canUse"`
	CanCreate     bool   `json:"canCreate"`
	CanEdit       bool   `json:"canEdit"`
	CanDelete     bool   `json:"canDelete"`
}

func (a *App) ConfigureBackupRestore(dataDir string, masterKey []byte, externalMasterKey bool, restartFn func()) {
	a.dataDir = strings.TrimSpace(dataDir)
	a.masterKey = append(a.masterKey[:0], masterKey...)
	a.externalMasterKey = externalMasterKey
	a.restartFn = restartFn
}

func (a *App) requestRestart() {
	if a.restartFn != nil {
		a.restartFn()
	}
}

func New(db *sql.DB, box *zcrypto.Box, web string) *App {
	cfg := loadRuntimeConfig()
	a := &App{
		DB: db, Box: box, WebDir: web, live: map[string]*LiveSession{}, cfg: cfg,
		loginAttempts: map[string]*loginBucket{}, sessionReserveUser: map[int64]int{},
		sessionStop: make(chan struct{}), activeTransfers: map[string]*activeTransfer{},
		passwordHashSem:  make(chan struct{}, cfg.PasswordHashConcurrency),
		sftpActiveByUser: map[int64]int{},
	}
	if strings.TrimSpace(a.cfg.SetupToken) == "" {
		var userCount int
		if err := a.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount); err != nil {
			log.Printf("warning: could not determine initial setup state: %v", err)
		} else if userCount == 0 {
			b := make([]byte, 24)
			if _, err := rand.Read(b); err != nil {
				log.Printf("warning: could not generate initial setup token: %v", err)
			} else {
				a.cfg.SetupToken = base64.RawURLEncoding.EncodeToString(b)
				log.Printf("initial setup token: %s", a.cfg.SetupToken)
			}
		}
	}
	a.upgrader = websocket.Upgrader{CheckOrigin: a.validWebSocketOrigin}
	go a.sessionJanitor()
	go a.maintenanceJanitor()
	a.initTransferHistory()
	return a
}
func jsonOut(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
func (a *App) internalError(w http.ResponseWriter, operation string, err error) {
	requestID := randID(6)
	log.Printf("internal request error id=%s operation=%s: %v", requestID, operation, err)
	jsonOut(w, http.StatusInternalServerError, map[string]string{"error": "internal server error", "requestId": requestID})
}
func decode(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(v)
}
func randID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func hashPass(p string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	h := argon2.IDKey([]byte(p), salt, 3, 64*1024, 2, 32)
	return base64.RawStdEncoding.EncodeToString(salt) + "." + base64.RawStdEncoding.EncodeToString(h)
}
func checkPass(stored, p string) bool {
	a := strings.Split(stored, ".")
	if len(a) != 2 {
		return false
	}
	salt, e := base64.RawStdEncoding.DecodeString(a[0])
	if e != nil {
		return false
	}
	want, e := base64.RawStdEncoding.DecodeString(a[1])
	if e != nil {
		return false
	}
	if len(salt) != 16 || len(want) != 32 {
		return false
	}
	got := argon2.IDKey([]byte(p), salt, 3, 64*1024, 2, uint32(len(want)))
	return secureEqual(string(want), string(got))
}

func (a *App) checkPasswordLimited(stored, password string) (bool, bool) {
	if a.passwordHashSem == nil {
		return checkPass(stored, password), false
	}
	select {
	case a.passwordHashSem <- struct{}{}:
		defer func() { <-a.passwordHashSem }()
		return checkPass(stored, password), false
	default:
		return false, true
	}
}

func (a *App) hashPasswordLimited(password string) (string, bool) {
	if a.passwordHashSem == nil {
		return hashPass(password), false
	}
	select {
	case a.passwordHashSem <- struct{}{}:
		defer func() { <-a.passwordHashSem }()
		return hashPass(password), false
	default:
		return "", true
	}
}

func (a *App) reserveSFTPOperation(userID int64) error {
	a.sftpMu.Lock()
	defer a.sftpMu.Unlock()
	if a.sftpActiveTotal >= a.cfg.MaxTotalSFTPOperations {
		return fmt.Errorf("global file operation limit reached (%d)", a.cfg.MaxTotalSFTPOperations)
	}
	if a.sftpActiveByUser[userID] >= a.cfg.MaxSFTPOperationsPerUser {
		return fmt.Errorf("file operation limit for user reached (%d)", a.cfg.MaxSFTPOperationsPerUser)
	}
	a.sftpActiveTotal++
	a.sftpActiveByUser[userID]++
	return nil
}

func (a *App) releaseSFTPOperation(userID int64) {
	a.sftpMu.Lock()
	if a.sftpActiveTotal > 0 {
		a.sftpActiveTotal--
	}
	if a.sftpActiveByUser[userID] <= 1 {
		delete(a.sftpActiveByUser, userID)
	} else {
		a.sftpActiveByUser[userID]--
	}
	a.sftpMu.Unlock()
}

func (a *App) Routes() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		jsonOut(w, 200, map[string]any{"status": "ok", "version": Version})
	})
	m.HandleFunc("/api/docs", a.apiDocs)
	m.HandleFunc("/api/openapi.yaml", a.openAPISpec)
	m.HandleFunc("/api/setup/status", a.setupStatus)
	m.HandleFunc("/api/setup", a.setup)
	m.HandleFunc("/api/login", a.login)
	m.HandleFunc("/api/login/discover", a.loginDiscover)
	m.HandleFunc("/api/login/mfa", a.loginMFA)
	m.HandleFunc("/api/auth/providers", a.oidcPublicProviders)
	m.HandleFunc("/api/auth/oidc/start", a.oidcStart)
	m.HandleFunc("/api/auth/oidc/callback", a.oidcCallback)
	m.Handle("/api/admin/users", a.auth(a.admin(http.HandlerFunc(a.adminUsers))))
	m.Handle("/api/admin/users/", a.auth(a.admin(http.HandlerFunc(a.adminUserByID))))
	m.Handle("/api/admin/oidc/providers", a.auth(a.admin(http.HandlerFunc(a.oidcProviders))))
	m.Handle("/api/admin/oidc/providers/", a.auth(a.admin(http.HandlerFunc(a.oidcProviderByID))))
	m.Handle("/api/admin/oidc/test", a.auth(a.admin(http.HandlerFunc(a.oidcTest))))
	m.Handle("/api/admin/backup/status", a.auth(a.admin(http.HandlerFunc(a.adminBackupStatus))))
	m.Handle("/api/admin/backup/export", a.auth(a.admin(http.HandlerFunc(a.adminBackupExport))))
	m.Handle("/api/admin/backup/restore", a.auth(a.admin(http.HandlerFunc(a.adminBackupRestore))))
	m.Handle("/api/me/oidc", a.auth(http.HandlerFunc(a.meOIDC)))
	m.Handle("/api/me/oidc/start", a.auth(http.HandlerFunc(a.oidcLinkStart)))
	m.Handle("/api/logout", a.auth(http.HandlerFunc(a.logout)))
	m.Handle("/api/me", a.auth(http.HandlerFunc(a.me)))
	m.Handle("/api/me/settings", a.auth(http.HandlerFunc(a.meSettings)))
	m.Handle("/api/workspaces", a.auth(http.HandlerFunc(a.workspaces)))
	m.Handle("/api/server-search", a.auth(http.HandlerFunc(a.serverSearch)))
	m.Handle("/api/server-templates", a.auth(http.HandlerFunc(a.publicServerTemplates)))
	m.Handle("/api/server-templates/", a.auth(http.HandlerFunc(a.adoptServerTemplate)))
	m.Handle("/api/admin/workspaces", a.auth(a.admin(http.HandlerFunc(a.adminWorkspaces))))
	m.Handle("/api/admin/workspaces/", a.auth(a.admin(http.HandlerFunc(a.adminWorkspaceByID))))
	m.Handle("/api/admin/workspace-memberships", a.auth(a.admin(http.HandlerFunc(a.adminWorkspaceMemberships))))
	m.Handle("/api/admin/server-templates", a.auth(a.admin(http.HandlerFunc(a.adminServerTemplates))))
	m.Handle("/api/admin/server-templates/", a.auth(a.admin(http.HandlerFunc(a.adminServerTemplateByID))))
	m.Handle("/api/admin/server-template-user-access", a.auth(a.admin(http.HandlerFunc(a.adminServerTemplateUserAccess))))
	m.Handle("/api/code-snippets", a.auth(http.HandlerFunc(a.codeSnippets)))
	m.Handle("/api/code-snippets/", a.auth(http.HandlerFunc(a.codeSnippetByID)))
	m.Handle("/api/snippet-folders", a.auth(http.HandlerFunc(a.snippetFolders)))
	m.Handle("/api/snippet-folders/", a.auth(http.HandlerFunc(a.snippetFolderByID)))
	m.Handle("/api/snippet-permissions", a.auth(http.HandlerFunc(a.codeSnippetPermissions)))
	m.Handle("/api/admin/snippet-folder-permissions", a.auth(a.admin(http.HandlerFunc(a.adminSnippetFolderPermissions))))
	m.Handle("/api/admin/snippet-permissions", a.auth(a.admin(http.HandlerFunc(a.adminCodeSnippetPermissions))))
	m.Handle("/api/admin/snippet-permissions/", a.auth(a.admin(http.HandlerFunc(a.adminCodeSnippetPermissionByUser))))
	m.Handle("/api/me/mfa", a.auth(http.HandlerFunc(a.mfaStatus)))
	m.Handle("/api/me/mfa/setup", a.auth(http.HandlerFunc(a.mfaSetup)))
	m.Handle("/api/me/mfa/confirm", a.auth(http.HandlerFunc(a.mfaConfirm)))
	m.Handle("/api/me/mfa/recovery", a.auth(http.HandlerFunc(a.mfaRegenerateRecovery)))
	m.Handle("/api/me/mfa/disable", a.auth(http.HandlerFunc(a.mfaDisable)))
	m.Handle("/api/servers", a.auth(http.HandlerFunc(a.servers)))
	m.Handle("/api/servers/", a.auth(http.HandlerFunc(a.serverByID)))
	m.Handle("/api/folders", a.auth(http.HandlerFunc(a.folders)))
	m.Handle("/api/folders/", a.auth(http.HandlerFunc(a.folderByID)))
	m.Handle("/api/credential-profiles", a.auth(http.HandlerFunc(a.credentialProfiles)))
	m.Handle("/api/credential-profiles/", a.auth(http.HandlerFunc(a.credentialProfileByID)))
	m.Handle("/api/import/openssh/preview", a.auth(http.HandlerFunc(a.openSSHImportPreviewHandler)))
	m.Handle("/api/import/openssh", a.auth(http.HandlerFunc(a.openSSHImportHandler)))
	m.Handle("/api/files/", a.auth(http.HandlerFunc(a.files)))
	m.Handle("/api/sessions", a.auth(http.HandlerFunc(a.sessions)))
	m.Handle("/api/sessions/quick", a.auth(http.HandlerFunc(a.quickConnect)))
	m.Handle("/api/sessions/", a.auth(http.HandlerFunc(a.sessionByID)))
	m.Handle("/api/transfers", a.auth(http.HandlerFunc(a.transfers)))
	m.Handle("/api/transfers/", a.auth(http.HandlerFunc(a.transferByID)))
	m.Handle("/ws/ssh/", a.auth(http.HandlerFunc(a.wsSSH)))
	fs := http.FileServer(http.Dir(a.WebDir))
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/" {
			if ssoID := strings.TrimSpace(r.URL.Query().Get("sso")); ssoID != "" {
				a.oidcDirectStart(w, r, ssoID)
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/ws/") {
			http.NotFound(w, r)
			return
		}
		p := path.Join(a.WebDir, path.Clean(r.URL.Path))
		if st, e := os.Stat(p); e == nil && !st.IsDir() {
			fs.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, path.Join(a.WebDir, "index.html"))
	})
	return a.security(m)
}
func (a *App) security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		connectSources := "'self'"
		if host := strings.TrimSpace(a.effectiveHost(r)); host != "" && !strings.ContainsAny(host, " \t\r\n/\\;") {
			connectSources += " ws://" + host + " wss://" + host
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data: blob:; connect-src "+connectSources)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		if a.effectiveProto(r) == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

type idleDeadlineReader struct {
	reader     io.Reader
	controller *http.ResponseController
	timeout    time.Duration
}

func (r *idleDeadlineReader) Read(p []byte) (int, error) {
	if r.controller != nil && r.timeout > 0 {
		_ = r.controller.SetReadDeadline(time.Now().Add(r.timeout))
	}
	return r.reader.Read(p)
}

type idleDeadlineWriter struct {
	writer     io.Writer
	controller *http.ResponseController
	timeout    time.Duration
}

func (w *idleDeadlineWriter) Write(p []byte) (int, error) {
	if w.controller != nil && w.timeout > 0 {
		_ = w.controller.SetWriteDeadline(time.Now().Add(w.timeout))
	}
	return w.writer.Write(p)
}

func (a *App) setupStatus(w http.ResponseWriter, r *http.Request) {
	var n int
	_ = a.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
	jsonOut(w, 200, map[string]bool{"needed": n == 0})
}
func (a *App) setup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	a.setupMu.Lock()
	defer a.setupMu.Unlock()
	var n int
	_ = a.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
	if n > 0 {
		jsonOut(w, 409, map[string]string{"error": "setup already completed"})
		return
	}
	if strings.TrimSpace(a.cfg.SetupToken) == "" {
		jsonOut(w, http.StatusServiceUnavailable, map[string]string{"error": "initial setup is not available"})
		return
	}
	var x struct {
		Name       string `json:"name"`
		Email      string `json:"email"`
		Password   string `json:"password"`
		SetupToken string `json:"setupToken"`
	}
	if decode(r, &x) != nil || len(x.Password) < 10 || x.Email == "" {
		jsonOut(w, 400, map[string]string{"error": "name, email and password (10+ chars) required"})
		return
	}
	if !secureEqual(strings.TrimSpace(a.cfg.SetupToken), strings.TrimSpace(x.SetupToken)) {
		jsonOut(w, http.StatusUnauthorized, map[string]string{"error": "invalid setup token"})
		return
	}
	passwordHash, saturated := a.hashPasswordLimited(x.Password)
	if saturated {
		jsonOut(w, http.StatusTooManyRequests, map[string]string{"error": "authentication capacity reached; try again shortly"})
		return
	}
	_, e := a.DB.Exec("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)", x.Name, strings.ToLower(x.Email), passwordHash, "admin")
	if e != nil {
		a.internalError(w, "app", e)
		return
	}
	a.loginWith(w, r, x.Email, x.Password)
}
func (a *App) loginDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if ok, retry := a.allowLoginDiscovery(r); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
		jsonOut(w, http.StatusTooManyRequests, map[string]string{"error": "too many login checks; try again later"})
		return
	}
	var in struct {
		Email string `json:"email"`
	}
	if decode(r, &in) != nil || normalizeUserEmail(in.Email) == "" {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "email required"})
		return
	}
	email := normalizeUserEmail(in.Email)
	if providerID, providerName, ok, err := a.activeSSOForEmail(email); err != nil {
		jsonOut(w, http.StatusInternalServerError, map[string]string{"error": "could not resolve login method"})
		return
	} else if ok {
		jsonOut(w, http.StatusOK, map[string]any{"method": "sso", "providerId": providerID, "providerName": providerName})
		return
	}

	var userID int64
	var active int
	var passwordHash string
	if err := a.DB.QueryRow("SELECT id,active,password_hash FROM users WHERE email=?", email).Scan(&userID, &active, &passwordHash); err == nil {
		if active == 0 || strings.HasPrefix(passwordHash, "!oidc!") {
			jsonOut(w, http.StatusOK, map[string]any{"method": "unavailable"})
			return
		}
		jsonOut(w, http.StatusOK, map[string]any{"method": "password"})
		return
	} else if !errors.Is(err, sql.ErrNoRows) {
		jsonOut(w, http.StatusInternalServerError, map[string]string{"error": "could not resolve login method"})
		return
	}

	// Unknown email addresses are never routed into JIT SSO from the normal
	// ZentSSH login form. Automatic OIDC user creation is intentionally reached
	// only through an explicit provider start, for example /?sso=<ssoId>.
	jsonOut(w, http.StatusOK, map[string]any{"method": "unavailable"})
}

func (a *App) activeSSOForEmail(email string) (int64, string, bool, error) {
	email = normalizeUserEmail(email)
	if email == "" {
		return 0, "", false, nil
	}
	var providerID int64
	var providerName string
	err := a.DB.QueryRow(`SELECT p.id,p.name
		FROM oidc_identities i
		JOIN oidc_providers p ON p.id=i.provider_id
		JOIN users u ON u.id=i.user_id
		WHERE u.active=1 AND p.enabled=1
		  AND (LOWER(u.email)=? OR LOWER(i.email_claim)=?)
		ORDER BY CASE WHEN LOWER(u.email)=? THEN 0 ELSE 1 END,p.name,p.id
		LIMIT 1`, email, email, email).Scan(&providerID, &providerName)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", false, nil
	}
	if err != nil {
		return 0, "", false, err
	}
	return providerID, providerName, true, nil
}

func (a *App) activeSSOForUser(userID int64) (int64, string, bool, error) {
	var providerID int64
	var providerName string
	err := a.DB.QueryRow(`SELECT p.id,p.name
		FROM oidc_identities i
		JOIN oidc_providers p ON p.id=i.provider_id
		WHERE i.user_id=? AND p.enabled=1
		ORDER BY p.name,p.id
		LIMIT 1`, userID).Scan(&providerID, &providerName)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", false, nil
	}
	if err != nil {
		return 0, "", false, err
	}
	return providerID, providerName, true, nil
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	if ok, retry := a.allowLoginAttempt(r); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
		jsonOut(w, http.StatusTooManyRequests, map[string]string{"error": "too many login attempts; try again later"})
		return
	}
	var x struct{ Email, Password string }
	if decode(r, &x) != nil {
		jsonOut(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	a.loginWith(w, r, x.Email, x.Password)
}
func (a *App) loginWith(w http.ResponseWriter, r *http.Request, email, pw string) {
	var id int64
	var name, hash, userRole string
	var active, mfaEnabled int
	e := a.DB.QueryRow("SELECT id,name,password_hash,role,active,mfa_enabled FROM users WHERE email=?", normalizeUserEmail(email)).Scan(&id, &name, &hash, &userRole, &active, &mfaEnabled)
	if e != nil || active == 0 {
		jsonOut(w, 401, map[string]string{"error": "invalid credentials"})
		return
	}
	passwordOK, saturated := a.checkPasswordLimited(hash, pw)
	if saturated {
		jsonOut(w, http.StatusTooManyRequests, map[string]string{"error": "authentication capacity reached; try again shortly"})
		return
	}
	if !passwordOK {
		jsonOut(w, 401, map[string]string{"error": "invalid credentials"})
		return
	}
	if providerID, _, ssoManaged, se := a.activeSSOForUser(id); se != nil {
		jsonOut(w, 500, map[string]string{"error": "could not resolve login method"})
		return
	} else if ssoManaged {
		a.resetLoginAttempts(r)
		jsonOut(w, http.StatusConflict, map[string]any{"error": "SSO login required", "code": "sso_required", "providerId": providerID})
		return
	}
	if mfaEnabled != 0 {
		challenge, ce := a.beginMFAChallenge(id)
		if ce != nil {
			jsonOut(w, 500, map[string]string{"error": "could not create MFA challenge"})
			return
		}
		jsonOut(w, 200, map[string]any{"mfaRequired": true, "challengeId": challenge})
		return
	}
	user, e := a.createSession(w, r, id)
	if e != nil {
		jsonOut(w, 500, map[string]string{"error": "session creation failed"})
		return
	}
	a.resetLoginAttempts(r)
	jsonOut(w, 200, user)
}

func (a *App) createSession(w http.ResponseWriter, r *http.Request, userID int64) (map[string]any, error) {
	var name, email, userRole string
	var active int
	if e := a.DB.QueryRow("SELECT name,email,role,active FROM users WHERE id=?", userID).Scan(&name, &email, &userRole, &active); e != nil {
		return nil, e
	}
	userRole = normalizeUserRole(userRole)
	if active == 0 || !validUserRole(userRole) {
		return nil, errors.New("user account is disabled or has an invalid role")
	}
	sid := randID(32)
	csrf := randID(32)
	exp := time.Now().Add(a.cfg.SessionTTL)
	tx, e := a.DB.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("UPDATE users SET last_login_at=CURRENT_TIMESTAMP WHERE id=?", userID); e != nil {
		return nil, e
	}
	if _, e = tx.Exec("DELETE FROM sessions WHERE expires_at < ?", time.Now()); e != nil {
		return nil, e
	}
	webSessionLimit := a.cfg.MaxWebSessionsPerUser
	if webSessionLimit < 2 {
		webSessionLimit = 20
	}
	keepExisting := webSessionLimit - 1
	if _, e = tx.Exec(`DELETE FROM sessions WHERE user_id=? AND id NOT IN (
		SELECT id FROM sessions WHERE user_id=? ORDER BY created_at DESC, id DESC LIMIT ?
	)`, userID, userID, keepExisting); e != nil {
		return nil, e
	}
	if _, e = tx.Exec("INSERT INTO sessions(id,user_id,expires_at,created_at) VALUES(?,?,?,CURRENT_TIMESTAMP)", sessionDBID(sid), userID, exp); e != nil {
		return nil, e
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	http.SetCookie(w, &http.Cookie{Name: "zentssh_session", Value: sid, Path: "/", HttpOnly: true, Secure: a.secureCookie(r), SameSite: http.SameSiteLaxMode, Expires: exp})
	a.setCSRFCookie(w, r, csrf, exp)
	return map[string]any{"id": userID, "name": name, "email": email, "role": userRole}, nil
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if c, e := r.Cookie("zentssh_session"); e == nil {
		_, _ = a.DB.Exec("DELETE FROM sessions WHERE id IN (?,?)", sessionDBID(c.Value), c.Value)
	}
	a.clearAuthCookies(w, r)
	jsonOut(w, 200, map[string]bool{"ok": true})
}
func (a *App) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, e := r.Cookie("zentssh_session")
		if e != nil || c.Value == "" {
			jsonOut(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		var userID int64
		var exp time.Time
		lookupID := sessionDBID(c.Value)
		e = a.DB.QueryRow("SELECT user_id,expires_at FROM sessions WHERE id=?", lookupID).Scan(&userID, &exp)
		if errors.Is(e, sql.ErrNoRows) {
			// Compatibility with sessions issued by early development builds.
			e = a.DB.QueryRow("SELECT user_id,expires_at FROM sessions WHERE id=?", c.Value).Scan(&userID, &exp)
		}
		if e != nil || time.Now().After(exp) {
			_, _ = a.DB.Exec("DELETE FROM sessions WHERE id IN (?,?)", lookupID, c.Value)
			a.clearAuthCookies(w, r)
			jsonOut(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		userRole, e := a.roleForUser(userID)
		if e != nil {
			jsonOut(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if !a.csrfOK(r) {
			jsonOut(w, http.StatusForbidden, map[string]string{"error": "CSRF validation failed"})
			return
		}
		if !isUnsafeMethod(r.Method) {
			if c, ce := r.Cookie("zentssh_csrf"); ce != nil || c.Value == "" {
				a.setCSRFCookie(w, r, randID(32), exp)
			}
		}
		ctx := context.WithValue(r.Context(), userCtxKey{}, userID)
		ctx = context.WithValue(ctx, roleCtxKey{}, userRole)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
func uid(r *http.Request) int64 { v, _ := r.Context().Value(userCtxKey{}).(int64); return v }
func (a *App) me(w http.ResponseWriter, r *http.Request) {
	userID := uid(r)
	var name, email, passwordHash string
	if err := a.DB.QueryRow("SELECT name,email,password_hash FROM users WHERE id=?", userID).Scan(&name, &email, &passwordHash); err != nil {
		jsonOut(w, http.StatusInternalServerError, map[string]string{"error": "could not load profile"})
		return
	}
	language, err := a.ensureUserLanguage(userID, r.Header.Get("Accept-Language"))
	if err != nil {
		jsonOut(w, http.StatusInternalServerError, map[string]string{"error": "could not load UI language"})
		return
	}
	providerID, providerName, ssoManaged, ssoErr := a.activeSSOForUser(userID)
	if ssoErr != nil {
		jsonOut(w, http.StatusInternalServerError, map[string]string{"error": "could not load SSO state"})
		return
	}
	respond := func() {
		localPasswordAvailable := !strings.HasPrefix(passwordHash, "!oidc!")
		jsonOut(w, http.StatusOK, map[string]any{
			"id": userID, "name": name, "email": email, "role": role(r), "language": language,
			"localPasswordAvailable": localPasswordAvailable,
			"localLoginEnabled":      localPasswordAvailable && !ssoManaged,
			"ssoManaged":             ssoManaged,
			"ssoProviderId":          providerID,
			"ssoProviderName":        providerName,
		})
	}
	switch r.Method {
	case http.MethodGet:
		respond()
	case http.MethodPatch:
		var in struct {
			Name            string `json:"name"`
			Email           string `json:"email"`
			Language        string `json:"language"`
			CurrentPassword string `json:"currentPassword"`
			NewPassword     string `json:"newPassword"`
		}
		if decode(r, &in) != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		if strings.TrimSpace(in.Name) != "" {
			name = strings.TrimSpace(in.Name)
		}
		if strings.TrimSpace(in.Email) != "" {
			email = normalizeUserEmail(in.Email)
		}
		if name == "" || email == "" {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "name and email are required"})
			return
		}
		if strings.TrimSpace(in.Language) != "" {
			var ok bool
			language, ok = normalizeUILanguage(in.Language)
			if !ok {
				jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid UI language"})
				return
			}
		}
		newPasswordHash := passwordHash
		if in.NewPassword != "" {
			if ssoManaged {
				jsonOut(w, http.StatusConflict, map[string]string{"error": "local password changes are disabled while SSO is linked"})
				return
			}
			if strings.HasPrefix(passwordHash, "!oidc!") {
				jsonOut(w, http.StatusConflict, map[string]string{"error": "this account has no local password"})
				return
			}
			if !a.verifyLocalPassword(userID, in.CurrentPassword) {
				jsonOut(w, http.StatusUnauthorized, map[string]string{"error": "current password is incorrect"})
				return
			}
			if len(in.NewPassword) < 10 {
				jsonOut(w, http.StatusBadRequest, map[string]string{"error": "new password must have at least 10 characters"})
				return
			}
			var saturated bool
			newPasswordHash, saturated = a.hashPasswordLimited(in.NewPassword)
			if saturated {
				jsonOut(w, http.StatusTooManyRequests, map[string]string{"error": "authentication capacity reached; try again shortly"})
				return
			}
		}
		passwordChanged := newPasswordHash != passwordHash
		tx, err := a.DB.Begin()
		if err != nil {
			a.internalError(w, "app", err)
			return
		}
		defer tx.Rollback()
		if _, err = tx.Exec("UPDATE users SET name=?,email=?,password_hash=? WHERE id=?", name, email, newPasswordHash, userID); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "unique") {
				jsonOut(w, http.StatusConflict, map[string]string{"error": "email already exists"})
			} else {
				a.internalError(w, "app", err)
			}
			return
		}
		if _, err = tx.Exec(`INSERT INTO user_settings(user_id,ssh_session_retention,show_hidden_files,ui_language) VALUES(?,?,?,?)
			ON CONFLICT(user_id) DO UPDATE SET ui_language=excluded.ui_language`, userID, "inherit", 0, language); err != nil {
			a.internalError(w, "app", err)
			return
		}
		if passwordChanged {
			if err = revokeOtherWebSessionsTx(tx, r, userID); err != nil {
				a.internalError(w, "profile.password.revoke_sessions", err)
				return
			}
		}
		if err = tx.Commit(); err != nil {
			a.internalError(w, "profile.update.commit", err)
			return
		}
		passwordHash = newPasswordHash
		if passwordChanged {
			a.terminateUserLiveSessions(userID, "password_changed")
			a.terminateUserTransfers(userID)
		}
		a.audit(userID, "profile.update", "language="+language)
		respond()
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
func (a *App) servers(w http.ResponseWriter, r *http.Request) {
	workspaceID, err := workspaceIDFromRequest(r)
	if err != nil {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	switch r.Method {
	case http.MethodGet:
		permissions := fullWorkspacePermissions()
		workspaceName := ""
		workspaceActive := true
		if workspaceID > 0 {
			workspace, p, accessErr := a.requireWorkspacePermission(uid(r), workspaceID, "read")
			if accessErr != nil {
				jsonOut(w, http.StatusNotFound, map[string]string{"error": "workspace not found"})
				return
			}
			permissions, workspaceName, workspaceActive = p, workspace.Name, workspace.Active
		}
		out, loadErr := a.loadServersForScope(uid(r), workspaceID)
		if loadErr != nil {
			a.internalError(w, "servers.list", loadErr)
			return
		}
		for i := range out {
			s := &out[i]
			if workspaceID == 0 {
				s.CanUse, s.CanCreate, s.CanEdit, s.CanDelete = true, true, true, true
			} else {
				s.WorkspaceName = workspaceName
				s.CanUse, s.CanCreate, s.CanEdit, s.CanDelete = permissions.CanUse, permissions.CanCreate, permissions.CanEdit, permissions.CanDelete
				if !workspaceActive {
					s.CanUse, s.CanCreate, s.CanEdit, s.CanDelete = false, false, false, false
				}
			}
			a.decorateTemplateServerAccess(uid(r), role(r), s)
			s.Secret = ""
			s.Status = "unknown"
		}
		jsonOut(w, http.StatusOK, out)
	case http.MethodPost:
		permissions := fullWorkspacePermissions()
		if workspaceID > 0 {
			_, p, accessErr := a.requireWorkspacePermission(uid(r), workspaceID, "create")
			if accessErr != nil {
				jsonOut(w, http.StatusForbidden, map[string]string{"error": "workspace create permission required"})
				return
			}
			permissions = p
		}
		var s Server
		if decode(r, &s) != nil || strings.TrimSpace(s.Name) == "" || strings.TrimSpace(s.Host) == "" {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "name and host required"})
			return
		}
		if s.TemplateID != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "use the server template adoption endpoint"})
			return
		}
		if s.Port == 0 {
			s.Port = 22
		}
		if s.Port < 1 || s.Port > 65535 {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "port must be between 1 and 65535"})
			return
		}
		if s.AuthType == "" {
			s.AuthType = "password"
		}
		if s.Color == "" {
			s.Color = "#5aa9ff"
		}
		if s.Kind == "" {
			s.Kind = "ssh"
		}
		s.TerminalEditorMode = normalizeTerminalEditorMode(s.TerminalEditorMode)
		s.CrontabEditorMode = normalizeCrontabEditorMode(s.CrontabEditorMode)
		if err := a.prepareServerCredentials(uid(r), &s); err != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if workspaceID > 0 && s.CredentialProfileID != nil {
			p, _, _, _, profileErr := a.loadCredentialProfileRaw(*s.CredentialProfileID)
			if profileErr != nil || !p.Shared {
				jsonOut(w, http.StatusBadRequest, map[string]string{"error": "workspace servers require direct credentials or a shared credential profile"})
				return
			}
		}
		if s.CredentialProfileID == nil && strings.TrimSpace(s.Secret) == "" {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "direct server credentials require a password or private key"})
			return
		}
		if err := a.validateFolderForScope(uid(r), workspaceID, s.FolderID, "read"); err != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := a.validateJumpHostForServer(uid(r), 0, workspaceID, s.JumpHostID); err != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		enc := ""
		if s.CredentialProfileID == nil {
			enc, err = a.Box.Encrypt(s.Secret)
			if err != nil {
				jsonOut(w, http.StatusInternalServerError, map[string]string{"error": "credential encryption failed"})
				return
			}
		}
		var workspaceValue any
		if workspaceID > 0 {
			workspaceValue = workspaceID
		}
		res, err := a.DB.Exec(`INSERT INTO servers(owner_user_id,name,host,port,username,auth_type,secret_enc,folder_id,color,kind,credential_profile_id,jump_host_id,terminal_editor_mode,crontab_editor_mode,workspace_id,template_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)`,
			uid(r), strings.TrimSpace(s.Name), strings.TrimSpace(s.Host), s.Port, s.Username, s.AuthType, enc, s.FolderID, s.Color, s.Kind, s.CredentialProfileID, s.JumpHostID, s.TerminalEditorMode, s.CrontabEditorMode, workspaceValue)
		if err != nil {
			a.internalError(w, "app", err)
			return
		}
		s.ID, _ = res.LastInsertId()
		if workspaceID > 0 {
			s.WorkspaceID = &workspaceID
			s.CanUse, s.CanCreate, s.CanEdit, s.CanDelete = permissions.CanUse, permissions.CanCreate, permissions.CanEdit, permissions.CanDelete
		} else {
			s.CanUse, s.CanCreate, s.CanEdit, s.CanDelete = true, true, true, true
		}
		s.Secret = ""
		a.audit(uid(r), "server.create", fmt.Sprintf("server=%d workspace=%d", s.ID, workspaceID))
		jsonOut(w, http.StatusCreated, s)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func parseID(p, prefix string) (int64, error) {
	x := strings.TrimPrefix(p, prefix)
	x = strings.Split(x, "/")[0]
	return strconv.ParseInt(x, 10, 64)
}

func (a *App) serverByID(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.URL.Path, "/api/servers/")
	if err != nil {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	need := "read"
	switch {
	case strings.HasSuffix(r.URL.Path, "/status"), strings.HasSuffix(r.URL.Path, "/connect-check"), strings.HasSuffix(r.URL.Path, "/crontab"):
		need = "use"
	case strings.HasSuffix(r.URL.Path, "/trust-host-key"), strings.HasSuffix(r.URL.Path, "/folder"), strings.HasSuffix(r.URL.Path, "/preferences"), r.Method == http.MethodPatch:
		need = "edit"
	case r.Method == http.MethodDelete:
		need = "delete"
	}
	existing, _, accessErr := a.loadServerForPermission(uid(r), id, need)
	if accessErr != nil {
		if errors.Is(accessErr, sql.ErrNoRows) {
			jsonOut(w, http.StatusNotFound, map[string]string{"error": "server not found"})
		} else if need != "read" {
			jsonOut(w, http.StatusForbidden, map[string]string{"error": accessErr.Error()})
		} else {
			a.internalError(w, "app", accessErr)
		}
		return
	}
	if strings.HasSuffix(r.URL.Path, "/status") {
		a.serverStatus(w, r, id)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/connect-check") {
		a.serverConnectCheck(w, r, id)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/trust-host-key") {
		a.serverTrustHostKey(w, r, id)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/folder") {
		a.serverFolder(w, r, id)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/preferences") {
		a.serverPreferences(w, r, id)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/crontab") {
		a.serverCrontab(w, r, id)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		dependencyCount, dependencyErr := a.serverJumpDependencyCount(id)
		if dependencyErr != nil {
			a.internalError(w, "app", dependencyErr)
			return
		}
		if dependencyCount > 0 {
			jsonOut(w, http.StatusConflict, map[string]any{
				"error":          "server is used as a jump host",
				"code":           "jump_host_in_use",
				"dependentCount": dependencyCount,
			})
			return
		}
		a.terminateServerLiveSessions(id, "server_deleted")
		a.terminateServerTransfers(id)
		res, deleteErr := a.DB.Exec(`DELETE FROM servers WHERE id=?`, id)
		if deleteErr != nil {
			a.internalError(w, "app", deleteErr)
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			jsonOut(w, http.StatusNotFound, map[string]string{"error": "server not found"})
			return
		}
		a.audit(uid(r), "server.delete", fmt.Sprintf("server=%d", id))
		jsonOut(w, http.StatusOK, map[string]bool{"ok": true})
	case http.MethodPatch:
		var in Server
		if decode(r, &in) != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		if err := a.updateServer(id, uid(r), existing, &in); err != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		updated, _, loadErr := a.loadServer(id)
		if loadErr != nil {
			a.internalError(w, "app", loadErr)
			return
		}
		updated.CanUse, updated.CanCreate, updated.CanEdit, updated.CanDelete = existing.CanUse, existing.CanCreate, existing.CanEdit, existing.CanDelete
		a.decorateTemplateServerAccess(uid(r), role(r), &updated)
		updated.Secret = ""
		a.audit(uid(r), "server.update", fmt.Sprintf("server=%d", id))
		jsonOut(w, http.StatusOK, updated)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *App) updateServer(id, userID int64, existing Server, in *Server) error {
	workspaceID := int64(0)
	if existing.WorkspaceID != nil {
		workspaceID = *existing.WorkspaceID
	}
	if existing.TemplateID == nil && in.Port == 0 {
		in.Port = 22
	}
	routeChanged := existing.TemplateID == nil && (strings.TrimSpace(in.Host) != existing.Host || in.Port != existing.Port || int64PtrValue(in.JumpHostID) != int64PtrValue(existing.JumpHostID))
	preservingExistingWorkspaceProfile := workspaceID > 0 && existing.CredentialProfileID != nil && in.CredentialProfileID != nil && *existing.CredentialProfileID == *in.CredentialProfileID
	if preservingExistingWorkspaceProfile && !routeChanged {
		p, _, _, _, err := a.loadCredentialProfileRaw(*in.CredentialProfileID)
		if err != nil || !p.Shared {
			return errors.New("workspace credential profile is no longer available")
		}
		in.Username, in.AuthType, in.Secret = p.Username, p.AuthType, ""
	} else if err := a.prepareServerCredentials(userID, in); err != nil {
		return err
	}
	if workspaceID > 0 && routeChanged && in.CredentialProfileID == nil && strings.TrimSpace(in.Secret) == "" {
		return errors.New("changing a shared server target requires new credentials or your own credential profile")
	}
	if workspaceID > 0 && in.CredentialProfileID != nil {
		p, _, _, _, err := a.loadCredentialProfileRaw(*in.CredentialProfileID)
		if err != nil || !p.Shared {
			return errors.New("workspace servers require direct credentials or a shared credential profile")
		}
		if routeChanged && p.OwnerUserID != userID {
			return errors.New("changing a shared server target requires your own credential profile")
		}
	}
	if existing.TemplateID != nil && in.CredentialProfileID != nil {
		p, _, _, _, err := a.loadCredentialProfileRaw(*in.CredentialProfileID)
		if err != nil || p.OwnerUserID != userID {
			return errors.New("template-derived servers require your own credential profile")
		}
	}
	if err := a.validateFolderForScope(userID, workspaceID, in.FolderID, "read"); err != nil {
		return err
	}
	if existing.TemplateID == nil {
		if strings.TrimSpace(in.Name) == "" || strings.TrimSpace(in.Host) == "" {
			return errors.New("name and host required")
		}
		if in.Port < 1 || in.Port > 65535 {
			return errors.New("port must be between 1 and 65535")
		}
		if in.Color == "" {
			in.Color = existing.Color
		}
		if in.Kind == "" {
			in.Kind = existing.Kind
		}
		if err := a.validateJumpHostForServer(userID, id, workspaceID, in.JumpHostID); err != nil {
			return err
		}
		in.TerminalEditorMode = normalizeTerminalEditorMode(in.TerminalEditorMode)
		in.CrontabEditorMode = normalizeCrontabEditorMode(in.CrontabEditorMode)
	}
	var oldSecret, oldAuth string
	var oldProfile sql.NullInt64
	if err := a.DB.QueryRow(`SELECT secret_enc,auth_type,credential_profile_id FROM servers WHERE id=?`, id).Scan(&oldSecret, &oldAuth, &oldProfile); err != nil {
		return errors.New("server not found")
	}
	enc := oldSecret
	if in.CredentialProfileID != nil {
		enc = ""
	} else {
		if oldProfile.Valid && strings.TrimSpace(in.Secret) == "" {
			return errors.New("switching from a credential profile to direct credentials requires a new secret")
		}
		if oldAuth != "" && in.AuthType != oldAuth && strings.TrimSpace(in.Secret) == "" {
			return errors.New("changing authentication type requires a new secret")
		}
		if in.Secret != "" {
			var err error
			enc, err = a.Box.Encrypt(in.Secret)
			if err != nil {
				return errors.New("credential encryption failed")
			}
		}
	}
	if existing.TemplateID != nil {
		_, err := a.DB.Exec(`UPDATE servers SET username=?,auth_type=?,secret_enc=?,folder_id=?,credential_profile_id=? WHERE id=?`, in.Username, in.AuthType, enc, in.FolderID, in.CredentialProfileID, id)
		return err
	}
	_, err := a.DB.Exec(`UPDATE servers SET name=?,host=?,port=?,username=?,auth_type=?,secret_enc=?,folder_id=?,color=?,kind=?,credential_profile_id=?,jump_host_id=?,terminal_editor_mode=?,crontab_editor_mode=? WHERE id=?`,
		strings.TrimSpace(in.Name), strings.TrimSpace(in.Host), in.Port, in.Username, in.AuthType, enc, in.FolderID, in.Color, in.Kind, in.CredentialProfileID, in.JumpHostID, in.TerminalEditorMode, in.CrontabEditorMode, id)
	return err
}

func normalizeTerminalEditorMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "web", "terminal":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "ask"
	}
}

func normalizeCrontabEditorMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "visual", "terminal":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "ask"
	}
}

func (a *App) serverPreferences(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Method != http.MethodPatch {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	server, _, err := a.loadServerForPermission(uid(r), id, "edit")
	if err != nil {
		jsonOut(w, http.StatusNotFound, map[string]string{"error": "server not found"})
		return
	}
	if server.TemplateID != nil {
		jsonOut(w, http.StatusConflict, map[string]string{"error": "editor preferences are inherited from the server template"})
		return
	}
	var in struct {
		TerminalEditorMode *string `json:"terminalEditorMode"`
		CrontabEditorMode  *string `json:"crontabEditorMode"`
	}
	if decode(r, &in) != nil || (in.TerminalEditorMode == nil && in.CrontabEditorMode == nil) {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "at least one preference is required"})
		return
	}
	var currentTerminal, currentCrontab string
	if err := a.DB.QueryRow(`SELECT terminal_editor_mode,crontab_editor_mode FROM servers WHERE id=?`, id).Scan(&currentTerminal, &currentCrontab); err != nil {
		jsonOut(w, http.StatusNotFound, map[string]string{"error": "server not found"})
		return
	}
	if in.TerminalEditorMode != nil {
		currentTerminal = normalizeTerminalEditorMode(*in.TerminalEditorMode)
	}
	if in.CrontabEditorMode != nil {
		currentCrontab = normalizeCrontabEditorMode(*in.CrontabEditorMode)
	}
	if _, err := a.DB.Exec(`UPDATE servers SET terminal_editor_mode=?,crontab_editor_mode=? WHERE id=?`, currentTerminal, currentCrontab, id); err != nil {
		a.internalError(w, "app", err)
		return
	}
	a.audit(uid(r), "server.preferences.update", fmt.Sprintf("server=%d terminal_editor=%s crontab_editor=%s", id, currentTerminal, currentCrontab))
	jsonOut(w, http.StatusOK, map[string]any{"ok": true, "terminalEditorMode": currentTerminal, "crontabEditorMode": currentCrontab})
}

func (a *App) serverFolder(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Method != http.MethodPatch {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	server, _, err := a.loadServerForPermission(uid(r), id, "edit")
	if err != nil {
		jsonOut(w, http.StatusNotFound, map[string]string{"error": "server not found"})
		return
	}
	var in struct {
		FolderID json.RawMessage `json:"folderId"`
	}
	if decode(r, &in) != nil || len(in.FolderID) == 0 {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "folderId is required"})
		return
	}
	var folderID *int64
	if strings.TrimSpace(string(in.FolderID)) != "null" {
		var target int64
		if json.Unmarshal(in.FolderID, &target) != nil || target <= 0 {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "folderId must be a valid folder id or null"})
			return
		}
		folderID = &target
	}
	workspaceID := int64(0)
	if server.WorkspaceID != nil {
		workspaceID = *server.WorkspaceID
	}
	if err := a.validateFolderForScope(uid(r), workspaceID, folderID, "read"); err != nil {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if _, err := a.DB.Exec(`UPDATE servers SET folder_id=? WHERE id=?`, folderID, id); err != nil {
		a.internalError(w, "app", err)
		return
	}
	folderAudit := "root"
	if folderID != nil {
		folderAudit = strconv.FormatInt(*folderID, 10)
	}
	a.audit(uid(r), "server.folder.move", fmt.Sprintf("server=%d folder=%s", id, folderAudit))
	jsonOut(w, http.StatusOK, map[string]any{"ok": true, "id": id, "folderId": folderID})
}

func (a *App) folders(w http.ResponseWriter, r *http.Request) {
	workspaceID, err := workspaceIDFromRequest(r)
	if err != nil {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	switch r.Method {
	case http.MethodGet:
		permissions := fullWorkspacePermissions()
		workspaceName := ""
		workspaceActive := true
		if workspaceID > 0 {
			workspace, p, accessErr := a.requireWorkspacePermission(uid(r), workspaceID, "read")
			if accessErr != nil {
				jsonOut(w, http.StatusNotFound, map[string]string{"error": "workspace not found"})
				return
			}
			permissions, workspaceName, workspaceActive = p, workspace.Name, workspace.Active
		}
		var rows *sql.Rows
		if workspaceID == 0 {
			rows, err = a.DB.Query(`SELECT id,owner_user_id,name,parent_id,sort_order,workspace_id FROM folders WHERE owner_user_id=? AND workspace_id IS NULL ORDER BY sort_order,lower(name),id`, uid(r))
		} else {
			rows, err = a.DB.Query(`SELECT id,owner_user_id,name,parent_id,sort_order,workspace_id FROM folders WHERE workspace_id=? ORDER BY sort_order,lower(name),id`, workspaceID)
		}
		if err != nil {
			a.internalError(w, "app", err)
			return
		}
		defer rows.Close()
		out := []Folder{}
		for rows.Next() {
			var f Folder
			var parent, ws sql.NullInt64
			if err := rows.Scan(&f.ID, &f.OwnerUserID, &f.Name, &parent, &f.SortOrder, &ws); err != nil {
				a.internalError(w, "app", err)
				return
			}
			if parent.Valid {
				f.ParentID = &parent.Int64
			}
			if ws.Valid {
				f.WorkspaceID = &ws.Int64
				f.WorkspaceName = workspaceName
			}
			f.CanUse, f.CanCreate, f.CanEdit, f.CanDelete = permissions.CanUse, permissions.CanCreate, permissions.CanEdit, permissions.CanDelete
			if !workspaceActive {
				f.CanUse, f.CanCreate, f.CanEdit, f.CanDelete = false, false, false, false
			}
			out = append(out, f)
		}
		jsonOut(w, http.StatusOK, out)
	case http.MethodPost:
		permissions := fullWorkspacePermissions()
		if workspaceID > 0 {
			_, p, accessErr := a.requireWorkspacePermission(uid(r), workspaceID, "create")
			if accessErr != nil {
				jsonOut(w, http.StatusForbidden, map[string]string{"error": "workspace create permission required"})
				return
			}
			permissions = p
		}
		var f Folder
		if decode(r, &f) != nil || strings.TrimSpace(f.Name) == "" {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "name required"})
			return
		}
		if err := a.validateFolderForScope(uid(r), workspaceID, f.ParentID, "read"); err != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		var workspaceValue any
		if workspaceID > 0 {
			workspaceValue = workspaceID
		}
		res, err := a.DB.Exec(`INSERT INTO folders(owner_user_id,name,parent_id,sort_order,workspace_id) VALUES(?,?,?,?,?)`, uid(r), strings.TrimSpace(f.Name), f.ParentID, f.SortOrder, workspaceValue)
		if err != nil {
			a.internalError(w, "app", err)
			return
		}
		f.ID, _ = res.LastInsertId()
		f.OwnerUserID = uid(r)
		if workspaceID > 0 {
			f.WorkspaceID = &workspaceID
		}
		f.CanUse, f.CanCreate, f.CanEdit, f.CanDelete = permissions.CanUse, permissions.CanCreate, permissions.CanEdit, permissions.CanDelete
		a.audit(uid(r), "folder.create", fmt.Sprintf("folder=%d workspace=%d", f.ID, workspaceID))
		jsonOut(w, http.StatusCreated, f)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *App) folderByID(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r.URL.Path, "/api/folders/")
	if err != nil {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "bad folder id"})
		return
	}
	need := "read"
	if r.Method == http.MethodPatch {
		need = "edit"
	} else if r.Method == http.MethodDelete {
		need = "delete"
	}
	folder, accessErr := a.folderAccessForUser(uid(r), id, need)
	if accessErr != nil {
		jsonOut(w, http.StatusNotFound, map[string]string{"error": "folder not found"})
		return
	}
	workspaceID := int64(0)
	if folder.WorkspaceID != nil {
		workspaceID = *folder.WorkspaceID
	}
	switch r.Method {
	case http.MethodPatch:
		var in Folder
		if decode(r, &in) != nil || strings.TrimSpace(in.Name) == "" {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "name required"})
			return
		}
		if in.ParentID != nil {
			if *in.ParentID == id {
				jsonOut(w, http.StatusBadRequest, map[string]string{"error": "folder cannot be its own parent"})
				return
			}
			if err := a.validateFolderForScope(uid(r), workspaceID, in.ParentID, "read"); err != nil {
				jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			seen := map[int64]bool{id: true}
			cur := *in.ParentID
			for cur != 0 {
				if seen[cur] {
					jsonOut(w, http.StatusBadRequest, map[string]string{"error": "folder move would create a cycle"})
					return
				}
				seen[cur] = true
				parent, parentErr := a.folderAccessForUser(uid(r), cur, "read")
				if parentErr != nil || (workspaceID == 0 && parent.WorkspaceID != nil) || (workspaceID > 0 && (parent.WorkspaceID == nil || *parent.WorkspaceID != workspaceID)) {
					jsonOut(w, http.StatusBadRequest, map[string]string{"error": "parent folder not found"})
					return
				}
				if parent.ParentID == nil {
					break
				}
				cur = *parent.ParentID
			}
		}
		if _, err := a.DB.Exec(`UPDATE folders SET name=?,parent_id=?,sort_order=? WHERE id=?`, strings.TrimSpace(in.Name), in.ParentID, in.SortOrder, id); err != nil {
			a.internalError(w, "app", err)
			return
		}
		in.ID, in.OwnerUserID, in.WorkspaceID = id, folder.OwnerUserID, folder.WorkspaceID
		in.CanUse, in.CanCreate, in.CanEdit, in.CanDelete = folder.CanUse, folder.CanCreate, folder.CanEdit, folder.CanDelete
		a.audit(uid(r), "folder.update", fmt.Sprintf("folder=%d", id))
		jsonOut(w, http.StatusOK, in)
	case http.MethodDelete:
		var children, servers int
		_ = a.DB.QueryRow(`SELECT COUNT(*) FROM folders WHERE parent_id=?`, id).Scan(&children)
		_ = a.DB.QueryRow(`SELECT COUNT(*) FROM servers WHERE folder_id=?`, id).Scan(&servers)
		if children > 0 || servers > 0 {
			jsonOut(w, http.StatusConflict, map[string]string{"error": "folder is not empty; move contained folders/servers first"})
			return
		}
		if _, err := a.DB.Exec(`DELETE FROM folders WHERE id=?`, id); err != nil {
			a.internalError(w, "app", err)
			return
		}
		a.audit(uid(r), "folder.delete", fmt.Sprintf("folder=%d", id))
		jsonOut(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

type serverRowScanner interface {
	Scan(dest ...any) error
}

const serverEffectiveSelect = `SELECT s.id,s.owner_user_id,
	COALESCE(t.name,s.name),COALESCE(t.host,s.host),COALESCE(t.port,s.port),s.username,s.auth_type,s.secret_enc,s.folder_id,
	COALESCE(t.color,s.color),COALESCE(t.kind,s.kind),s.credential_profile_id,
	CASE WHEN s.template_id IS NOT NULL AND t.jump_template_id IS NOT NULL THEN
		(SELECT js.id FROM servers js WHERE js.owner_user_id=s.owner_user_id AND js.workspace_id IS NULL AND js.template_id=t.jump_template_id LIMIT 1)
	ELSE s.jump_host_id END,
	COALESCE(t.terminal_editor_mode,s.terminal_editor_mode),COALESCE(t.crontab_editor_mode,s.crontab_editor_mode),
	EXISTS(SELECT 1 FROM known_host_keys k WHERE k.server_id=s.id),s.workspace_id,COALESCE(w.name,''),s.template_id,COALESCE(t.name,''),COALESCE(t.active,1),
	CASE WHEN s.template_id IS NOT NULL AND t.jump_template_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM servers js WHERE js.owner_user_id=s.owner_user_id AND js.workspace_id IS NULL AND js.template_id=t.jump_template_id) THEN 1 ELSE 0 END
	FROM servers s LEFT JOIN workspaces w ON w.id=s.workspace_id LEFT JOIN server_templates t ON t.id=s.template_id`

func scanServerRow(scanner serverRowScanner) (Server, string, error) {
	var s Server
	var enc string
	var folder, profile, jump, workspace, template sql.NullInt64
	var workspaceName, templateName string
	var trusted, templateActive, jumpMissing int
	err := scanner.Scan(&s.ID, &s.OwnerUserID, &s.Name, &s.Host, &s.Port, &s.Username, &s.AuthType, &enc, &folder, &s.Color, &s.Kind, &profile, &jump, &s.TerminalEditorMode, &s.CrontabEditorMode, &trusted, &workspace, &workspaceName, &template, &templateName, &templateActive, &jumpMissing)
	if err != nil {
		return s, "", err
	}
	if folder.Valid {
		s.FolderID = &folder.Int64
	}
	if profile.Valid {
		s.CredentialProfileID = &profile.Int64
	}
	if jump.Valid {
		s.JumpHostID = &jump.Int64
	}
	if workspace.Valid {
		s.WorkspaceID = &workspace.Int64
		s.WorkspaceName = workspaceName
	}
	if template.Valid {
		s.TemplateID = &template.Int64
		s.TemplateName = templateName
		s.TemplateActive = templateActive != 0
		s.TemplateAccessible = true
		s.TemplateJumpMissing = jumpMissing != 0
	}
	s.HostKeyTrusted = trusted != 0
	return s, enc, nil
}

func (a *App) loadServer(id int64) (Server, string, error) {
	s, enc, err := scanServerRow(a.DB.QueryRow(serverEffectiveSelect+` WHERE s.id=?`, id))
	if err != nil {
		return s, "", err
	}
	if enc == "" {
		return s, "", nil
	}
	secret, err := a.Box.Decrypt(enc)
	return s, secret, err
}

func (a *App) loadServersForScope(ownerUserID, workspaceID int64) ([]Server, error) {
	query := serverEffectiveSelect
	var args []any
	if workspaceID == 0 {
		query += ` WHERE s.owner_user_id=? AND s.workspace_id IS NULL ORDER BY lower(COALESCE(t.name,s.name)),s.id`
		args = append(args, ownerUserID)
	} else {
		query += ` WHERE s.workspace_id=? ORDER BY lower(COALESCE(t.name,s.name)),s.id`
		args = append(args, workspaceID)
	}
	rows, err := a.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Server, 0)
	for rows.Next() {
		s, _, scanErr := scanServerRow(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func safeInlinePreviewContentType(name string) (string, bool) {
	switch strings.ToLower(path.Ext(name)) {
	case ".png":
		return "image/png", true
	case ".jpg", ".jpeg":
		return "image/jpeg", true
	case ".gif":
		return "image/gif", true
	case ".webp":
		return "image/webp", true
	case ".avif":
		return "image/avif", true
	case ".bmp":
		return "image/bmp", true
	case ".ico":
		return "image/x-icon", true
	default:
		return "", false
	}
}

func (a *App) files(w http.ResponseWriter, r *http.Request) {
	id, e := parseID(r.URL.Path, "/api/files/")
	if e != nil {
		jsonOut(w, 400, map[string]string{"error": "bad server id"})
		return
	}
	if _, _, e := a.loadServerForUser(uid(r), id); e != nil {
		jsonOut(w, 404, map[string]string{"error": "server not found"})
		return
	}
	if e := a.reserveSFTPOperation(uid(r)); e != nil {
		jsonOut(w, http.StatusTooManyRequests, map[string]string{"error": e.Error()})
		return
	}
	defer a.releaseSFTPOperation(uid(r))
	cl, cleanup, e := a.openSSHClient(id)
	if e != nil {
		a.writeSSHConnectError(w, e)
		return
	}
	defer cleanup()
	sf, e := sshx.SFTP(cl)
	if e != nil {
		jsonOut(w, 502, map[string]string{"error": e.Error()})
		return
	}
	defer sf.Close()
	p := r.URL.Query().Get("path")
	if p == "" {
		p = "."
	}
	switch r.Method {
	case "GET":
		downloadWriter := io.Writer(w)
		var downloadController *http.ResponseController
		if a.cfg.SFTPStreamIdleTimeout > 0 {
			downloadController = http.NewResponseController(w)
			downloadWriter = &idleDeadlineWriter{writer: w, controller: downloadController, timeout: a.cfg.SFTPStreamIdleTimeout}
			defer func() { _ = downloadController.SetWriteDeadline(time.Time{}) }()
		}
		if r.URL.Query().Get("realpath") == "1" {
			realPath, realErr := sf.RealPath(p)
			if realErr != nil {
				jsonOut(w, http.StatusBadRequest, map[string]string{"error": realErr.Error()})
				return
			}
			jsonOut(w, http.StatusOK, map[string]string{"path": realPath})
			return
		}
		if r.URL.Query().Get("download") == "1" {
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", path.Base(p)))
			if e = sshx.Download(sf, p, downloadWriter); e != nil {
				log.Println(e)
			}
			return
		}
		if r.URL.Query().Get("inline") == "1" {
			info, statErr := sf.Stat(p)
			if statErr != nil {
				jsonOut(w, http.StatusNotFound, map[string]string{"error": statErr.Error()})
				return
			}
			if info.IsDir() {
				jsonOut(w, http.StatusBadRequest, map[string]string{"error": "cannot preview a directory"})
				return
			}
			contentType, allowed := safeInlinePreviewContentType(p)
			if !allowed {
				jsonOut(w, http.StatusUnsupportedMediaType, map[string]string{"error": "inline preview is only available for safe raster image formats"})
				return
			}
			w.Header().Set("Content-Type", contentType)
			w.Header().Set("Content-Disposition", mime.FormatMediaType("inline", map[string]string{"filename": path.Base(p)}))
			w.Header().Set("Cache-Control", "private, no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
			w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
			if e = sshx.Download(sf, p, downloadWriter); e != nil {
				log.Println(e)
			}
			return
		}
		if r.URL.Query().Get("text") == "1" {
			info, statErr := sf.Stat(p)
			if statErr != nil {
				jsonOut(w, 404, map[string]string{"error": statErr.Error()})
				return
			}
			if info.IsDir() {
				jsonOut(w, 400, map[string]string{"error": "cannot edit a directory"})
				return
			}
			const maxEditorBytes = int64(2 * 1024 * 1024)
			if info.Size() > maxEditorBytes {
				jsonOut(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "file is larger than the 2 MiB editor limit"})
				return
			}
			f, openErr := sf.Open(p)
			if openErr != nil {
				a.internalError(w, "app", openErr)
				return
			}
			defer f.Close()
			b, readErr := io.ReadAll(io.LimitReader(f, maxEditorBytes+1))
			if readErr != nil {
				a.internalError(w, "app", readErr)
				return
			}
			if int64(len(b)) > maxEditorBytes {
				jsonOut(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "file is larger than the 2 MiB editor limit"})
				return
			}
			jsonOut(w, 200, map[string]any{"path": p, "content": string(b), "size": len(b), "mode": info.Mode().String(), "modTime": info.ModTime()})
			return
		}
		xs, e := sshx.List(sf, p)
		if e != nil {
			a.internalError(w, "app", e)
			return
		}
		settings, settingsErr := a.settingsForUser(uid(r))
		if settingsErr == nil && !settings.ShowHiddenFiles {
			filtered := xs[:0]
			for _, entry := range xs {
				if !strings.HasPrefix(entry.Name, ".") {
					filtered = append(filtered, entry)
				}
			}
			xs = filtered
		}
		jsonOut(w, 200, map[string]any{"path": p, "entries": xs})
	case "PUT":
		uploadBody := io.Reader(r.Body)
		if a.cfg.SFTPStreamIdleTimeout > 0 {
			controller := http.NewResponseController(w)
			uploadBody = &idleDeadlineReader{reader: r.Body, controller: controller, timeout: a.cfg.SFTPStreamIdleTimeout}
			defer func() { _ = controller.SetReadDeadline(time.Time{}) }()
		}
		if e = sshx.Upload(sf, p, uploadBody); e != nil {
			a.internalError(w, "app", e)
			return
		}
		jsonOut(w, 200, map[string]bool{"ok": true})
	case "POST":
		var action struct {
			Action string `json:"action"`
			Path   string `json:"path"`
			Target string `json:"target"`
			URL    string `json:"url"`
			Mode   string `json:"mode"`
			UID    int    `json:"uid"`
			GID    int    `json:"gid"`
		}
		if decode(r, &action) != nil {
			jsonOut(w, 400, map[string]string{"error": "invalid file action"})
			return
		}
		action.Path = strings.TrimSpace(action.Path)
		if action.Path == "" {
			action.Path = p
		}
		switch strings.ToLower(strings.TrimSpace(action.Action)) {
		case "mkdir":
			e = sf.MkdirAll(action.Path)
		case "create":
			f, createErr := sf.OpenFile(action.Path, os.O_CREATE|os.O_WRONLY|os.O_EXCL)
			if createErr == nil {
				e = f.Close()
			} else {
				e = createErr
			}
		case "rename":
			if strings.TrimSpace(action.Target) == "" {
				e = errors.New("target path is required")
			} else {
				e = sf.Rename(action.Path, action.Target)
			}
		case "chmod":
			modeText := strings.TrimPrefix(strings.TrimSpace(action.Mode), "0")
			if modeText == "" {
				modeText = "0"
			}
			var mode uint64
			mode, e = strconv.ParseUint(modeText, 8, 32)
			if e == nil {
				e = sf.Chmod(action.Path, os.FileMode(mode))
			}
		case "chown":
			if action.UID < 0 || action.GID < 0 {
				e = errors.New("uid and gid must be non-negative")
			} else {
				e = sf.Chown(action.Path, action.UID, action.GID)
			}
		case "download_url":
			if strings.TrimSpace(action.URL) == "" {
				e = errors.New("URL is required")
			} else {
				e = a.uploadURLToRemote(r.Context(), sf, action.URL, action.Path)
			}
		default:
			jsonOut(w, 400, map[string]string{"error": "unsupported file action"})
			return
		}
		if e != nil {
			a.internalError(w, "app", e)
			return
		}
		jsonOut(w, 200, map[string]bool{"ok": true})
	case "DELETE":
		e = sf.Remove(p)
		if e != nil {
			e = sf.RemoveDirectory(p)
		}
		if e != nil {
			a.internalError(w, "app", e)
			return
		}
		jsonOut(w, 200, map[string]bool{"ok": true})
	default:
		w.WriteHeader(405)
	}
}
