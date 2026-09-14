package app

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type oidcProvider struct {
	ID                int64  `json:"id"`
	SSOID             string `json:"ssoId"`
	Name              string `json:"name"`
	IssuerURL         string `json:"issuerUrl"`
	ClientID          string `json:"clientId"`
	ClientSecret      string `json:"clientSecret,omitempty"`
	RedirectURL       string `json:"redirectUrl"`
	Scopes            string `json:"scopes"`
	GroupClaim        string `json:"groupClaim"`
	RequiredGroup     string `json:"requiredGroup"`
	AdminGroup        string `json:"adminGroup"`
	TokenAuthMethod   string `json:"tokenAuthMethod"`
	Enabled           bool   `json:"enabled"`
	AutoCreate        bool   `json:"autoCreate"`
	HasClientSecret   bool   `json:"hasClientSecret"`
	ClearClientSecret bool   `json:"clearClientSecret,omitempty"`
}

type oidcDiscovery struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

type oidcClaims map[string]any

type oidcState struct {
	ProviderID   int64
	Nonce        string
	CodeVerifier string
	LinkUserID   sql.NullInt64
	ExpiresAt    time.Time
}

func (a *App) admin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var role string
		if e := a.DB.QueryRow("SELECT role FROM users WHERE id=?", uid(r)).Scan(&role); e != nil || role != "admin" {
			jsonOut(w, http.StatusForbidden, map[string]string{"error": "admin permission required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) oidcPublicProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	rows, e := a.DB.Query("SELECT id,name FROM oidc_providers WHERE enabled=1 ORDER BY name,id")
	if e != nil {
		jsonOut(w, 500, map[string]string{"error": "could not load SSO providers"})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var name string
		if e := rows.Scan(&id, &name); e != nil {
			jsonOut(w, 500, map[string]string{"error": "could not load SSO providers"})
			return
		}
		out = append(out, map[string]any{"id": id, "name": name})
	}
	jsonOut(w, 200, out)
}

func (a *App) oidcProviders(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rows, e := a.DB.Query(`SELECT id,sso_id,name,issuer_url,client_id,client_secret_enc,redirect_url,scopes,group_claim,required_group,admin_group,token_auth_method,enabled,auto_create FROM oidc_providers ORDER BY name,id`)
		if e != nil {
			a.internalError(w, "oidc", e)
			return
		}
		defer rows.Close()
		out := []oidcProvider{}
		for rows.Next() {
			p, e := scanOIDCProvider(rows)
			if e != nil {
				a.internalError(w, "oidc", e)
				return
			}
			out = append(out, p)
		}
		jsonOut(w, 200, out)
	case http.MethodPost:
		var p oidcProvider
		if e := decode(r, &p); e != nil {
			jsonOut(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if e := normalizeOIDCProvider(&p); e != nil {
			jsonOut(w, 400, map[string]string{"error": e.Error()})
			return
		}
		enc := ""
		var e error
		if p.ClientSecret != "" {
			enc, e = a.Box.Encrypt(p.ClientSecret)
			if e != nil {
				jsonOut(w, 500, map[string]string{"error": "client secret encryption failed"})
				return
			}
		}
		p.SSOID, e = a.allocateOIDCSSOID()
		if e != nil {
			jsonOut(w, 500, map[string]string{"error": "could not allocate SSO provider id"})
			return
		}
		res, e := a.DB.Exec(`INSERT INTO oidc_providers(sso_id,name,issuer_url,client_id,client_secret_enc,redirect_url,scopes,group_claim,required_group,admin_group,token_auth_method,enabled,auto_create) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			p.SSOID, p.Name, p.IssuerURL, p.ClientID, enc, p.RedirectURL, p.Scopes, p.GroupClaim, p.RequiredGroup, p.AdminGroup, p.TokenAuthMethod, boolInt(p.Enabled), boolInt(p.AutoCreate))
		if e != nil {
			a.internalError(w, "oidc", e)
			return
		}
		p.ID, _ = res.LastInsertId()
		p.ClientSecret = ""
		p.HasClientSecret = enc != ""
		a.audit(uid(r), "oidc.provider.create", fmt.Sprintf("provider=%d name=%s", p.ID, p.Name))
		jsonOut(w, 201, p)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *App) oidcProviderByID(w http.ResponseWriter, r *http.Request) {
	id, e := parseID(r.URL.Path, "/api/admin/oidc/providers/")
	if e != nil {
		jsonOut(w, 400, map[string]string{"error": "bad provider id"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		p, _, e := a.loadOIDCProvider(id, true)
		if e != nil {
			jsonOut(w, 404, map[string]string{"error": "provider not found"})
			return
		}
		jsonOut(w, 200, p)
	case http.MethodPatch:
		old, oldSecret, e := a.loadOIDCProvider(id, true)
		if e != nil {
			jsonOut(w, 404, map[string]string{"error": "provider not found"})
			return
		}
		var p oidcProvider
		if e := decode(r, &p); e != nil {
			jsonOut(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if p.Name == "" {
			p.Name = old.Name
		}
		if p.IssuerURL == "" {
			p.IssuerURL = old.IssuerURL
		}
		if p.ClientID == "" {
			p.ClientID = old.ClientID
		}
		if p.RedirectURL == "" {
			p.RedirectURL = old.RedirectURL
		}
		if p.Scopes == "" {
			p.Scopes = old.Scopes
		}
		if p.GroupClaim == "" {
			p.GroupClaim = old.GroupClaim
		}
		if p.RequiredGroup == "" {
			p.RequiredGroup = old.RequiredGroup
		}
		if p.AdminGroup == "" {
			p.AdminGroup = old.AdminGroup
		}
		if p.TokenAuthMethod == "" {
			p.TokenAuthMethod = old.TokenAuthMethod
		}
		if e := normalizeOIDCProvider(&p); e != nil {
			jsonOut(w, 400, map[string]string{"error": e.Error()})
			return
		}
		enc := oldSecret
		if p.ClearClientSecret {
			enc = ""
		}
		if p.ClientSecret != "" {
			enc, e = a.Box.Encrypt(p.ClientSecret)
			if e != nil {
				jsonOut(w, 500, map[string]string{"error": "client secret encryption failed"})
				return
			}
		}
		_, e = a.DB.Exec(`UPDATE oidc_providers SET name=?,issuer_url=?,client_id=?,client_secret_enc=?,redirect_url=?,scopes=?,group_claim=?,required_group=?,admin_group=?,token_auth_method=?,enabled=?,auto_create=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`,
			p.Name, p.IssuerURL, p.ClientID, enc, p.RedirectURL, p.Scopes, p.GroupClaim, p.RequiredGroup, p.AdminGroup, p.TokenAuthMethod, boolInt(p.Enabled), boolInt(p.AutoCreate), id)
		if e != nil {
			a.internalError(w, "oidc", e)
			return
		}
		p.ID = id
		p.SSOID = old.SSOID
		p.ClientSecret = ""
		p.HasClientSecret = enc != ""
		a.audit(uid(r), "oidc.provider.update", fmt.Sprintf("provider=%d name=%s", id, p.Name))
		jsonOut(w, 200, p)
	case http.MethodDelete:
		var n int
		if e := a.DB.QueryRow("SELECT COUNT(*) FROM oidc_identities WHERE provider_id=?", id).Scan(&n); e != nil {
			a.internalError(w, "oidc", e)
			return
		}
		if n > 0 {
			jsonOut(w, 409, map[string]string{"error": "provider is linked to users; disable it instead of deleting it"})
			return
		}
		res, e := a.DB.Exec("DELETE FROM oidc_providers WHERE id=?", id)
		if e != nil {
			a.internalError(w, "oidc", e)
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			jsonOut(w, 404, map[string]string{"error": "provider not found"})
			return
		}
		a.audit(uid(r), "oidc.provider.delete", fmt.Sprintf("provider=%d", id))
		jsonOut(w, 200, map[string]bool{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *App) oidcTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var x struct {
		IssuerURL string `json:"issuerUrl"`
	}
	if decode(r, &x) != nil || strings.TrimSpace(x.IssuerURL) == "" {
		jsonOut(w, 400, map[string]string{"error": "issuerUrl required"})
		return
	}
	d, e := discoverOIDC(r.Context(), x.IssuerURL)
	if e != nil {
		jsonOut(w, 502, map[string]string{"error": e.Error()})
		return
	}
	keys, e := fetchJWKS(r.Context(), d.JWKSURI)
	if e != nil {
		jsonOut(w, 502, map[string]string{"error": e.Error()})
		return
	}
	jsonOut(w, 200, map[string]any{
		"ok":                    true,
		"issuer":                d.Issuer,
		"authorizationEndpoint": d.AuthorizationEndpoint,
		"tokenEndpoint":         d.TokenEndpoint,
		"jwksUri":               d.JWKSURI,
		"keyCount":              len(keys),
	})
}

func (a *App) meOIDC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	rows, e := a.DB.Query(`SELECT p.id,p.name,i.subject,i.email_claim FROM oidc_identities i JOIN oidc_providers p ON p.id=i.provider_id WHERE i.user_id=? ORDER BY p.name`, uid(r))
	if e != nil {
		a.internalError(w, "oidc", e)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var name, sub, email string
		if e := rows.Scan(&id, &name, &sub, &email); e != nil {
			a.internalError(w, "oidc", e)
			return
		}
		out = append(out, map[string]any{"providerId": id, "providerName": name, "subject": sub, "email": email})
	}
	jsonOut(w, 200, out)
}

const oidcSSOIDAlphabet = "abcdefghijkmnpqrstuvwxyz23456789"

func newOIDCSSOID() (string, error) {
	raw := make([]byte, 8)
	if _, err := crand.Read(raw); err != nil {
		return "", err
	}
	out := make([]byte, len(raw))
	for i, value := range raw {
		out[i] = oidcSSOIDAlphabet[int(value)%len(oidcSSOIDAlphabet)]
	}
	return string(out), nil
}

func normalizeOIDCSSOID(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != 8 {
		return "", false
	}
	for _, ch := range value {
		if !strings.ContainsRune(oidcSSOIDAlphabet, ch) {
			return "", false
		}
	}
	return value, true
}

func (a *App) allocateOIDCSSOID() (string, error) {
	for attempts := 0; attempts < 32; attempts++ {
		candidate, err := newOIDCSSOID()
		if err != nil {
			return "", err
		}
		var count int
		if err := a.DB.QueryRow(`SELECT COUNT(*) FROM oidc_providers WHERE sso_id=?`, candidate).Scan(&count); err != nil {
			return "", err
		}
		if count == 0 {
			return candidate, nil
		}
	}
	return "", errors.New("could not allocate unique SSO provider id")
}

func (a *App) oidcDirectStart(w http.ResponseWriter, r *http.Request, rawSSOID string) {
	w.Header().Set("Cache-Control", "no-store")
	ssoID, ok := normalizeOIDCSSOID(rawSSOID)
	if !ok {
		a.oidcDirectUnavailable(w, r)
		return
	}
	var providerID int64
	if err := a.DB.QueryRow(`SELECT id FROM oidc_providers WHERE sso_id=? AND enabled=1`, ssoID).Scan(&providerID); err != nil {
		a.oidcDirectUnavailable(w, r)
		return
	}
	target, err := a.beginOIDCAuthorization(w, r, providerID, nil)
	if err != nil {
		a.oidcDirectUnavailable(w, r)
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (a *App) oidcDirectUnavailable(w http.ResponseWriter, r *http.Request) {
	q := url.Values{}
	q.Set("oidc_error", "Dieser SSO-Anmeldeweg ist nicht verfügbar.")
	http.Redirect(w, r, "/?"+q.Encode(), http.StatusFound)
}

func (a *App) oidcStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Query().Get("mode") == "link" {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "SSO account linking must be started from the authenticated settings flow"})
		return
	}
	id, e := strconv.ParseInt(r.URL.Query().Get("provider"), 10, 64)
	if e != nil || id <= 0 {
		jsonOut(w, 400, map[string]string{"error": "provider required"})
		return
	}
	u, e := a.beginOIDCAuthorization(w, r, id, nil)
	if e != nil {
		jsonOut(w, http.StatusBadGateway, map[string]string{"error": e.Error()})
		return
	}
	http.Redirect(w, r, u, http.StatusFound)
}

func (a *App) oidcLinkStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		ProviderID int64  `json:"providerId"`
		Password   string `json:"password"`
		MFACode    string `json:"mfaCode"`
	}
	if decode(r, &in) != nil || in.ProviderID <= 0 {
		jsonOut(w, 400, map[string]string{"error": "providerId required"})
		return
	}
	userID := uid(r)
	if !a.enforceSensitiveAuthAttempt(w, r, userID) {
		return
	}
	var passwordHash string
	var mfaEnabled int
	if err := a.DB.QueryRow(`SELECT password_hash,mfa_enabled FROM users WHERE id=?`, userID).Scan(&passwordHash, &mfaEnabled); err != nil {
		jsonOut(w, http.StatusInternalServerError, map[string]string{"error": "could not verify current account"})
		return
	}
	if strings.HasPrefix(passwordHash, "!oidc!") {
		jsonOut(w, http.StatusConflict, map[string]string{"error": "additional SSO linking requires an account with a local password"})
		return
	}
	passwordOK, saturated := a.checkPasswordLimited(passwordHash, in.Password)
	if saturated {
		jsonOut(w, http.StatusTooManyRequests, map[string]string{"error": "authentication capacity reached; try again shortly"})
		return
	}
	if !passwordOK {
		jsonOut(w, http.StatusUnauthorized, map[string]string{"error": "current password is required"})
		return
	}
	if mfaEnabled != 0 {
		a.mfaMu.Lock()
		ok := a.verifyMFAForUser(userID, in.MFACode, true)
		a.mfaMu.Unlock()
		if !ok {
			jsonOut(w, http.StatusUnauthorized, map[string]string{"error": "valid MFA or recovery code required"})
			return
		}
	}
	u, e := a.beginOIDCAuthorization(w, r, in.ProviderID, &userID)
	if e != nil {
		jsonOut(w, http.StatusBadGateway, map[string]string{"error": "could not start SSO linking"})
		return
	}
	a.resetSensitiveAuthAttempts(r, userID)
	jsonOut(w, 200, map[string]string{"url": u})
}

func (a *App) beginOIDCAuthorization(w http.ResponseWriter, r *http.Request, providerID int64, linkUserID *int64) (string, error) {
	ctx := r.Context()
	p, _, e := a.loadOIDCProvider(providerID, true)
	if e != nil || !p.Enabled {
		return "", errors.New("SSO provider not available")
	}
	d, e := discoverOIDC(ctx, p.IssuerURL)
	if e != nil {
		return "", fmt.Errorf("OIDC discovery failed: %w", e)
	}
	if !sameIssuer(d.Issuer, p.IssuerURL) {
		return "", errors.New("OIDC issuer mismatch")
	}

	state := randID(32)
	nonce := randID(32)
	verifier := randID(48)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	var linkUser any
	if linkUserID != nil {
		linkUser = *linkUserID
	}
	_, _ = a.DB.Exec("DELETE FROM oidc_states WHERE expires_at < ?", time.Now())
	expiresAt := time.Now().Add(10 * time.Minute)
	if _, e = a.DB.Exec("INSERT INTO oidc_states(state,provider_id,nonce,code_verifier,link_user_id,expires_at) VALUES(?,?,?,?,?,?)", state, providerID, nonce, verifier, linkUser, expiresAt); e != nil {
		return "", errors.New("could not start SSO login")
	}
	http.SetCookie(w, &http.Cookie{Name: "zentssh_oidc_state", Value: state, Path: "/api/auth/oidc/callback", HttpOnly: true, Secure: a.secureCookie(r), SameSite: http.SameSiteLaxMode, Expires: expiresAt, MaxAge: 600})
	u, e := url.Parse(d.AuthorizationEndpoint)
	if e != nil {
		return "", errors.New("invalid authorization endpoint")
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", p.RedirectURL)
	q.Set("scope", p.Scopes)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (a *App) clearOIDCStateCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "zentssh_oidc_state", Value: "", Path: "/api/auth/oidc/callback", HttpOnly: true, Secure: a.secureCookie(r), SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func (a *App) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	defer a.clearOIDCStateCookie(w, r)
	if providerError := r.URL.Query().Get("error"); providerError != "" {
		a.oidcRedirectError(w, r, "SSO provider rejected the login: "+providerError)
		return
	}
	stateID := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if stateID == "" || code == "" {
		a.oidcRedirectError(w, r, "SSO callback is missing state or code")
		return
	}
	stateCookie, cookieErr := r.Cookie("zentssh_oidc_state")
	if cookieErr != nil || !secureEqual(stateCookie.Value, stateID) {
		a.oidcRedirectError(w, r, "SSO login state does not match this browser")
		return
	}
	st, e := a.consumeOIDCState(stateID)
	if e != nil {
		a.oidcRedirectError(w, r, "SSO login state is invalid or expired")
		return
	}
	p, secretEnc, e := a.loadOIDCProvider(st.ProviderID, true)
	if e != nil || !p.Enabled {
		a.oidcRedirectError(w, r, "SSO provider is disabled or missing")
		return
	}
	secret := ""
	if secretEnc != "" {
		secret, e = a.Box.Decrypt(secretEnc)
		if e != nil {
			a.oidcRedirectError(w, r, "SSO client secret could not be decrypted")
			return
		}
	}
	d, e := discoverOIDC(r.Context(), p.IssuerURL)
	if e != nil || !sameIssuer(d.Issuer, p.IssuerURL) {
		a.oidcRedirectError(w, r, "OIDC discovery failed")
		return
	}
	idToken, e := exchangeOIDCCode(r.Context(), d, p, secret, code, st.CodeVerifier)
	if e != nil {
		a.oidcRedirectError(w, r, "SSO token exchange failed: "+e.Error())
		return
	}
	claims, e := verifyIDToken(r.Context(), d, p, idToken, st.Nonce)
	if e != nil {
		a.oidcRedirectError(w, r, "SSO ID token validation failed: "+e.Error())
		return
	}
	sub := claimString(claims, "sub")
	email := strings.ToLower(strings.TrimSpace(claimString(claims, "email")))
	if sub == "" {
		a.oidcRedirectError(w, r, "SSO token has no subject")
		return
	}
	// Do not reject email_verified=false here. Some OIDC providers (including
	// authentik 2025.10+) deliberately report false when they have no
	// authoritative verification source. ZentSSH binds an SSO identity by the
	// provider + subject pair and never auto-links an existing local account by
	// email alone, so an unverified email claim does not weaken account binding.
	groups := claimStrings(claims[p.GroupClaim])
	if p.RequiredGroup != "" && !containsString(groups, p.RequiredGroup) {
		a.oidcRedirectError(w, r, "your SSO account is not a member of the required group")
		return
	}

	if st.LinkUserID.Valid {
		if e := a.linkOIDCIdentity(st.ProviderID, st.LinkUserID.Int64, sub, email); e != nil {
			a.oidcRedirectError(w, r, e.Error())
			return
		}
		a.audit(st.LinkUserID.Int64, "oidc.identity.link", fmt.Sprintf("provider=%d", st.ProviderID))
		http.Redirect(w, r, "/?oidc_linked=1", http.StatusFound)
		return
	}

	userID, e := a.resolveOIDCUser(p, sub, email, claims)
	if e != nil {
		a.oidcRedirectError(w, r, e.Error())
		return
	}
	if _, e := a.createSession(w, r, userID); e != nil {
		log.Printf("OIDC session creation failed: provider=%d user=%d: %v", p.ID, userID, e)
		a.oidcRedirectError(w, r, "could not create ZentSSH session")
		return
	}
	a.audit(userID, "auth.oidc.login", fmt.Sprintf("provider=%d", p.ID))
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *App) resolveOIDCUser(p oidcProvider, sub, email string, claims oidcClaims) (int64, error) {
	// Resolve through users as well as oidc_identities. Older builds could leave
	// an identity behind after its user was deleted because SQLite foreign-key
	// enforcement was only enabled on one pooled connection. Never trust such a
	// dangling user_id as a valid login target.
	var userID int64
	e := a.DB.QueryRow(`SELECT u.id
		FROM oidc_identities i
		JOIN users u ON u.id=i.user_id
		WHERE i.provider_id=? AND i.subject=?`, p.ID, sub).Scan(&userID)
	if e == nil {
		return userID, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return 0, e
	}

	// Remove only an invalid identity for this exact provider+subject. This is a
	// separate committed statement so historical corruption is repaired even if
	// automatic creation is disabled or the current token cannot be provisioned.
	if _, e = a.DB.Exec(`DELETE FROM oidc_identities
		WHERE provider_id=? AND subject=?
		  AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id=oidc_identities.user_id)`, p.ID, sub); e != nil {
		return 0, e
	}

	if !p.AutoCreate {
		return 0, errors.New("SSO account is not linked")
	}
	if email == "" {
		return 0, errors.New("SSO provider did not supply an email address")
	}

	tx, e := a.DB.Begin()
	if e != nil {
		return 0, e
	}
	defer tx.Rollback()

	// Re-check inside the creation transaction in case another callback resolved
	// the same provider+subject while the orphan cleanup was running.
	e = tx.QueryRow(`SELECT u.id
		FROM oidc_identities i
		JOIN users u ON u.id=i.user_id
		WHERE i.provider_id=? AND i.subject=?`, p.ID, sub).Scan(&userID)
	if e == nil {
		return userID, nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return 0, e
	}

	var existingID int64
	if e = tx.QueryRow("SELECT id FROM users WHERE email=?", email).Scan(&existingID); e == nil {
		return 0, errors.New("an existing ZentSSH account already uses this email; sign in locally and link SSO from Settings")
	} else if !errors.Is(e, sql.ErrNoRows) {
		return 0, e
	}

	name := strings.TrimSpace(claimString(claims, "name"))
	if name == "" {
		name = strings.TrimSpace(claimString(claims, "preferred_username"))
	}
	if name == "" {
		name = email
	}
	role := "user"
	if p.AdminGroup != "" && containsString(claimStrings(claims[p.GroupClaim]), p.AdminGroup) {
		role = "admin"
	}
	res, e := tx.Exec("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)", name, email, "!oidc!"+randID(24), role)
	if e != nil {
		return 0, e
	}
	userID, e = res.LastInsertId()
	if e != nil {
		return 0, e
	}
	if _, e = tx.Exec("INSERT INTO oidc_identities(provider_id,user_id,subject,email_claim) VALUES(?,?,?,?)", p.ID, userID, sub, email); e != nil {
		return 0, e
	}
	if e = tx.Commit(); e != nil {
		return 0, e
	}
	return userID, nil
}

func (a *App) linkOIDCIdentity(providerID, userID int64, sub, email string) error {
	var other int64
	e := a.DB.QueryRow("SELECT user_id FROM oidc_identities WHERE provider_id=? AND subject=?", providerID, sub).Scan(&other)
	if e == nil {
		if other == userID {
			return nil
		}
		return errors.New("this SSO identity is already linked to another ZentSSH user")
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	_, e = a.DB.Exec("INSERT INTO oidc_identities(provider_id,user_id,subject,email_claim) VALUES(?,?,?,?)", providerID, userID, sub, email)
	if e != nil && strings.Contains(strings.ToLower(e.Error()), "unique") {
		return errors.New("this ZentSSH user is already linked to another identity from this SSO provider")
	}
	return e
}

func (a *App) consumeOIDCState(stateID string) (oidcState, error) {
	var st oidcState
	tx, e := a.DB.Begin()
	if e != nil {
		return st, e
	}
	defer tx.Rollback()
	e = tx.QueryRow("SELECT provider_id,nonce,code_verifier,link_user_id,expires_at FROM oidc_states WHERE state=?", stateID).Scan(&st.ProviderID, &st.Nonce, &st.CodeVerifier, &st.LinkUserID, &st.ExpiresAt)
	if e != nil {
		return st, e
	}
	res, e := tx.Exec("DELETE FROM oidc_states WHERE state=?", stateID)
	if e != nil {
		return st, e
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return st, errors.New("state already consumed")
	}
	if time.Now().After(st.ExpiresAt) {
		return st, errors.New("state expired")
	}
	if e = tx.Commit(); e != nil {
		return st, e
	}
	return st, nil
}

func (a *App) userFromSessionCookie(r *http.Request) (int64, bool) {
	c, e := r.Cookie("zentssh_session")
	if e != nil {
		return 0, false
	}
	var userID int64
	var exp time.Time
	lookup := sessionDBID(c.Value)
	e = a.DB.QueryRow("SELECT user_id,expires_at FROM sessions WHERE id=?", lookup).Scan(&userID, &exp)
	if errors.Is(e, sql.ErrNoRows) {
		e = a.DB.QueryRow("SELECT user_id,expires_at FROM sessions WHERE id=?", c.Value).Scan(&userID, &exp)
	}
	if e != nil || time.Now().After(exp) {
		return 0, false
	}
	return userID, true
}

func (a *App) loadOIDCProvider(id int64, allowDisabled bool) (oidcProvider, string, error) {
	var p oidcProvider
	var enabled, auto int
	var secretEnc string
	q := `SELECT id,sso_id,name,issuer_url,client_id,client_secret_enc,redirect_url,scopes,group_claim,required_group,admin_group,token_auth_method,enabled,auto_create FROM oidc_providers WHERE id=?`
	if !allowDisabled {
		q += " AND enabled=1"
	}
	e := a.DB.QueryRow(q, id).Scan(&p.ID, &p.SSOID, &p.Name, &p.IssuerURL, &p.ClientID, &secretEnc, &p.RedirectURL, &p.Scopes, &p.GroupClaim, &p.RequiredGroup, &p.AdminGroup, &p.TokenAuthMethod, &enabled, &auto)
	p.Enabled = enabled != 0
	p.AutoCreate = auto != 0
	p.HasClientSecret = secretEnc != ""
	return p, secretEnc, e
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanOIDCProvider(row rowScanner) (oidcProvider, error) {
	var p oidcProvider
	var enabled, auto int
	var secret string
	e := row.Scan(&p.ID, &p.SSOID, &p.Name, &p.IssuerURL, &p.ClientID, &secret, &p.RedirectURL, &p.Scopes, &p.GroupClaim, &p.RequiredGroup, &p.AdminGroup, &p.TokenAuthMethod, &enabled, &auto)
	p.Enabled = enabled != 0
	p.AutoCreate = auto != 0
	p.HasClientSecret = secret != ""
	return p, e
}

func normalizeOIDCProvider(p *oidcProvider) error {
	p.Name = strings.TrimSpace(p.Name)
	p.IssuerURL = strings.TrimRight(strings.TrimSpace(p.IssuerURL), "/")
	p.ClientID = strings.TrimSpace(p.ClientID)
	p.RedirectURL = strings.TrimSpace(p.RedirectURL)
	p.Scopes = strings.TrimSpace(p.Scopes)
	p.GroupClaim = strings.TrimSpace(p.GroupClaim)
	p.RequiredGroup = strings.TrimSpace(p.RequiredGroup)
	p.AdminGroup = strings.TrimSpace(p.AdminGroup)
	p.TokenAuthMethod = strings.TrimSpace(p.TokenAuthMethod)
	if p.Scopes == "" {
		p.Scopes = "openid email profile"
	}
	if p.GroupClaim == "" {
		p.GroupClaim = "groups"
	}
	if p.TokenAuthMethod == "" {
		p.TokenAuthMethod = "client_secret_basic"
	}
	if p.Name == "" || p.IssuerURL == "" || p.ClientID == "" || p.RedirectURL == "" {
		return errors.New("name, issuerUrl, clientId and redirectUrl are required")
	}
	if !strings.Contains(" "+p.Scopes+" ", " openid ") {
		return errors.New("scopes must include openid")
	}
	for _, raw := range []string{p.IssuerURL, p.RedirectURL} {
		u, e := url.Parse(raw)
		if e != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return errors.New("issuerUrl and redirectUrl must be absolute http(s) URLs")
		}
		host := strings.ToLower(u.Hostname())
		loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
		if u.Scheme != "https" && !loopback {
			return errors.New("OIDC issuerUrl and redirectUrl must use HTTPS except on localhost")
		}
	}
	switch p.TokenAuthMethod {
	case "client_secret_basic", "client_secret_post", "none":
	default:
		return errors.New("tokenAuthMethod must be client_secret_basic, client_secret_post or none")
	}
	return nil
}

func discoverOIDC(ctx context.Context, issuer string) (oidcDiscovery, error) {
	var d oidcDiscovery
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return d, errors.New("empty issuer")
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if e != nil {
		return d, e
	}
	res, e := oidcHTTPClient.Do(req)
	if e != nil {
		return d, e
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return d, fmt.Errorf("discovery returned HTTP %d", res.StatusCode)
	}
	if e = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&d); e != nil {
		return d, e
	}
	if d.Issuer == "" || d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return d, errors.New("discovery response is incomplete")
	}
	for _, endpoint := range []string{d.Issuer, d.AuthorizationEndpoint, d.TokenEndpoint, d.JWKSURI} {
		if err := validateOIDCTransportURL(endpoint); err != nil {
			return d, err
		}
	}
	return d, nil
}

func validateOIDCTransportURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return errors.New("OIDC endpoint is not an absolute URL")
	}
	host := strings.ToLower(u.Hostname())
	loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return fmt.Errorf("OIDC endpoint must use HTTPS except on localhost: %s", raw)
	}
	return nil
}

var oidcHTTPClient = &http.Client{Timeout: 12 * time.Second}

func exchangeOIDCCode(ctx context.Context, d oidcDiscovery, p oidcProvider, secret, code, verifier string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", p.RedirectURL)
	form.Set("client_id", p.ClientID)
	form.Set("code_verifier", verifier)
	if p.TokenAuthMethod == "client_secret_post" && secret != "" {
		form.Set("client_secret", secret)
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if e != nil {
		return "", e
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.TokenAuthMethod == "client_secret_basic" && secret != "" {
		req.SetBasicAuth(p.ClientID, secret)
	}
	res, e := oidcHTTPClient.Do(req)
	if e != nil {
		return "", e
	}
	defer res.Body.Close()
	body, e := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if e != nil {
		return "", e
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", fmt.Errorf("token endpoint returned HTTP %d", res.StatusCode)
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if e = json.Unmarshal(body, &tok); e != nil {
		return "", e
	}
	if tok.IDToken == "" {
		return "", errors.New("token response has no id_token")
	}
	return tok.IDToken, nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func fetchJWKS(ctx context.Context, uri string) ([]jwk, error) {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if e != nil {
		return nil, e
	}
	res, e := oidcHTTPClient.Do(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("JWKS endpoint returned HTTP %d", res.StatusCode)
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if e = json.NewDecoder(io.LimitReader(res.Body, 2<<20)).Decode(&set); e != nil {
		return nil, e
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("JWKS contains no keys")
	}
	return set.Keys, nil
}

func verifyIDToken(ctx context.Context, d oidcDiscovery, p oidcProvider, token, nonce string) (oidcClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed JWT")
	}
	headerRaw, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil {
		return nil, errors.New("invalid JWT header")
	}
	claimsRaw, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		return nil, errors.New("invalid JWT claims")
	}
	sig, e := base64.RawURLEncoding.DecodeString(parts[2])
	if e != nil {
		return nil, errors.New("invalid JWT signature encoding")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if e = json.Unmarshal(headerRaw, &hdr); e != nil || hdr.Alg == "" || hdr.Alg == "none" {
		return nil, errors.New("invalid JWT header")
	}
	var claims oidcClaims
	if e = json.Unmarshal(claimsRaw, &claims); e != nil {
		return nil, errors.New("invalid JWT claims")
	}
	keys, e := fetchJWKS(ctx, d.JWKSURI)
	if e != nil {
		return nil, e
	}
	signed := []byte(parts[0] + "." + parts[1])
	verified := false
	for _, key := range keys {
		if hdr.Kid != "" && key.Kid != hdr.Kid {
			continue
		}
		if key.Alg != "" && key.Alg != hdr.Alg {
			continue
		}
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		if verifyJWTSignature(hdr.Alg, key, signed, sig) == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, errors.New("JWT signature verification failed")
	}
	if !sameIssuer(claimString(claims, "iss"), p.IssuerURL) || !sameIssuer(claimString(claims, "iss"), d.Issuer) {
		return nil, errors.New("issuer mismatch")
	}
	if !audienceContains(claims["aud"], p.ClientID) {
		return nil, errors.New("audience mismatch")
	}
	if azp := claimString(claims, "azp"); azp != "" && azp != p.ClientID {
		return nil, errors.New("authorized party mismatch")
	}
	if audCount(claims["aud"]) > 1 && claimString(claims, "azp") != p.ClientID {
		return nil, errors.New("authorized party missing for multi-audience token")
	}
	if claimString(claims, "nonce") != nonce {
		return nil, errors.New("nonce mismatch")
	}
	now := time.Now().Unix()
	exp, ok := numericClaim(claims, "exp")
	if !ok || now >= exp {
		return nil, errors.New("ID token expired")
	}
	if nbf, ok := numericClaim(claims, "nbf"); ok && now+60 < nbf {
		return nil, errors.New("ID token is not valid yet")
	}
	if iat, ok := numericClaim(claims, "iat"); ok && iat > now+120 {
		return nil, errors.New("ID token issued-at time is in the future")
	}
	return claims, nil
}

func verifyJWTSignature(alg string, key jwk, signed, sig []byte) error {
	switch alg {
	case "RS256", "RS384", "RS512":
		if key.Kty != "RSA" {
			return errors.New("wrong key type")
		}
		pub, e := rsaPublicKey(key)
		if e != nil {
			return e
		}
		var h crypto.Hash
		var sum []byte
		switch alg {
		case "RS256":
			h = crypto.SHA256
			x := sha256.Sum256(signed)
			sum = x[:]
		case "RS384":
			h = crypto.SHA384
			x := sha512.Sum384(signed)
			sum = x[:]
		case "RS512":
			h = crypto.SHA512
			x := sha512.Sum512(signed)
			sum = x[:]
		}
		return rsa.VerifyPKCS1v15(pub, h, sum, sig)
	case "ES256", "ES384", "ES512":
		if key.Kty != "EC" {
			return errors.New("wrong key type")
		}
		pub, e := ecPublicKey(key)
		if e != nil {
			return e
		}
		var digest []byte
		switch alg {
		case "ES256":
			x := sha256.Sum256(signed)
			digest = x[:]
		case "ES384":
			x := sha512.Sum384(signed)
			digest = x[:]
		case "ES512":
			x := sha512.Sum512(signed)
			digest = x[:]
		}
		part := (pub.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*part {
			return errors.New("invalid ECDSA signature size")
		}
		r := new(big.Int).SetBytes(sig[:part])
		s := new(big.Int).SetBytes(sig[part:])
		if !ecdsa.Verify(pub, digest, r, s) {
			return errors.New("ECDSA verification failed")
		}
		return nil
	default:
		return errors.New("unsupported JWT algorithm")
	}
}

func rsaPublicKey(key jwk) (*rsa.PublicKey, error) {
	n, e := base64.RawURLEncoding.DecodeString(key.N)
	if e != nil || len(n) == 0 {
		return nil, errors.New("invalid RSA modulus")
	}
	eb, e := base64.RawURLEncoding.DecodeString(key.E)
	if e != nil || len(eb) == 0 {
		return nil, errors.New("invalid RSA exponent")
	}
	exp := 0
	for _, b := range eb {
		exp = exp<<8 | int(b)
	}
	if exp < 3 {
		return nil, errors.New("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}, nil
}

func ecPublicKey(key jwk) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch key.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, errors.New("unsupported EC curve")
	}
	xb, e := base64.RawURLEncoding.DecodeString(key.X)
	if e != nil {
		return nil, errors.New("invalid EC x coordinate")
	}
	yb, e := base64.RawURLEncoding.DecodeString(key.Y)
	if e != nil {
		return nil, errors.New("invalid EC y coordinate")
	}
	x, y := new(big.Int).SetBytes(xb), new(big.Int).SetBytes(yb)
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("EC key is not on curve")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func claimString(c oidcClaims, key string) string {
	v, _ := c[key].(string)
	return v
}

func numericClaim(c oidcClaims, key string) (int64, bool) {
	switch v := c[key].(type) {
	case float64:
		return int64(v), true
	case json.Number:
		n, e := v.Int64()
		return n, e == nil
	case int64:
		return v, true
	case int:
		return int64(v), true
	default:
		return 0, false
	}
}

func audienceContains(v any, clientID string) bool {
	switch a := v.(type) {
	case string:
		return a == clientID
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok && s == clientID {
				return true
			}
		}
	}
	return false
}

func audCount(v any) int {
	switch a := v.(type) {
	case string:
		if a != "" {
			return 1
		}
	case []any:
		return len(a)
	}
	return 0
}

func sameIssuer(a, b string) bool {
	return strings.TrimRight(strings.TrimSpace(a), "/") == strings.TrimRight(strings.TrimSpace(b), "/")
}

func claimStrings(v any) []string {
	var out []string
	switch x := v.(type) {
	case string:
		if strings.TrimSpace(x) != "" {
			out = append(out, strings.TrimSpace(x))
		}
	case []any:
		for _, item := range x {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				out = append(out, strings.TrimSpace(text))
			}
		}
	case []string:
		for _, text := range x {
			if strings.TrimSpace(text) != "" {
				out = append(out, strings.TrimSpace(text))
			}
		}
	}
	return out
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func (a *App) oidcRedirectError(w http.ResponseWriter, r *http.Request, message string) {
	u := url.URL{Path: "/", RawQuery: url.Values{"oidc_error": []string{message}}.Encode()}
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (a *App) audit(userID int64, action, detail string) {
	_, _ = a.DB.Exec("INSERT INTO audit_logs(user_id,action,detail) VALUES(?,?,?)", userID, action, detail)
}
