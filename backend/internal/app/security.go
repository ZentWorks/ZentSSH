package app

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type runtimeConfig struct {
	SessionTTL               time.Duration
	CookieSecure             string
	BaseURL                  *url.URL
	TrustedProxyNets         []*net.IPNet
	SetupToken               string
	LoginLimit               int
	LoginWindow              time.Duration
	AllowWSNoOrigin          bool
	SessionRetention         time.Duration
	SessionBufferSize        int
	MaxWebSessionsPerUser    int
	MaxSessionsPerUser       int
	MaxTotalSessions         int
	MaxTransfersPerUser      int
	MaxTotalTransfers        int
	PasswordHashConcurrency  int
	MaxSFTPOperationsPerUser int
	MaxTotalSFTPOperations   int
	SFTPStreamIdleTimeout    time.Duration
	AuditRetention           time.Duration
}

type loginBucket struct {
	Started time.Time
	Count   int
}

type roleCtxKey struct{}
type csrfCtxKey struct{}

func loadRuntimeConfig() runtimeConfig {
	cfg := runtimeConfig{
		SessionTTL:               parseDurationEnv("WEB_SESSION_TTL", 24*time.Hour, 5*time.Minute, 30*24*time.Hour),
		CookieSecure:             strings.ToLower(strings.TrimSpace(envString("COOKIE_SECURE", "auto"))),
		SetupToken:               strings.TrimSpace(os.Getenv("SETUP_TOKEN")),
		LoginLimit:               parseIntEnv("LOGIN_RATE_LIMIT_MAX", 10, 1, 1000),
		LoginWindow:              parseDurationEnv("LOGIN_RATE_LIMIT_WINDOW", 10*time.Minute, time.Minute, 24*time.Hour),
		AllowWSNoOrigin:          parseBoolEnv("ALLOW_WS_NO_ORIGIN", false),
		SessionRetention:         parseDurationAllowZero("SSH_SESSION_RETENTION", 30*time.Minute, 24*time.Hour),
		SessionBufferSize:        parseIntEnv("SESSION_BUFFER_SIZE", 2<<20, 64<<10, 32<<20),
		MaxWebSessionsPerUser:    parseIntEnv("MAX_WEB_SESSIONS_PER_USER", 20, 2, 200),
		MaxSessionsPerUser:       parseIntEnv("MAX_SESSIONS_PER_USER", 8, 1, 128),
		MaxTotalSessions:         parseIntEnv("MAX_TOTAL_SESSIONS", 64, 1, 2048),
		MaxTransfersPerUser:      parseIntEnv("MAX_TRANSFERS_PER_USER", 3, 1, 64),
		MaxTotalTransfers:        parseIntEnv("MAX_TOTAL_TRANSFERS", 12, 1, 256),
		PasswordHashConcurrency:  parseIntEnv("MAX_PASSWORD_HASH_CONCURRENCY", 4, 1, 32),
		MaxSFTPOperationsPerUser: parseIntEnv("MAX_SFTP_OPERATIONS_PER_USER", 6, 1, 64),
		MaxTotalSFTPOperations:   parseIntEnv("MAX_TOTAL_SFTP_OPERATIONS", 48, 1, 512),
		SFTPStreamIdleTimeout:    parseDurationEnv("SFTP_STREAM_IDLE_TIMEOUT", 2*time.Minute, 10*time.Second, 30*time.Minute),
		AuditRetention:           parseDurationAllowZero("AUDIT_RETENTION", 90*24*time.Hour, 3650*24*time.Hour),
	}
	if raw := strings.TrimSpace(os.Getenv("BASE_URL")); raw != "" {
		if u, err := url.Parse(raw); err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https") {
			cfg.BaseURL = u
		}
	}
	for _, raw := range strings.Split(os.Getenv("TRUSTED_PROXY_CIDRS"), ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "/") {
			if ip := net.ParseIP(raw); ip != nil {
				if ip.To4() != nil {
					raw += "/32"
				} else {
					raw += "/128"
				}
			}
		}
		if _, n, err := net.ParseCIDR(raw); err == nil {
			cfg.TrustedProxyNets = append(cfg.TrustedProxyNets, n)
		}
	}
	switch cfg.CookieSecure {
	case "true", "false", "auto":
	default:
		cfg.CookieSecure = "auto"
	}
	return cfg
}

func parseBoolEnv(k string, d bool) bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
	if raw == "" {
		return d
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return d
	}
}

func envString(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}
func parseIntEnv(k string, d, min, max int) int {
	v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(k)))
	if err != nil {
		return d
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
func parseDurationAllowZero(k string, d, max time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(k))
	if raw == "" {
		return d
	}
	if raw == "0" || strings.EqualFold(raw, "off") {
		return 0
	}
	if strings.EqualFold(raw, "unlimited") || strings.EqualFold(raw, "infinite") || strings.EqualFold(raw, "forever") {
		return -1
	}
	v, err := time.ParseDuration(raw)
	if err != nil || v < 0 {
		return d
	}
	if v > max {
		return max
	}
	return v
}

func parseDurationEnv(k string, d, min, max time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(k))
	if raw == "" {
		return d
	}
	v, err := time.ParseDuration(raw)
	if err != nil {
		return d
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func sessionDBID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func secureEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (a *App) isTrustedProxy(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range a.cfg.TrustedProxyNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func remoteIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	return net.ParseIP(strings.Trim(host, "[]"))
}

func parseForwardedIPs(raw string) []net.IP {
	out := []net.IP{}
	for _, part := range strings.Split(raw, ",") {
		ip := net.ParseIP(strings.Trim(strings.TrimSpace(part), "[]"))
		if ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

func (a *App) clientIP(r *http.Request) string {
	peer := remoteIP(r)
	if !a.isTrustedProxy(peer) {
		if peer != nil {
			return peer.String()
		}
		return "unknown"
	}
	chain := append(parseForwardedIPs(r.Header.Get("X-Forwarded-For")), peer)
	if len(chain) == 0 {
		return "unknown"
	}
	current := chain[len(chain)-1]
	for i := len(chain) - 2; i >= 0 && a.isTrustedProxy(current); i-- {
		current = chain[i]
	}
	if current == nil {
		return "unknown"
	}
	return current.String()
}

func lastHeaderValue(v string) string {
	parts := strings.Split(v, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		if s := strings.TrimSpace(parts[i]); s != "" {
			return s
		}
	}
	return ""
}

func (a *App) effectiveProto(r *http.Request) string {
	if a.cfg.BaseURL != nil {
		return a.cfg.BaseURL.Scheme
	}
	if r.TLS != nil {
		return "https"
	}
	if a.isTrustedProxy(remoteIP(r)) {
		if p := strings.ToLower(lastHeaderValue(r.Header.Get("X-Forwarded-Proto"))); p == "https" || p == "http" {
			return p
		}
	}
	return "http"
}

func (a *App) effectiveHost(r *http.Request) string {
	if a.cfg.BaseURL != nil {
		return strings.ToLower(a.cfg.BaseURL.Host)
	}
	host := r.Host
	if a.isTrustedProxy(remoteIP(r)) {
		if h := lastHeaderValue(r.Header.Get("X-Forwarded-Host")); h != "" {
			host = h
		}
	}
	return strings.ToLower(strings.TrimSpace(host))
}

func (a *App) validWebSocketOrigin(r *http.Request) bool {
	raw := strings.TrimSpace(r.Header.Get("Origin"))
	if raw == "" {
		return a.cfg.AllowWSNoOrigin
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	if strings.ToLower(u.Host) != a.effectiveHost(r) {
		return false
	}
	return strings.ToLower(u.Scheme) == a.effectiveProto(r)
}

func (a *App) secureCookie(r *http.Request) bool {
	switch a.cfg.CookieSecure {
	case "true":
		return true
	case "false":
		return false
	default:
		return a.effectiveProto(r) == "https"
	}
}

func (a *App) setCSRFCookie(w http.ResponseWriter, r *http.Request, token string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{Name: "zentssh_csrf", Value: token, Path: "/", HttpOnly: false, Secure: a.secureCookie(r), SameSite: http.SameSiteStrictMode, Expires: exp})
}

func (a *App) clearAuthCookies(w http.ResponseWriter, r *http.Request) {
	secure := a.secureCookie(r)
	http.SetCookie(w, &http.Cookie{Name: "zentssh_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: "zentssh_csrf", Value: "", Path: "/", MaxAge: -1, HttpOnly: false, Secure: secure, SameSite: http.SameSiteStrictMode})
}

func currentWebSessionIDs(r *http.Request) (hashed, raw string) {
	if c, err := r.Cookie("zentssh_session"); err == nil {
		raw = c.Value
	}
	if raw != "" {
		hashed = sessionDBID(raw)
	}
	return hashed, raw
}

func revokeOtherWebSessionsTx(tx *sql.Tx, r *http.Request, userID int64) error {
	hashed, raw := currentWebSessionIDs(r)
	if raw == "" {
		return errors.New("current web session is missing")
	}
	_, err := tx.Exec(`DELETE FROM sessions WHERE user_id=? AND id<>? AND id<>?`, userID, hashed, raw)
	return err
}

func isUnsafeMethod(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func (a *App) csrfOK(r *http.Request) bool {
	if !isUnsafeMethod(r.Method) {
		return true
	}
	c, err := r.Cookie("zentssh_csrf")
	if err != nil || c.Value == "" {
		return false
	}
	return secureEqual(c.Value, r.Header.Get("X-CSRF-Token"))
}

func (a *App) roleForUser(userID int64) (string, error) {
	var userRole string
	var active int
	err := a.DB.QueryRow("SELECT role,active FROM users WHERE id=?", userID).Scan(&userRole, &active)
	if err != nil {
		return "", err
	}
	userRole = normalizeUserRole(userRole)
	if active == 0 || !validUserRole(userRole) {
		return "", errors.New("user is disabled or has invalid role")
	}
	return userRole, nil
}
func role(r *http.Request) string  { v, _ := r.Context().Value(roleCtxKey{}).(string); return v }
func isAdmin(r *http.Request) bool { return role(r) == "admin" }
func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !isAdmin(r) {
		jsonOut(w, http.StatusForbidden, map[string]string{"error": "admin permission required"})
		return false
	}
	return true
}

func (a *App) allowLoginAttempt(r *http.Request) (bool, time.Duration) {
	return a.allowLoginAttemptKey(a.clientIP(r), a.cfg.LoginLimit)
}

func (a *App) allowLoginDiscovery(r *http.Request) (bool, time.Duration) {
	limit := a.cfg.LoginLimit * 4
	if limit < 20 {
		limit = 20
	}
	return a.allowLoginAttemptKey("discover:"+a.clientIP(r), limit)
}

func (a *App) allowSensitiveAuthAttempt(r *http.Request, userID int64) (bool, time.Duration) {
	key := "stepup:" + strconv.FormatInt(userID, 10) + ":" + a.clientIP(r)
	return a.allowLoginAttemptKey(key, a.cfg.LoginLimit)
}

func (a *App) resetSensitiveAuthAttempts(r *http.Request, userID int64) {
	key := "stepup:" + strconv.FormatInt(userID, 10) + ":" + a.clientIP(r)
	a.rateMu.Lock()
	delete(a.loginAttempts, key)
	a.rateMu.Unlock()
}

func (a *App) enforceSensitiveAuthAttempt(w http.ResponseWriter, r *http.Request, userID int64) bool {
	ok, retry := a.allowSensitiveAuthAttempt(r, userID)
	if ok {
		return true
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
	jsonOut(w, http.StatusTooManyRequests, map[string]string{"error": "too many verification attempts; try again later"})
	return false
}

func (a *App) allowLoginAttemptKey(key string, limit int) (bool, time.Duration) {
	if limit < 1 {
		limit = 1
	}
	now := time.Now()
	a.rateMu.Lock()
	defer a.rateMu.Unlock()
	if a.loginAttempts == nil {
		a.loginAttempts = map[string]*loginBucket{}
	}
	if len(a.loginAttempts) > 4096 {
		for k, bucket := range a.loginAttempts {
			if now.Sub(bucket.Started) >= a.cfg.LoginWindow {
				delete(a.loginAttempts, k)
			}
		}
	}
	// Bound memory even during distributed source-IP floods. Evict one old arbitrary
	// bucket only after the map remains very large after the expiry sweep.
	if len(a.loginAttempts) >= 16384 {
		for k := range a.loginAttempts {
			delete(a.loginAttempts, k)
			break
		}
	}
	b := a.loginAttempts[key]
	if b == nil || now.Sub(b.Started) >= a.cfg.LoginWindow {
		a.loginAttempts[key] = &loginBucket{Started: now, Count: 1}
		return true, 0
	}
	if b.Count >= limit {
		return false, a.cfg.LoginWindow - now.Sub(b.Started)
	}
	b.Count++
	return true, 0
}

func (a *App) resetLoginAttempts(r *http.Request) {
	a.rateMu.Lock()
	delete(a.loginAttempts, a.clientIP(r))
	a.rateMu.Unlock()
}
