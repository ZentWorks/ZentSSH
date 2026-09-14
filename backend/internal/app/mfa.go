package app

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	mfaChallengeTTL = 5 * time.Minute
	mfaSetupTTL     = 10 * time.Minute
	mfaMaxAttempts  = 5
)

func generateTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

func totpAt(secret string, at time.Time) (string, error) {
	clean := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean)
	if err != nil || len(key) == 0 {
		return "", errors.New("invalid TOTP secret")
	}
	counter := uint64(at.Unix() / 30)
	msg := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		msg[i] = byte(counter)
		counter >>= 8
	}
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(msg)
	sum := mac.Sum(nil)
	off := int(sum[len(sum)-1] & 0x0f)
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", bin%1_000_000), nil
}

func verifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	for _, ch := range code {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	for offset := -1; offset <= 1; offset++ {
		want, err := totpAt(secret, now.Add(time.Duration(offset)*30*time.Second))
		if err == nil && secureEqual(want, code) {
			return true
		}
	}
	return false
}

func normalizeRecoveryCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(code), "-", ""), " ", ""))
}

func recoveryHash(code string) string {
	sum := sha256.Sum256([]byte(normalizeRecoveryCode(code)))
	return hex.EncodeToString(sum[:])
}

func generateRecoveryCodes(n int) ([]string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]string, 0, n)
	for len(out) < n {
		raw := make([]byte, 12)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		b := make([]byte, 12)
		for i := range b {
			b[i] = alphabet[int(raw[i])%len(alphabet)]
		}
		out = append(out, string(b[:4])+"-"+string(b[4:8])+"-"+string(b[8:12]))
	}
	return out, nil
}

func (a *App) mfaStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var enabled int
	var passwordHash string
	var recovery int
	if err := a.DB.QueryRow("SELECT mfa_enabled,password_hash FROM users WHERE id=?", uid(r)).Scan(&enabled, &passwordHash); err != nil {
		jsonOut(w, 500, map[string]string{"error": "could not load MFA status"})
		return
	}
	providerID, providerName, ssoManaged, err := a.activeSSOForUser(uid(r))
	if err != nil {
		jsonOut(w, 500, map[string]string{"error": "could not load SSO state"})
		return
	}
	_ = a.DB.QueryRow("SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id=?", uid(r)).Scan(&recovery)
	jsonOut(w, 200, map[string]any{
		"enabled": enabled != 0, "paused": enabled != 0 && ssoManaged,
		"recoveryCodesRemaining": recovery,
		"localPasswordAvailable": !strings.HasPrefix(passwordHash, "!oidc!"),
		"ssoManaged":             ssoManaged, "ssoProviderId": providerID, "ssoProviderName": providerName,
	})
}

func (a *App) rejectSSOManagedMFA(w http.ResponseWriter, r *http.Request) bool {
	_, providerName, managed, err := a.activeSSOForUser(uid(r))
	if err != nil {
		jsonOut(w, http.StatusInternalServerError, map[string]string{"error": "could not load SSO state"})
		return true
	}
	if !managed {
		return false
	}
	detail := "MFA is managed by SSO while an active provider is linked"
	if strings.TrimSpace(providerName) != "" {
		detail += ": " + providerName
	}
	jsonOut(w, http.StatusConflict, map[string]string{"error": detail})
	return true
}

func (a *App) verifyLocalPassword(userID int64, password string) bool {
	var hash string
	if err := a.DB.QueryRow("SELECT password_hash FROM users WHERE id=?", userID).Scan(&hash); err != nil {
		return false
	}
	if strings.HasPrefix(hash, "!oidc!") {
		return false
	}
	ok, saturated := a.checkPasswordLimited(hash, password)
	return !saturated && ok
}

func (a *App) mfaSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if a.rejectSSOManagedMFA(w, r) {
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if decode(r, &in) != nil || !a.verifyLocalPassword(uid(r), in.Password) {
		jsonOut(w, 401, map[string]string{"error": "current password is required"})
		return
	}
	secret, err := generateTOTPSecret()
	if err != nil {
		jsonOut(w, 500, map[string]string{"error": "could not generate MFA secret"})
		return
	}
	enc, err := a.Box.Encrypt(secret)
	if err != nil {
		jsonOut(w, 500, map[string]string{"error": "could not encrypt MFA secret"})
		return
	}
	if _, err = a.DB.Exec(`INSERT INTO mfa_setups(user_id,secret_enc,expires_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET secret_enc=excluded.secret_enc,expires_at=excluded.expires_at`, uid(r), enc, time.Now().Add(mfaSetupTTL)); err != nil {
		jsonOut(w, 500, map[string]string{"error": "could not save MFA setup"})
		return
	}
	var email string
	_ = a.DB.QueryRow("SELECT email FROM users WHERE id=?", uid(r)).Scan(&email)
	label := url.QueryEscape("ZentSSH:" + email)
	issuer := url.QueryEscape("ZentSSH")
	uri := "otpauth://totp/" + label + "?secret=" + url.QueryEscape(secret) + "&issuer=" + issuer + "&algorithm=SHA1&digits=6&period=30"
	a.audit(uid(r), "mfa.setup.start", "")
	jsonOut(w, 200, map[string]string{"secret": secret, "otpauthUri": uri})
}

func (a *App) mfaConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if a.rejectSSOManagedMFA(w, r) {
		return
	}
	var in struct {
		Code string `json:"code"`
	}
	if decode(r, &in) != nil {
		jsonOut(w, 400, map[string]string{"error": "code required"})
		return
	}
	a.mfaMu.Lock()
	defer a.mfaMu.Unlock()
	var enc string
	var exp time.Time
	if err := a.DB.QueryRow("SELECT secret_enc,expires_at FROM mfa_setups WHERE user_id=?", uid(r)).Scan(&enc, &exp); err != nil || time.Now().After(exp) {
		jsonOut(w, 400, map[string]string{"error": "MFA setup expired; start again"})
		return
	}
	secret, err := a.Box.Decrypt(enc)
	if err != nil {
		jsonOut(w, 500, map[string]string{"error": "could not decrypt MFA setup"})
		return
	}
	if !verifyTOTP(secret, in.Code, time.Now()) {
		jsonOut(w, 401, map[string]string{"error": "invalid verification code"})
		return
	}
	codes, err := generateRecoveryCodes(10)
	if err != nil {
		jsonOut(w, 500, map[string]string{"error": "could not generate recovery codes"})
		return
	}
	tx, err := a.DB.Begin()
	if err != nil {
		a.internalError(w, "mfa", err)
		return
	}
	defer tx.Rollback()
	if _, err = tx.Exec("UPDATE users SET mfa_enabled=1,mfa_secret_enc=? WHERE id=?", enc, uid(r)); err != nil {
		a.internalError(w, "mfa", err)
		return
	}
	if _, err = tx.Exec("DELETE FROM mfa_recovery_codes WHERE user_id=?", uid(r)); err != nil {
		a.internalError(w, "mfa", err)
		return
	}
	for _, code := range codes {
		if _, err = tx.Exec("INSERT INTO mfa_recovery_codes(user_id,code_hash) VALUES(?,?)", uid(r), recoveryHash(code)); err != nil {
			a.internalError(w, "mfa", err)
			return
		}
	}
	if _, err = tx.Exec("DELETE FROM mfa_setups WHERE user_id=?", uid(r)); err != nil {
		a.internalError(w, "mfa", err)
		return
	}
	if err = revokeOtherWebSessionsTx(tx, r, uid(r)); err != nil {
		a.internalError(w, "mfa.enable.revoke_sessions", err)
		return
	}
	if err = tx.Commit(); err != nil {
		a.internalError(w, "mfa", err)
		return
	}
	a.terminateUserLiveSessions(uid(r), "mfa_changed")
	a.terminateUserTransfers(uid(r))
	a.audit(uid(r), "mfa.enable", "")
	jsonOut(w, 200, map[string]any{"enabled": true, "recoveryCodes": codes})
}

func (a *App) verifyTOTPForUser(userID int64, code string) bool {
	var enabled int
	var enc string
	if err := a.DB.QueryRow("SELECT mfa_enabled,mfa_secret_enc FROM users WHERE id=?", userID).Scan(&enabled, &enc); err != nil || enabled == 0 || enc == "" {
		return false
	}
	secret, err := a.Box.Decrypt(enc)
	return err == nil && verifyTOTP(secret, code, time.Now())
}

func (a *App) verifyMFAForUser(userID int64, code string, consumeRecovery bool) bool {
	if a.verifyTOTPForUser(userID, code) {
		return true
	}
	hash := recoveryHash(code)
	if !consumeRecovery {
		var n int
		return a.DB.QueryRow("SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id=? AND code_hash=?", userID, hash).Scan(&n) == nil && n == 1
	}
	res, err := a.DB.Exec("DELETE FROM mfa_recovery_codes WHERE user_id=? AND code_hash=?", userID, hash)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

func (a *App) mfaDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if a.rejectSSOManagedMFA(w, r) {
		return
	}
	var in struct{ Password, Code string }
	if decode(r, &in) != nil || !a.verifyLocalPassword(uid(r), in.Password) {
		jsonOut(w, 401, map[string]string{"error": "current password is required"})
		return
	}
	a.mfaMu.Lock()
	defer a.mfaMu.Unlock()
	if !a.verifyMFAForUser(uid(r), in.Code, true) {
		jsonOut(w, 401, map[string]string{"error": "invalid MFA or recovery code"})
		return
	}
	tx, err := a.DB.Begin()
	if err != nil {
		a.internalError(w, "mfa", err)
		return
	}
	defer tx.Rollback()
	if _, err = tx.Exec("UPDATE users SET mfa_enabled=0,mfa_secret_enc='' WHERE id=?", uid(r)); err != nil {
		a.internalError(w, "mfa", err)
		return
	}
	if _, err = tx.Exec("DELETE FROM mfa_recovery_codes WHERE user_id=?", uid(r)); err != nil {
		a.internalError(w, "mfa", err)
		return
	}
	if _, err = tx.Exec("DELETE FROM mfa_setups WHERE user_id=?", uid(r)); err != nil {
		a.internalError(w, "mfa", err)
		return
	}
	if err = revokeOtherWebSessionsTx(tx, r, uid(r)); err != nil {
		a.internalError(w, "mfa.disable.revoke_sessions", err)
		return
	}
	if err = tx.Commit(); err != nil {
		a.internalError(w, "mfa", err)
		return
	}
	a.terminateUserLiveSessions(uid(r), "mfa_changed")
	a.terminateUserTransfers(uid(r))
	a.audit(uid(r), "mfa.disable", "")
	jsonOut(w, 200, map[string]bool{"ok": true})
}

func (a *App) mfaRegenerateRecovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if a.rejectSSOManagedMFA(w, r) {
		return
	}
	var in struct{ Password, Code string }
	if decode(r, &in) != nil || !a.verifyLocalPassword(uid(r), in.Password) {
		jsonOut(w, 401, map[string]string{"error": "current password is required"})
		return
	}
	a.mfaMu.Lock()
	defer a.mfaMu.Unlock()
	if !a.verifyTOTPForUser(uid(r), in.Code) {
		jsonOut(w, 401, map[string]string{"error": "valid TOTP code required"})
		return
	}
	codes, err := generateRecoveryCodes(10)
	if err != nil {
		jsonOut(w, 500, map[string]string{"error": "could not generate recovery codes"})
		return
	}
	tx, err := a.DB.Begin()
	if err != nil {
		a.internalError(w, "mfa", err)
		return
	}
	defer tx.Rollback()
	if _, err = tx.Exec("DELETE FROM mfa_recovery_codes WHERE user_id=?", uid(r)); err != nil {
		a.internalError(w, "mfa", err)
		return
	}
	for _, code := range codes {
		if _, err = tx.Exec("INSERT INTO mfa_recovery_codes(user_id,code_hash) VALUES(?,?)", uid(r), recoveryHash(code)); err != nil {
			a.internalError(w, "mfa", err)
			return
		}
	}
	if err = revokeOtherWebSessionsTx(tx, r, uid(r)); err != nil {
		a.internalError(w, "mfa.recovery.revoke_sessions", err)
		return
	}
	if err = tx.Commit(); err != nil {
		a.internalError(w, "mfa", err)
		return
	}
	a.terminateUserLiveSessions(uid(r), "mfa_changed")
	a.terminateUserTransfers(uid(r))
	a.audit(uid(r), "mfa.recovery.regenerate", "")
	jsonOut(w, 200, map[string]any{"recoveryCodes": codes})
}

func (a *App) beginMFAChallenge(userID int64) (string, error) {
	id := randID(32)
	_, _ = a.DB.Exec("DELETE FROM mfa_challenges WHERE expires_at < ? OR user_id=?", time.Now(), userID)
	_, err := a.DB.Exec("INSERT INTO mfa_challenges(id,user_id,expires_at,attempts) VALUES(?,?,?,0)", id, userID, time.Now().Add(mfaChallengeTTL))
	return id, err
}

func (a *App) loginMFA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if ok, retry := a.allowLoginAttempt(r); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
		jsonOut(w, 429, map[string]string{"error": "too many login attempts; try again later"})
		return
	}
	var in struct{ ChallengeID, Code string }
	if decode(r, &in) != nil || strings.TrimSpace(in.ChallengeID) == "" {
		jsonOut(w, 400, map[string]string{"error": "challengeId and code required"})
		return
	}
	a.mfaMu.Lock()
	defer a.mfaMu.Unlock()
	var userID int64
	var exp time.Time
	var attempts int
	err := a.DB.QueryRow("SELECT user_id,expires_at,attempts FROM mfa_challenges WHERE id=?", in.ChallengeID).Scan(&userID, &exp, &attempts)
	if err != nil || time.Now().After(exp) {
		_, _ = a.DB.Exec("DELETE FROM mfa_challenges WHERE id=?", in.ChallengeID)
		jsonOut(w, 401, map[string]string{"error": "MFA challenge is invalid or expired"})
		return
	}
	if attempts >= mfaMaxAttempts {
		_, _ = a.DB.Exec("DELETE FROM mfa_challenges WHERE id=?", in.ChallengeID)
		jsonOut(w, 401, map[string]string{"error": "MFA challenge attempt limit reached"})
		return
	}
	if providerID, _, managed, ssoErr := a.activeSSOForUser(userID); ssoErr != nil {
		jsonOut(w, http.StatusInternalServerError, map[string]string{"error": "could not resolve login method"})
		return
	} else if managed {
		_, _ = a.DB.Exec("DELETE FROM mfa_challenges WHERE id=?", in.ChallengeID)
		jsonOut(w, http.StatusConflict, map[string]any{"error": "SSO login required", "code": "sso_required", "providerId": providerID})
		return
	}
	if !a.verifyMFAForUser(userID, in.Code, true) {
		_, _ = a.DB.Exec("UPDATE mfa_challenges SET attempts=attempts+1 WHERE id=?", in.ChallengeID)
		jsonOut(w, 401, map[string]string{"error": "invalid MFA or recovery code"})
		return
	}
	res, err := a.DB.Exec("DELETE FROM mfa_challenges WHERE id=?", in.ChallengeID)
	if err != nil {
		jsonOut(w, 500, map[string]string{"error": "could not consume MFA challenge"})
		return
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		jsonOut(w, 401, map[string]string{"error": "MFA challenge was already used"})
		return
	}
	user, err := a.createSession(w, r, userID)
	if err != nil {
		jsonOut(w, 500, map[string]string{"error": "session creation failed"})
		return
	}
	a.resetLoginAttempts(r)
	a.audit(userID, "auth.local.mfa", "")
	jsonOut(w, 200, user)
}
