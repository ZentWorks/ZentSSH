package app

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"zentssh.local/backend/internal/sshx"
)

type hostKeyActionError struct {
	Code     string            `json:"code"`
	ServerID int64             `json:"serverId"`
	Server   string            `json:"server"`
	Host     string            `json:"host"`
	Port     int               `json:"port"`
	Actual   sshx.HostKeyInfo  `json:"actual"`
	Expected *sshx.HostKeyInfo `json:"expected,omitempty"`
	Inner    error             `json:"-"`
}

func (e *hostKeyActionError) Error() string {
	if e.Code == "host_key_changed" {
		return fmt.Sprintf("SSH host key changed for %s", e.Server)
	}
	return fmt.Sprintf("SSH host key trust required for %s", e.Server)
}

func (a *App) serverStatus(w http.ResponseWriter, r *http.Request, serverID int64) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	a.mu.Lock()
	for _, live := range a.live {
		if live.ServerID == serverID && live.UserID == uid(r) && !live.Closed {
			a.mu.Unlock()
			jsonOut(w, http.StatusOK, map[string]any{"status": "active"})
			return
		}
	}
	a.mu.Unlock()

	target, _, err := a.loadServer(serverID)
	if err != nil {
		jsonOut(w, http.StatusNotFound, map[string]string{"error": "server not found"})
		return
	}
	if target.JumpHostID == nil {
		status := "unreachable"
		if sshx.Probe(target.Host, target.Port) {
			status = "reachable"
		}
		jsonOut(w, http.StatusOK, map[string]any{"status": status})
		return
	}
	jumpClient, cleanup, err := a.openSSHClient(*target.JumpHostID)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		jsonOut(w, http.StatusOK, map[string]any{"status": "unknown"})
		return
	}
	conn, err := jumpClient.Dial("tcp", net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
	if err != nil {
		jsonOut(w, http.StatusOK, map[string]any{"status": "unreachable"})
		return
	}
	_ = conn.Close()
	jsonOut(w, http.StatusOK, map[string]any{"status": "reachable"})
}

func (a *App) serverConnectCheck(w http.ResponseWriter, r *http.Request, serverID int64) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	client, cleanup, e := a.openSSHClient(serverID)
	if cleanup != nil {
		defer cleanup()
	}
	if e != nil {
		if hk := new(hostKeyActionError); errors.As(e, &hk) {
			jsonOut(w, http.StatusConflict, hk)
			return
		}
		jsonOut(w, http.StatusBadGateway, map[string]any{"error": e.Error(), "code": "ssh_connect_failed"})
		return
	}
	if client != nil {
		_ = client.Close()
	}
	jsonOut(w, 200, map[string]any{"ok": true})
}

func (a *App) serverTrustHostKey(w http.ResponseWriter, r *http.Request, serverID int64) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		Fingerprint string `json:"fingerprint"`
		Replace     bool   `json:"replace"`
	}
	if decode(r, &in) != nil || strings.TrimSpace(in.Fingerprint) == "" {
		jsonOut(w, 400, map[string]string{"error": "fingerprint required"})
		return
	}
	info, e := a.scanServerHostKey(serverID)
	if e != nil {
		if hk := new(hostKeyActionError); errors.As(e, &hk) {
			jsonOut(w, http.StatusConflict, hk)
			return
		}
		jsonOut(w, 502, map[string]string{"error": e.Error()})
		return
	}
	if info.Fingerprint != in.Fingerprint {
		jsonOut(w, 409, map[string]any{"error": "host key changed while confirming trust", "code": "host_key_changed_during_trust", "actual": info})
		return
	}
	var existing string
	e = a.DB.QueryRow("SELECT fingerprint FROM known_host_keys WHERE server_id=?", serverID).Scan(&existing)
	if e == nil && existing != info.Fingerprint && !in.Replace {
		jsonOut(w, 409, map[string]any{"error": "a different host key is already trusted; explicit replace confirmation required", "code": "host_key_replace_required", "expectedFingerprint": existing, "actual": info})
		return
	}
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		a.internalError(w, "sshconnect", e)
		return
	}
	_, e = a.DB.Exec(`INSERT INTO known_host_keys(server_id,algorithm,key_base64,fingerprint,trusted_by,trusted_at) VALUES(?,?,?,?,?,CURRENT_TIMESTAMP)
		ON CONFLICT(server_id) DO UPDATE SET algorithm=excluded.algorithm,key_base64=excluded.key_base64,fingerprint=excluded.fingerprint,trusted_by=excluded.trusted_by,trusted_at=CURRENT_TIMESTAMP`, serverID, info.Algorithm, info.KeyBase64, info.Fingerprint, uid(r))
	if e != nil {
		a.internalError(w, "sshconnect", e)
		return
	}
	a.audit(uid(r), "ssh.host_key.trust", fmt.Sprintf("server=%d fingerprint=%s replace=%t", serverID, info.Fingerprint, in.Replace))
	jsonOut(w, 200, map[string]any{"ok": true, "hostKey": info})
}

func (a *App) openSSHClient(serverID int64) (*ssh.Client, func(), error) {
	target, _, e := a.loadServer(serverID)
	if e != nil {
		return nil, nil, e
	}
	targetCfg, e := a.sshConfigForServer(target)
	if e != nil {
		return nil, nil, e
	}

	if target.JumpHostID == nil {
		trusted, e := a.trustedHostKey(target.ID)
		if errors.Is(e, sql.ErrNoRows) {
			actual, se := sshx.ScanHostKey(target.Host, target.Port, 8*time.Second)
			if se != nil {
				return nil, nil, se
			}
			return nil, nil, &hostKeyActionError{Code: "host_key_required", ServerID: target.ID, Server: target.Name, Host: target.Host, Port: target.Port, Actual: actual}
		}
		if e != nil {
			return nil, nil, e
		}
		cb, e := sshx.HostKeyCallback(trusted)
		if e != nil {
			return nil, nil, e
		}
		targetCfg.HostKey = cb
		client, e := sshx.Client(targetCfg)
		if e != nil {
			if actual, se := sshx.ScanHostKey(target.Host, target.Port, 8*time.Second); se == nil && actual.Fingerprint != trusted.Fingerprint {
				return nil, nil, &hostKeyActionError{Code: "host_key_changed", ServerID: target.ID, Server: target.Name, Host: target.Host, Port: target.Port, Actual: actual, Expected: &trusted, Inner: e}
			}
			return nil, nil, e
		}
		return client, func() { _ = client.Close() }, nil
	}

	jump, _, e := a.loadServer(*target.JumpHostID)
	if e != nil {
		return nil, nil, fmt.Errorf("load jump host: %w", e)
	}
	if !sameServerScope(target, jump) {
		return nil, nil, errors.New("jump host is not available in this server scope")
	}
	if jump.JumpHostID != nil {
		return nil, nil, errors.New("nested jump hosts are not supported")
	}
	jumpCfg, e := a.sshConfigForServer(jump)
	if e != nil {
		return nil, nil, fmt.Errorf("jump host credentials: %w", e)
	}
	jumpTrusted, e := a.trustedHostKey(jump.ID)
	if errors.Is(e, sql.ErrNoRows) {
		actual, se := sshx.ScanHostKey(jump.Host, jump.Port, 8*time.Second)
		if se != nil {
			return nil, nil, se
		}
		return nil, nil, &hostKeyActionError{Code: "host_key_required", ServerID: jump.ID, Server: jump.Name, Host: jump.Host, Port: jump.Port, Actual: actual}
	}
	if e != nil {
		return nil, nil, e
	}
	jumpCB, e := sshx.HostKeyCallback(jumpTrusted)
	if e != nil {
		return nil, nil, e
	}
	jumpCfg.HostKey = jumpCB
	jumpClient, e := sshx.Client(jumpCfg)
	if e != nil {
		if actual, se := sshx.ScanHostKey(jump.Host, jump.Port, 8*time.Second); se == nil && actual.Fingerprint != jumpTrusted.Fingerprint {
			return nil, nil, &hostKeyActionError{Code: "host_key_changed", ServerID: jump.ID, Server: jump.Name, Host: jump.Host, Port: jump.Port, Actual: actual, Expected: &jumpTrusted, Inner: e}
		}
		return nil, nil, fmt.Errorf("jump host connection failed: %w", e)
	}
	cleanupJump := func() { _ = jumpClient.Close() }

	targetTrusted, e := a.trustedHostKey(target.ID)
	if errors.Is(e, sql.ErrNoRows) {
		actual, se := sshx.ScanHostKeyVia(jumpClient, target.Host, target.Port, 8*time.Second)
		cleanupJump()
		if se != nil {
			return nil, nil, se
		}
		return nil, nil, &hostKeyActionError{Code: "host_key_required", ServerID: target.ID, Server: target.Name, Host: target.Host, Port: target.Port, Actual: actual}
	}
	if e != nil {
		cleanupJump()
		return nil, nil, e
	}
	targetCB, e := sshx.HostKeyCallback(targetTrusted)
	if e != nil {
		cleanupJump()
		return nil, nil, e
	}
	targetCfg.HostKey = targetCB
	targetClient, e := sshx.ClientVia(jumpClient, targetCfg)
	if e != nil {
		if actual, se := sshx.ScanHostKeyVia(jumpClient, target.Host, target.Port, 8*time.Second); se == nil && actual.Fingerprint != targetTrusted.Fingerprint {
			cleanupJump()
			return nil, nil, &hostKeyActionError{Code: "host_key_changed", ServerID: target.ID, Server: target.Name, Host: target.Host, Port: target.Port, Actual: actual, Expected: &targetTrusted, Inner: e}
		}
		cleanupJump()
		return nil, nil, e
	}
	return targetClient, func() { _ = targetClient.Close(); cleanupJump() }, nil
}

func (a *App) scanServerHostKey(serverID int64) (sshx.HostKeyInfo, error) {
	target, _, e := a.loadServer(serverID)
	if e != nil {
		return sshx.HostKeyInfo{}, e
	}
	if target.JumpHostID == nil {
		return sshx.ScanHostKey(target.Host, target.Port, 8*time.Second)
	}
	jump, _, e := a.loadServer(*target.JumpHostID)
	if e != nil {
		return sshx.HostKeyInfo{}, e
	}
	if !sameServerScope(target, jump) {
		return sshx.HostKeyInfo{}, errors.New("jump host is not available in this server scope")
	}
	if jump.JumpHostID != nil {
		return sshx.HostKeyInfo{}, errors.New("nested jump hosts are not supported")
	}
	trusted, e := a.trustedHostKey(jump.ID)
	if errors.Is(e, sql.ErrNoRows) {
		actual, se := sshx.ScanHostKey(jump.Host, jump.Port, 8*time.Second)
		if se != nil {
			return sshx.HostKeyInfo{}, se
		}
		return sshx.HostKeyInfo{}, &hostKeyActionError{Code: "host_key_required", ServerID: jump.ID, Server: jump.Name, Host: jump.Host, Port: jump.Port, Actual: actual}
	}
	if e != nil {
		return sshx.HostKeyInfo{}, e
	}
	cfg, e := a.sshConfigForServer(jump)
	if e != nil {
		return sshx.HostKeyInfo{}, e
	}
	cb, e := sshx.HostKeyCallback(trusted)
	if e != nil {
		return sshx.HostKeyInfo{}, e
	}
	cfg.HostKey = cb
	jumpClient, e := sshx.Client(cfg)
	if e != nil {
		return sshx.HostKeyInfo{}, e
	}
	defer jumpClient.Close()
	return sshx.ScanHostKeyVia(jumpClient, target.Host, target.Port, 8*time.Second)
}

func (a *App) trustedHostKey(serverID int64) (sshx.HostKeyInfo, error) {
	var info sshx.HostKeyInfo
	e := a.DB.QueryRow("SELECT algorithm,key_base64,fingerprint FROM known_host_keys WHERE server_id=?", serverID).Scan(&info.Algorithm, &info.KeyBase64, &info.Fingerprint)
	return info, e
}

func (a *App) sshConfigForServer(s Server) (sshx.Config, error) {
	cfg := sshx.Config{Host: s.Host, Port: s.Port, User: s.Username, AuthType: s.AuthType, Timeout: 10 * time.Second}
	if s.CredentialProfileID == nil {
		_, sec, e := a.loadServer(s.ID)
		if e != nil {
			return cfg, e
		}
		if s.AuthType == "key" || s.AuthType == "private-key" {
			cfg.PrivateKey = sec
		} else {
			cfg.Password = sec
		}
		return cfg, nil
	}
	p, se, pe, ce, e := a.loadCredentialProfileRaw(*s.CredentialProfileID)
	if e != nil {
		return cfg, e
	}
	if s.WorkspaceID != nil {
		if !p.Shared {
			return cfg, errors.New("workspace credential profile is no longer shared")
		}
	} else if p.OwnerUserID != s.OwnerUserID {
		return cfg, errors.New("credential profile does not belong to this server owner")
	}
	cfg.User = p.Username
	cfg.AuthType = p.AuthType
	secret, e := a.decryptOptional(se)
	if e != nil {
		return cfg, fmt.Errorf("decrypt credential profile secret: %w", e)
	}
	passphrase, e := a.decryptOptional(pe)
	if e != nil {
		return cfg, fmt.Errorf("decrypt credential profile passphrase: %w", e)
	}
	cert, e := a.decryptOptional(ce)
	if e != nil {
		return cfg, fmt.Errorf("decrypt credential profile certificate: %w", e)
	}
	if cfg.AuthType == "key" || cfg.AuthType == "private-key" {
		cfg.PrivateKey = secret
		cfg.Passphrase = passphrase
		cfg.Certificate = cert
	} else {
		cfg.Password = secret
	}
	return cfg, nil
}

func (a *App) decryptOptional(enc string) (string, error) {
	if enc == "" {
		return "", nil
	}
	return a.Box.Decrypt(enc)
}

func (a *App) writeSSHConnectError(w http.ResponseWriter, e error) {
	var hk *hostKeyActionError
	if errors.As(e, &hk) {
		jsonOut(w, http.StatusConflict, hk)
		return
	}
	jsonOut(w, http.StatusBadGateway, map[string]any{"error": e.Error(), "code": "ssh_connect_failed"})
}
