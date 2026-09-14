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

type quickConnectRequest struct {
	Target              string `json:"target"`
	AuthType            string `json:"authType"`
	Secret              string `json:"secret"`
	Passphrase          string `json:"passphrase"`
	Certificate         string `json:"certificate"`
	CredentialProfileID *int64 `json:"credentialProfileId"`
	JumpHostID          *int64 `json:"jumpHostId"`
	Fingerprint         string `json:"fingerprint"`
	Cols                int    `json:"cols"`
	Rows                int    `json:"rows"`
}

type quickTarget struct {
	User string `json:"username"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

func parseQuickTarget(raw string) (quickTarget, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return quickTarget{}, errors.New("target is required")
	}
	var userHost string
	port := 22
	if strings.HasPrefix(raw, "ssh ") || raw == "ssh" {
		fields := strings.Fields(raw)
		if len(fields) < 2 {
			return quickTarget{}, errors.New("SSH target is missing")
		}
		for i := 1; i < len(fields); i++ {
			switch fields[i] {
			case "-p":
				if i+1 >= len(fields) {
					return quickTarget{}, errors.New("-p requires a port")
				}
				p, err := strconv.Atoi(fields[i+1])
				if err != nil || p < 1 || p > 65535 {
					return quickTarget{}, errors.New("invalid SSH port")
				}
				port = p
				i++
			case "-l":
				if i+1 >= len(fields) {
					return quickTarget{}, errors.New("-l requires a username")
				}
				if userHost == "" {
					userHost = fields[i+1] + "@"
				}
				i++
			default:
				if strings.HasPrefix(fields[i], "-") {
					return quickTarget{}, fmt.Errorf("unsupported Quick Connect SSH option %s", fields[i])
				}
				if strings.HasSuffix(userHost, "@") {
					userHost += fields[i]
				} else {
					userHost = fields[i]
				}
			}
		}
	} else {
		userHost = raw
	}
	if userHost == "" || strings.HasSuffix(userHost, "@") {
		return quickTarget{}, errors.New("host is required")
	}
	user := ""
	hostPort := userHost
	if at := strings.LastIndex(userHost, "@"); at >= 0 {
		user = strings.TrimSpace(userHost[:at])
		hostPort = strings.TrimSpace(userHost[at+1:])
	}
	if hostPort == "" {
		return quickTarget{}, errors.New("host is required")
	}
	if strings.HasPrefix(hostPort, "[") {
		host, p, err := net.SplitHostPort(hostPort)
		if err == nil {
			hostPort = host
			parsed, pe := strconv.Atoi(p)
			if pe != nil || parsed < 1 || parsed > 65535 {
				return quickTarget{}, errors.New("invalid SSH port")
			}
			port = parsed
		} else if strings.HasSuffix(hostPort, "]") {
			hostPort = strings.Trim(hostPort, "[]")
		} else {
			return quickTarget{}, errors.New("invalid bracketed host")
		}
	} else if strings.Count(hostPort, ":") == 1 {
		parts := strings.SplitN(hostPort, ":", 2)
		if parsed, err := strconv.Atoi(parts[1]); err == nil {
			if parsed < 1 || parsed > 65535 {
				return quickTarget{}, errors.New("invalid SSH port")
			}
			hostPort, port = parts[0], parsed
		}
	}
	if strings.TrimSpace(hostPort) == "" {
		return quickTarget{}, errors.New("host is required")
	}
	return quickTarget{User: user, Host: hostPort, Port: port}, nil
}

func (a *App) quickConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in quickConnectRequest
	if decode(r, &in) != nil {
		jsonOut(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	target, err := parseQuickTarget(in.Target)
	if err != nil {
		jsonOut(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if err := a.validateJumpHostForQuickConnect(uid(r), in.JumpHostID); err != nil {
		jsonOut(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if err := a.reserveLiveSession(uid(r)); err != nil {
		jsonOut(w, http.StatusTooManyRequests, map[string]string{"error": err.Error()})
		return
	}
	defer a.releaseLiveSessionReservation(uid(r))

	actual, err := a.scanQuickTarget(target, in.JumpHostID)
	if err != nil {
		var hk *hostKeyActionError
		if errors.As(err, &hk) {
			jsonOut(w, http.StatusConflict, hk)
			return
		}
		jsonOut(w, 502, map[string]string{"error": err.Error()})
		return
	}
	trusted, trustErr := a.quickTrustedHostKey(uid(r), target, in.JumpHostID)
	if trustErr != nil && !errors.Is(trustErr, sql.ErrNoRows) {
		a.internalError(w, "quickconnect", trustErr)
		return
	}
	if errors.Is(trustErr, sql.ErrNoRows) {
		if strings.TrimSpace(in.Fingerprint) == "" {
			jsonOut(w, http.StatusConflict, map[string]any{
				"code": "host_key_required", "server": "Quick Connect", "host": target.Host, "port": target.Port, "actual": actual, "ephemeral": true,
			})
			return
		}
		if in.Fingerprint != actual.Fingerprint {
			jsonOut(w, http.StatusConflict, map[string]any{
				"code": "host_key_changed", "server": "Quick Connect", "host": target.Host, "port": target.Port, "actual": actual, "ephemeral": true,
				"error": "host key changed after confirmation",
			})
			return
		}
		if err := a.saveQuickTrustedHostKey(uid(r), target, in.JumpHostID, actual); err != nil {
			a.internalError(w, "quickconnect", err)
			return
		}
		a.audit(uid(r), "ssh.quick_host_key.trust", fmt.Sprintf("target=%s:%d route=%s fingerprint=%s", target.Host, target.Port, quickRouteKey(in.JumpHostID), actual.Fingerprint))
	} else if trusted.Fingerprint != actual.Fingerprint {
		if strings.TrimSpace(in.Fingerprint) == "" {
			jsonOut(w, http.StatusConflict, map[string]any{
				"code": "host_key_changed", "server": "Quick Connect", "host": target.Host, "port": target.Port, "actual": actual, "expected": trusted, "ephemeral": true,
			})
			return
		}
		if in.Fingerprint != actual.Fingerprint {
			jsonOut(w, http.StatusConflict, map[string]any{
				"code": "host_key_changed", "server": "Quick Connect", "host": target.Host, "port": target.Port, "actual": actual, "expected": trusted, "ephemeral": true,
				"error": "host key changed again while confirming replacement",
			})
			return
		}
		if err := a.saveQuickTrustedHostKey(uid(r), target, in.JumpHostID, actual); err != nil {
			a.internalError(w, "quickconnect", err)
			return
		}
		a.audit(uid(r), "ssh.quick_host_key.replace", fmt.Sprintf("target=%s:%d route=%s fingerprint=%s", target.Host, target.Port, quickRouteKey(in.JumpHostID), actual.Fingerprint))
	}
	cfg, err := a.quickSSHConfig(uid(r), target, in)
	if err != nil {
		jsonOut(w, 400, map[string]string{"error": err.Error()})
		return
	}
	cb, err := sshx.HostKeyCallback(actual)
	if err != nil {
		a.internalError(w, "quickconnect", err)
		return
	}
	cfg.HostKey = cb
	client, cleanup, err := a.openQuickSSHClient(cfg, in.JumpHostID)
	if err != nil {
		jsonOut(w, 502, map[string]string{"error": err.Error()})
		return
	}
	s, err := a.activateLiveSession(uid(r), 0, fmt.Sprintf("%s@%s", cfg.User, target.Host), target.Host, cfg.User, target.Port, true, client, cleanup, in.Cols, in.Rows)
	if err != nil {
		jsonOut(w, 502, map[string]string{"error": err.Error()})
		return
	}
	a.audit(uid(r), "ssh.quick_connect", fmt.Sprintf("session=%s target=%s@%s:%d", s.ID, cfg.User, target.Host, target.Port))
	out := s.info()
	jsonOut(w, http.StatusCreated, map[string]any{"session": out, "target": target, "username": cfg.User, "hostKey": actual})
}

func (a *App) quickSSHConfig(userID int64, target quickTarget, in quickConnectRequest) (sshx.Config, error) {
	cfg := sshx.Config{Host: target.Host, Port: target.Port, User: target.User, AuthType: strings.TrimSpace(in.AuthType), Timeout: 10 * time.Second}
	if in.CredentialProfileID != nil {
		p, err := a.credentialProfileOwnedBy(userID, *in.CredentialProfileID)
		if err != nil {
			return cfg, err
		}
		p, se, pe, ce, err := a.loadCredentialProfileRaw(p.ID)
		if err != nil {
			return cfg, err
		}
		cfg.User = p.Username
		cfg.AuthType = p.AuthType
		secret, err := a.decryptOptional(se)
		if err != nil {
			return cfg, err
		}
		passphrase, err := a.decryptOptional(pe)
		if err != nil {
			return cfg, err
		}
		cert, err := a.decryptOptional(ce)
		if err != nil {
			return cfg, err
		}
		if cfg.AuthType == "key" || cfg.AuthType == "private-key" {
			cfg.PrivateKey, cfg.Passphrase, cfg.Certificate = secret, passphrase, cert
		} else {
			cfg.Password = secret
		}
		return cfg, nil
	}
	if strings.TrimSpace(cfg.User) == "" {
		return cfg, errors.New("username is required; use user@host or a credential profile")
	}
	if cfg.AuthType == "" {
		cfg.AuthType = "password"
	}
	switch cfg.AuthType {
	case "password", "keyboard-interactive":
		if in.Secret == "" {
			return cfg, errors.New("password/interactive secret is required")
		}
		cfg.Password = in.Secret
	case "key", "private-key":
		if strings.TrimSpace(in.Secret) == "" {
			return cfg, errors.New("private key is required")
		}
		cfg.PrivateKey = in.Secret
		cfg.Passphrase = in.Passphrase
		cfg.Certificate = in.Certificate
	default:
		return cfg, errors.New("unsupported authentication type")
	}
	return cfg, nil
}

func quickRouteKey(jumpID *int64) string {
	if jumpID == nil || *jumpID <= 0 {
		return "direct"
	}
	return fmt.Sprintf("jump:%d", *jumpID)
}

func (a *App) quickTrustedHostKey(userID int64, target quickTarget, jumpID *int64) (sshx.HostKeyInfo, error) {
	var info sshx.HostKeyInfo
	err := a.DB.QueryRow(`SELECT algorithm,key_base64,fingerprint FROM quick_known_host_keys WHERE user_id=? AND host=? AND port=? AND route_key=?`, userID, target.Host, target.Port, quickRouteKey(jumpID)).Scan(&info.Algorithm, &info.KeyBase64, &info.Fingerprint)
	return info, err
}

func (a *App) saveQuickTrustedHostKey(userID int64, target quickTarget, jumpID *int64, info sshx.HostKeyInfo) error {
	_, err := a.DB.Exec(`INSERT INTO quick_known_host_keys(user_id,host,port,route_key,algorithm,key_base64,fingerprint,trusted_at) VALUES(?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
		ON CONFLICT(user_id,host,port,route_key) DO UPDATE SET algorithm=excluded.algorithm,key_base64=excluded.key_base64,fingerprint=excluded.fingerprint,trusted_at=CURRENT_TIMESTAMP`, userID, target.Host, target.Port, quickRouteKey(jumpID), info.Algorithm, info.KeyBase64, info.Fingerprint)
	return err
}

func (a *App) scanQuickTarget(target quickTarget, jumpID *int64) (sshx.HostKeyInfo, error) {
	if jumpID == nil {
		return sshx.ScanHostKey(target.Host, target.Port, 8*time.Second)
	}
	jumpClient, cleanup, err := a.openSSHClient(*jumpID)
	if err != nil {
		return sshx.HostKeyInfo{}, err
	}
	defer cleanup()
	return sshx.ScanHostKeyVia(jumpClient, target.Host, target.Port, 8*time.Second)
}

func (a *App) openQuickSSHClient(cfg sshx.Config, jumpID *int64) (*ssh.Client, func(), error) {
	if jumpID == nil {
		client, err := sshx.Client(cfg)
		if err != nil {
			return nil, nil, err
		}
		return client, func() { _ = client.Close() }, nil
	}
	jumpClient, jumpCleanup, err := a.openSSHClient(*jumpID)
	if err != nil {
		return nil, nil, err
	}
	client, err := sshx.ClientVia(jumpClient, cfg)
	if err != nil {
		jumpCleanup()
		return nil, nil, err
	}
	return client, func() { _ = client.Close(); jumpCleanup() }, nil
}
