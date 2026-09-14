package app

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

type credentialProfile struct {
	ID               int64  `json:"id"`
	OwnerUserID      int64  `json:"ownerUserId"`
	Name             string `json:"name"`
	Username         string `json:"username"`
	AuthType         string `json:"authType"`
	Secret           string `json:"secret,omitempty"`
	Passphrase       string `json:"passphrase,omitempty"`
	Certificate      string `json:"certificate,omitempty"`
	Shared           bool   `json:"shared"`
	IsOwner          bool   `json:"isOwner"`
	HasSecret        bool   `json:"hasSecret"`
	HasPassphrase    bool   `json:"hasPassphrase"`
	HasCertificate   bool   `json:"hasCertificate"`
	ClearSecret      bool   `json:"clearSecret,omitempty"`
	ClearPassphrase  bool   `json:"clearPassphrase,omitempty"`
	ClearCertificate bool   `json:"clearCertificate,omitempty"`
}

func (a *App) credentialProfiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rows, e := a.DB.Query(`SELECT id,owner_user_id,name,username,auth_type,secret_enc,passphrase_enc,certificate_enc,shared FROM credential_profiles WHERE owner_user_id=? ORDER BY lower(name),id`, uid(r))
		if e != nil {
			a.internalError(w, "credentials", e)
			return
		}
		defer rows.Close()
		out := []credentialProfile{}
		for rows.Next() {
			var p credentialProfile
			var secret, passphrase, cert string
			var shared int
			if e := rows.Scan(&p.ID, &p.OwnerUserID, &p.Name, &p.Username, &p.AuthType, &secret, &passphrase, &cert, &shared); e != nil {
				a.internalError(w, "credentials", e)
				return
			}
			p.Shared = shared != 0
			p.IsOwner = p.OwnerUserID == uid(r)
			p.HasSecret = secret != ""
			p.HasPassphrase = passphrase != ""
			p.HasCertificate = cert != ""
			out = append(out, p)
		}
		jsonOut(w, 200, out)
	case http.MethodPost:
		var p credentialProfile
		if decode(r, &p) != nil {
			jsonOut(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if e := normalizeCredentialProfile(&p); e != nil {
			jsonOut(w, 400, map[string]string{"error": e.Error()})
			return
		}
		if strings.TrimSpace(p.Secret) == "" {
			jsonOut(w, 400, map[string]string{"error": "a credential secret is required"})
			return
		}
		secretEnc, passphraseEnc, certEnc, e := a.encryptCredentialProfileSecrets(p.Secret, p.Passphrase, p.Certificate)
		if e != nil {
			jsonOut(w, 500, map[string]string{"error": "credential encryption failed"})
			return
		}
		res, e := a.DB.Exec(`INSERT INTO credential_profiles(owner_user_id,name,username,auth_type,secret_enc,passphrase_enc,certificate_enc,shared) VALUES(?,?,?,?,?,?,?,?)`, uid(r), p.Name, p.Username, p.AuthType, secretEnc, passphraseEnc, certEnc, boolInt(p.Shared))
		if e != nil {
			if strings.Contains(strings.ToLower(e.Error()), "unique") {
				jsonOut(w, 409, map[string]string{"error": "a credential profile with this name already exists"})
			} else {
				a.internalError(w, "credentials", e)
			}
			return
		}
		p.ID, _ = res.LastInsertId()
		p.OwnerUserID = uid(r)
		p.IsOwner = true
		p.HasSecret = secretEnc != ""
		p.HasPassphrase = passphraseEnc != ""
		p.HasCertificate = certEnc != ""
		p.Secret, p.Passphrase, p.Certificate = "", "", ""
		a.audit(uid(r), "credential_profile.create", fmt.Sprintf("profile=%d name=%s", p.ID, p.Name))
		jsonOut(w, 201, p)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *App) credentialProfileByID(w http.ResponseWriter, r *http.Request) {
	id, e := parseID(r.URL.Path, "/api/credential-profiles/")
	if e != nil {
		jsonOut(w, 400, map[string]string{"error": "bad profile id"})
		return
	}
	p, encSecret, encPassphrase, encCert, e := a.loadCredentialProfileRaw(id)
	if e != nil {
		jsonOut(w, 404, map[string]string{"error": "credential profile not found"})
		return
	}
	if p.OwnerUserID != uid(r) {
		jsonOut(w, 403, map[string]string{"error": "only the profile owner can change this credential profile"})
		return
	}
	switch r.Method {
	case http.MethodPatch:
		oldAuthType := p.AuthType
		var in credentialProfile
		if decode(r, &in) != nil {
			jsonOut(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if in.Name != "" {
			p.Name = in.Name
		}
		if in.Username != "" {
			p.Username = in.Username
		}
		if in.AuthType != "" {
			p.AuthType = in.AuthType
		}
		p.Shared = in.Shared
		if !p.Shared {
			var workspaceUseCount int
			if e := a.DB.QueryRow(`SELECT COUNT(*) FROM servers WHERE credential_profile_id=? AND workspace_id IS NOT NULL`, id).Scan(&workspaceUseCount); e != nil {
				a.internalError(w, "credentials", e)
				return
			}
			if workspaceUseCount > 0 {
				jsonOut(w, http.StatusConflict, map[string]any{
					"error":       "credential profile is still shared through workspace servers",
					"code":        "credential_profile_used_by_workspace",
					"serverCount": workspaceUseCount,
				})
				return
			}
		}
		if e := normalizeCredentialProfile(&p); e != nil {
			jsonOut(w, 400, map[string]string{"error": e.Error()})
			return
		}
		if p.AuthType != oldAuthType && strings.TrimSpace(in.Secret) == "" {
			jsonOut(w, 400, map[string]string{"error": "changing authentication type requires a new credential secret"})
			return
		}
		if in.ClearSecret {
			encSecret = ""
		}
		if in.ClearPassphrase {
			encPassphrase = ""
		}
		if in.ClearCertificate {
			encCert = ""
		}
		if in.Secret != "" {
			encSecret, e = a.Box.Encrypt(in.Secret)
			if e != nil {
				jsonOut(w, 500, map[string]string{"error": "credential encryption failed"})
				return
			}
		}
		if in.Passphrase != "" {
			encPassphrase, e = a.Box.Encrypt(in.Passphrase)
			if e != nil {
				jsonOut(w, 500, map[string]string{"error": "credential encryption failed"})
				return
			}
		}
		if in.Certificate != "" {
			encCert, e = a.Box.Encrypt(in.Certificate)
			if e != nil {
				jsonOut(w, 500, map[string]string{"error": "credential encryption failed"})
				return
			}
		}
		if p.AuthType != "key" && p.AuthType != "private-key" {
			encPassphrase = ""
			encCert = ""
		}
		if encSecret == "" {
			jsonOut(w, 400, map[string]string{"error": "credential profile must contain a secret"})
			return
		}
		if _, e = a.DB.Exec(`UPDATE credential_profiles SET name=?,username=?,auth_type=?,secret_enc=?,passphrase_enc=?,certificate_enc=?,shared=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, p.Name, p.Username, p.AuthType, encSecret, encPassphrase, encCert, boolInt(p.Shared), id); e != nil {
			if strings.Contains(strings.ToLower(e.Error()), "unique") {
				jsonOut(w, 409, map[string]string{"error": "a credential profile with this name already exists"})
			} else {
				a.internalError(w, "credentials", e)
			}
			return
		}
		p.HasSecret = encSecret != ""
		p.HasPassphrase = encPassphrase != ""
		p.HasCertificate = encCert != ""
		p.IsOwner = true
		a.audit(uid(r), "credential_profile.update", fmt.Sprintf("profile=%d name=%s", p.ID, p.Name))
		jsonOut(w, 200, p)
	case http.MethodDelete:
		var n int
		if e := a.DB.QueryRow("SELECT COUNT(*) FROM servers WHERE credential_profile_id=?", id).Scan(&n); e != nil {
			a.internalError(w, "credentials", e)
			return
		}
		if n > 0 {
			jsonOut(w, 409, map[string]string{"error": "credential profile is still used by servers"})
			return
		}
		if _, e := a.DB.Exec("DELETE FROM credential_profiles WHERE id=?", id); e != nil {
			a.internalError(w, "credentials", e)
			return
		}
		a.audit(uid(r), "credential_profile.delete", fmt.Sprintf("profile=%d", id))
		jsonOut(w, 200, map[string]bool{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func normalizeCredentialProfile(p *credentialProfile) error {
	p.Name = strings.TrimSpace(p.Name)
	p.Username = strings.TrimSpace(p.Username)
	p.AuthType = strings.TrimSpace(p.AuthType)
	if p.Name == "" || p.Username == "" {
		return errors.New("name and username are required")
	}
	if p.AuthType == "" {
		p.AuthType = "password"
	}
	switch p.AuthType {
	case "password", "keyboard-interactive", "key", "private-key":
	default:
		return errors.New("unsupported credential profile authentication type")
	}
	return nil
}

func (a *App) encryptCredentialProfileSecrets(secret, passphrase, certificate string) (string, string, string, error) {
	var se, pe, ce string
	var e error
	if secret != "" {
		if se, e = a.Box.Encrypt(secret); e != nil {
			return "", "", "", e
		}
	}
	if passphrase != "" {
		if pe, e = a.Box.Encrypt(passphrase); e != nil {
			return "", "", "", e
		}
	}
	if certificate != "" {
		if ce, e = a.Box.Encrypt(certificate); e != nil {
			return "", "", "", e
		}
	}
	return se, pe, ce, nil
}

func (a *App) loadCredentialProfileRaw(id int64) (credentialProfile, string, string, string, error) {
	var p credentialProfile
	var se, pe, ce string
	var shared int
	e := a.DB.QueryRow(`SELECT id,owner_user_id,name,username,auth_type,secret_enc,passphrase_enc,certificate_enc,shared FROM credential_profiles WHERE id=?`, id).Scan(&p.ID, &p.OwnerUserID, &p.Name, &p.Username, &p.AuthType, &se, &pe, &ce, &shared)
	p.Shared = shared != 0
	p.HasSecret = se != ""
	p.HasPassphrase = pe != ""
	p.HasCertificate = ce != ""
	return p, se, pe, ce, e
}

func (a *App) credentialProfileOwnedBy(userID, profileID int64) (credentialProfile, error) {
	p, _, _, _, e := a.loadCredentialProfileRaw(profileID)
	if e != nil {
		return p, e
	}
	if p.OwnerUserID != userID {
		return p, errors.New("only your own credential profiles can be assigned")
	}
	return p, nil
}

func (a *App) prepareServerCredentials(userID int64, s *Server) error {
	if s.CredentialProfileID == nil {
		if strings.TrimSpace(s.Username) == "" {
			return errors.New("username is required when no credential profile is selected")
		}
		if s.AuthType == "" {
			s.AuthType = "password"
		}
		return nil
	}
	p, e := a.credentialProfileOwnedBy(userID, *s.CredentialProfileID)
	if e != nil {
		return e
	}
	s.Username = p.Username
	s.AuthType = p.AuthType
	// Inline server secrets are ignored while a profile is selected.
	s.Secret = ""
	return nil
}

func int64PtrFromString(v string) *int64 {
	if v == "" {
		return nil
	}
	n, e := strconv.ParseInt(v, 10, 64)
	if e != nil {
		return nil
	}
	return &n
}
