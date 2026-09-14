package app

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

type userSettings struct {
	SSHSessionRetention string  `json:"sshSessionRetention"`
	ShowHiddenFiles     bool    `json:"showHiddenFiles"`
	Language            string  `json:"language"`
	CollapsedFolderIDs  []int64 `json:"collapsedFolderIds"`
}

func normalizeSessionRetentionSetting(v string) (string, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "", "inherit":
		return "inherit", true
	case "0", "off", "immediate":
		return "immediate", true
	case "5m", "30m", "2h", "8h", "unlimited":
		return v, true
	default:
		return "", false
	}
}

func normalizeUILanguage(v string) (string, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "de" || strings.HasPrefix(v, "de-") {
		return "de", true
	}
	if v == "en" || strings.HasPrefix(v, "en-") {
		return "en", true
	}
	return "", false
}

func browserUILanguage(acceptLanguage string) string {
	first := strings.TrimSpace(strings.Split(acceptLanguage, ",")[0])
	if semi := strings.Index(first, ";"); semi >= 0 {
		first = first[:semi]
	}
	first = strings.ToLower(strings.TrimSpace(first))
	if first == "de" || strings.HasPrefix(first, "de-") {
		return "de"
	}
	return "en"
}

func normalizeCollapsedFolderIDs(values []int64) []int64 {
	if len(values) == 0 {
		return []int64{}
	}
	seen := make(map[int64]struct{}, len(values))
	out := make([]int64, 0, len(values))
	for _, id := range values {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func encodeCollapsedFolderIDs(values []int64) string {
	b, err := json.Marshal(normalizeCollapsedFolderIDs(values))
	if err != nil {
		return "[]"
	}
	return string(b)
}

func decodeCollapsedFolderIDs(raw string) []int64 {
	var values []int64
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &values); err != nil {
		return []int64{}
	}
	return normalizeCollapsedFolderIDs(values)
}

func retentionSettingDuration(v string, fallback time.Duration) time.Duration {
	v, ok := normalizeSessionRetentionSetting(v)
	if !ok || v == "inherit" {
		return fallback
	}
	if v == "immediate" {
		return 0
	}
	if v == "unlimited" {
		return -1
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func retentionDurationSetting(d, fallback time.Duration) string {
	if d == fallback {
		return "inherit"
	}
	if d < 0 {
		return "unlimited"
	}
	if d == 0 {
		return "immediate"
	}
	return d.String()
}

func (a *App) settingsForUser(userID int64) (userSettings, error) {
	var s userSettings
	var hidden int
	var collapsedRaw string
	err := a.DB.QueryRow("SELECT ssh_session_retention,show_hidden_files,ui_language,collapsed_folder_ids FROM user_settings WHERE user_id=?", userID).Scan(&s.SSHSessionRetention, &hidden, &s.Language, &collapsedRaw)
	s.ShowHiddenFiles = hidden != 0
	if errors.Is(err, sql.ErrNoRows) {
		s.SSHSessionRetention = "inherit"
		s.ShowHiddenFiles = false
		s.Language = ""
		s.CollapsedFolderIDs = []int64{}
		return s, nil
	}
	if err != nil {
		return s, err
	}
	s.CollapsedFolderIDs = decodeCollapsedFolderIDs(collapsedRaw)
	return s, nil
}

func (a *App) ensureUserLanguage(userID int64, acceptLanguage string) (string, error) {
	s, err := a.settingsForUser(userID)
	if err != nil {
		return "", err
	}
	if lang, ok := normalizeUILanguage(s.Language); ok {
		return lang, nil
	}
	lang := browserUILanguage(acceptLanguage)
	_, err = a.DB.Exec(`INSERT INTO user_settings(user_id,ssh_session_retention,show_hidden_files,ui_language,collapsed_folder_ids) VALUES(?,?,?,?,?)
		ON CONFLICT(user_id) DO UPDATE SET ui_language=excluded.ui_language`, userID, "inherit", 0, lang, "[]")
	if err != nil {
		return "", err
	}
	return lang, nil
}

func (a *App) sessionRetentionForUser(userID int64) time.Duration {
	s, err := a.settingsForUser(userID)
	if err != nil {
		return a.cfg.SessionRetention
	}
	return retentionSettingDuration(s.SSHSessionRetention, a.cfg.SessionRetention)
}

func (a *App) meSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s, err := a.settingsForUser(uid(r))
		if err != nil {
			a.internalError(w, "settings", err)
			return
		}
		if _, ok := normalizeUILanguage(s.Language); !ok {
			s.Language, err = a.ensureUserLanguage(uid(r), r.Header.Get("Accept-Language"))
			if err != nil {
				a.internalError(w, "settings", err)
				return
			}
		}
		jsonOut(w, 200, s)
	case http.MethodPatch:
		var in userSettings
		if decode(r, &in) != nil {
			jsonOut(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		current, err := a.settingsForUser(uid(r))
		if err != nil {
			a.internalError(w, "settings", err)
			return
		}
		retention, ok := normalizeSessionRetentionSetting(in.SSHSessionRetention)
		if !ok {
			jsonOut(w, 400, map[string]string{"error": "invalid SSH session retention"})
			return
		}
		language := current.Language
		if strings.TrimSpace(in.Language) != "" {
			language, ok = normalizeUILanguage(in.Language)
			if !ok {
				jsonOut(w, 400, map[string]string{"error": "invalid UI language"})
				return
			}
		} else if _, ok = normalizeUILanguage(language); !ok {
			language = browserUILanguage(r.Header.Get("Accept-Language"))
		}
		hidden := 0
		if in.ShowHiddenFiles {
			hidden = 1
		}
		collapsed := current.CollapsedFolderIDs
		if in.CollapsedFolderIDs != nil {
			collapsed = normalizeCollapsedFolderIDs(in.CollapsedFolderIDs)
		}
		collapsedRaw := encodeCollapsedFolderIDs(collapsed)
		_, err = a.DB.Exec(`INSERT INTO user_settings(user_id,ssh_session_retention,show_hidden_files,ui_language,collapsed_folder_ids) VALUES(?,?,?,?,?)
			ON CONFLICT(user_id) DO UPDATE SET ssh_session_retention=excluded.ssh_session_retention,show_hidden_files=excluded.show_hidden_files,ui_language=excluded.ui_language,collapsed_folder_ids=excluded.collapsed_folder_ids`, uid(r), retention, hidden, language, collapsedRaw)
		if err != nil {
			a.internalError(w, "settings", err)
			return
		}
		effective := retentionSettingDuration(retention, a.cfg.SessionRetention)
		a.mu.Lock()
		for _, live := range a.live {
			if live.UserID == uid(r) {
				live.Mu.Lock()
				live.Retention = effective
				live.Mu.Unlock()
			}
		}
		a.mu.Unlock()
		a.audit(uid(r), "settings.update", "session_retention="+retention+" language="+language)
		jsonOut(w, 200, userSettings{SSHSessionRetention: retention, ShowHiddenFiles: in.ShowHiddenFiles, Language: language, CollapsedFolderIDs: collapsed})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
