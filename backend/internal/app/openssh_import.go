package app

import (
	"bufio"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

type openSSHImportEntry struct {
	Alias                    string   `json:"alias"`
	HostName                 string   `json:"hostName"`
	User                     string   `json:"user,omitempty"`
	Port                     int      `json:"port"`
	IdentityFile             string   `json:"identityFile,omitempty"`
	ProxyJump                string   `json:"proxyJump,omitempty"`
	PreferredAuthentications string   `json:"preferredAuthentications,omitempty"`
	ServerAliveInterval      int      `json:"serverAliveInterval,omitempty"`
	Warnings                 []string `json:"warnings,omitempty"`
}

type openSSHImportPreview struct {
	Entries  []openSSHImportEntry `json:"entries"`
	Warnings []string             `json:"warnings,omitempty"`
}

type openSSHImportRequest struct {
	Config              string   `json:"config"`
	Aliases             []string `json:"aliases"`
	CredentialProfileID int64    `json:"credentialProfileId"`
	FolderID            *int64   `json:"folderId"`
}

type openSSHImportResult struct {
	Imported []Server `json:"imported"`
	Skipped  []string `json:"skipped,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

func (a *App) openSSHImportPreviewHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		Config string `json:"config"`
	}
	if decode(r, &in) != nil || strings.TrimSpace(in.Config) == "" {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "OpenSSH config is required"})
		return
	}
	preview := parseOpenSSHConfig(in.Config)
	jsonOut(w, http.StatusOK, preview)
}

func (a *App) openSSHImportHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var in openSSHImportRequest
	if decode(r, &in) != nil || strings.TrimSpace(in.Config) == "" || len(in.Aliases) == 0 || in.CredentialProfileID <= 0 {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "config, selected aliases and credentialProfileId are required"})
		return
	}
	profile, e := a.credentialProfileOwnedBy(uid(r), in.CredentialProfileID)
	if e != nil {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "credential profile is not available"})
		return
	}
	if in.FolderID != nil {
		var n int
		if e := a.DB.QueryRow("SELECT COUNT(*) FROM folders WHERE id=? AND owner_user_id=?", *in.FolderID, uid(r)).Scan(&n); e != nil || n == 0 {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "folder not found"})
			return
		}
	}

	preview := parseOpenSSHConfig(in.Config)
	byAlias := make(map[string]openSSHImportEntry, len(preview.Entries))
	for _, entry := range preview.Entries {
		byAlias[entry.Alias] = entry
	}
	selectedSet := map[string]bool{}
	selected := make([]openSSHImportEntry, 0, len(in.Aliases))
	for _, alias := range in.Aliases {
		alias = strings.TrimSpace(alias)
		if alias == "" || selectedSet[alias] {
			continue
		}
		entry, ok := byAlias[alias]
		if !ok {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("preview entry %q no longer exists in config", alias)})
			return
		}
		selectedSet[alias] = true
		selected = append(selected, entry)
	}
	if len(selected) == 0 {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "no valid aliases selected"})
		return
	}

	tx, e := a.DB.Begin()
	if e != nil {
		a.internalError(w, "openssh_import", e)
		return
	}
	defer tx.Rollback()

	result := openSSHImportResult{Imported: []Server{}, Skipped: []string{}, Warnings: append([]string{}, preview.Warnings...)}
	created := map[string]int64{}
	createdEntry := map[string]openSSHImportEntry{}

	for _, entry := range selected {
		var existing int64
		e := tx.QueryRow("SELECT id FROM servers WHERE owner_user_id=? AND name=? LIMIT 1", uid(r), entry.Alias).Scan(&existing)
		if e == nil {
			result.Skipped = append(result.Skipped, entry.Alias+": server name already exists")
			continue
		}
		if !errors.Is(e, sql.ErrNoRows) {
			a.internalError(w, "openssh_import", e)
			return
		}
		host := strings.TrimSpace(entry.HostName)
		if host == "" {
			host = entry.Alias
		}
		port := entry.Port
		if port <= 0 || port > 65535 {
			port = 22
		}
		res, e := tx.Exec(`INSERT INTO servers(owner_user_id,name,host,port,username,auth_type,secret_enc,folder_id,color,kind,credential_profile_id,jump_host_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL)`,
			uid(r), entry.Alias, host, port, profile.Username, profile.AuthType, "", in.FolderID, "#5aa9ff", "ssh", in.CredentialProfileID)
		if e != nil {
			a.internalError(w, "openssh_import", e)
			return
		}
		id, _ := res.LastInsertId()
		created[entry.Alias] = id
		createdEntry[entry.Alias] = entry
		warnings := append([]string{}, entry.Warnings...)
		if entry.User != "" && entry.User != profile.Username {
			warnings = append(warnings, fmt.Sprintf("OpenSSH User %q replaced by credential profile user %q", entry.User, profile.Username))
		}
		if entry.IdentityFile != "" {
			warnings = append(warnings, "IdentityFile is informational only; credentials come from the selected ZentSSH profile")
		}
		result.Warnings = append(result.Warnings, prefixWarnings(entry.Alias, warnings)...)
		result.Imported = append(result.Imported, Server{ID: id, Name: entry.Alias, Host: host, Port: port, Username: profile.Username, AuthType: profile.AuthType, FolderID: in.FolderID, Color: "#5aa9ff", Kind: "ssh", CredentialProfileID: &in.CredentialProfileID})
	}

	// Resolve one-level ProxyJump references after every selected server exists.
	for alias, id := range created {
		entry := createdEntry[alias]
		if strings.TrimSpace(entry.ProxyJump) == "" {
			continue
		}
		jumpAlias, ok := proxyJumpAlias(entry.ProxyJump)
		if !ok {
			result.Warnings = append(result.Warnings, alias+": ProxyJump could not be mapped automatically")
			continue
		}
		var jumpID int64
		if newID, exists := created[jumpAlias]; exists {
			jumpEntry := createdEntry[jumpAlias]
			if strings.TrimSpace(jumpEntry.ProxyJump) != "" {
				result.Warnings = append(result.Warnings, alias+": nested ProxyJump is not supported; jump host left unset")
				continue
			}
			jumpID = newID
		} else {
			var kind string
			var nested sql.NullInt64
			e := tx.QueryRow("SELECT id,kind,jump_host_id FROM servers WHERE owner_user_id=? AND name=? LIMIT 1", uid(r), jumpAlias).Scan(&jumpID, &kind, &nested)
			if e != nil || kind != "ssh" || nested.Valid {
				result.Warnings = append(result.Warnings, alias+": ProxyJump "+jumpAlias+" was not found as a usable one-level SSH server")
				continue
			}
		}
		if jumpID == id {
			result.Warnings = append(result.Warnings, alias+": self-referencing ProxyJump ignored")
			continue
		}
		if _, e := tx.Exec("UPDATE servers SET jump_host_id=? WHERE id=? AND owner_user_id=?", jumpID, id, uid(r)); e != nil {
			a.internalError(w, "openssh_import", e)
			return
		}
		for i := range result.Imported {
			if result.Imported[i].ID == id {
				j := jumpID
				result.Imported[i].JumpHostID = &j
				break
			}
		}
	}

	if e := tx.Commit(); e != nil {
		a.internalError(w, "openssh_import", e)
		return
	}
	a.audit(uid(r), "server.import_openssh", fmt.Sprintf("imported=%d skipped=%d", len(result.Imported), len(result.Skipped)))
	jsonOut(w, http.StatusCreated, result)
}

func parseOpenSSHConfig(input string) openSSHImportPreview {
	preview := openSSHImportPreview{Entries: []openSSHImportEntry{}}
	type block struct {
		aliases []string
		entry   openSSHImportEntry
	}
	var current *block
	flush := func() {
		if current == nil {
			return
		}
		for _, alias := range current.aliases {
			if !concreteSSHAlias(alias) {
				preview.Warnings = append(preview.Warnings, fmt.Sprintf("Host %q skipped because wildcard/negated patterns are not importable", alias))
				continue
			}
			e := current.entry
			e.Alias = alias
			if e.HostName == "" {
				e.HostName = alias
			}
			if e.Port == 0 {
				e.Port = 22
			}
			preview.Entries = append(preview.Entries, e)
		}
		current = nil
	}

	scanner := bufio.NewScanner(strings.NewReader(input))
	scanner.Buffer(make([]byte, 1024), 2<<20)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		fields, e := splitSSHFields(scanner.Text())
		if e != nil {
			preview.Warnings = append(preview.Warnings, fmt.Sprintf("line %d: %v", lineNo, e))
			continue
		}
		if len(fields) == 0 {
			continue
		}
		key := strings.ToLower(fields[0])
		vals := fields[1:]
		switch key {
		case "host":
			flush()
			if len(vals) == 0 {
				preview.Warnings = append(preview.Warnings, fmt.Sprintf("line %d: Host without alias ignored", lineNo))
				continue
			}
			current = &block{aliases: vals, entry: openSSHImportEntry{Port: 22}}
		case "match":
			flush()
			preview.Warnings = append(preview.Warnings, fmt.Sprintf("line %d: Match blocks are not imported", lineNo))
		case "include":
			preview.Warnings = append(preview.Warnings, fmt.Sprintf("line %d: Include is not expanded; paste the referenced config too if needed", lineNo))
		case "proxycommand":
			if current != nil {
				current.entry.Warnings = append(current.entry.Warnings, "ProxyCommand is not imported; use a ZentSSH Jump Host instead")
			}
		default:
			if current == nil || len(vals) == 0 {
				continue
			}
			value := strings.Join(vals, " ")
			switch key {
			case "hostname":
				current.entry.HostName = value
			case "user":
				current.entry.User = value
			case "port":
				p, e := strconv.Atoi(vals[0])
				if e != nil || p < 1 || p > 65535 {
					current.entry.Warnings = append(current.entry.Warnings, fmt.Sprintf("invalid Port %q; default 22 will be used", vals[0]))
					current.entry.Port = 22
				} else {
					current.entry.Port = p
				}
			case "identityfile":
				if current.entry.IdentityFile == "" {
					current.entry.IdentityFile = value
				} else {
					current.entry.Warnings = append(current.entry.Warnings, "multiple IdentityFile directives found; only the first is shown as a hint")
				}
			case "proxyjump":
				current.entry.ProxyJump = value
			case "preferredauthentications":
				current.entry.PreferredAuthentications = value
			case "serveraliveinterval":
				if n, e := strconv.Atoi(vals[0]); e == nil && n >= 0 {
					current.entry.ServerAliveInterval = n
				} else {
					current.entry.Warnings = append(current.entry.Warnings, fmt.Sprintf("invalid ServerAliveInterval %q ignored", vals[0]))
				}
			}
		}
	}
	flush()
	if e := scanner.Err(); e != nil {
		preview.Warnings = append(preview.Warnings, "config scan failed: "+e.Error())
	}
	return preview
}

func splitSSHFields(line string) ([]string, error) {
	var fields []string
	var b strings.Builder
	var quote rune
	escaped := false
	flush := func() {
		if b.Len() > 0 {
			fields = append(fields, b.String())
			b.Reset()
		}
	}
	for _, r := range line {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == '#' {
			break
		}
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			flush()
			continue
		}
		b.WriteRune(r)
	}
	if escaped {
		b.WriteRune('\\')
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote")
	}
	flush()
	return fields, nil
}

func concreteSSHAlias(alias string) bool {
	alias = strings.TrimSpace(alias)
	return alias != "" && !strings.HasPrefix(alias, "!") && !strings.ContainsAny(alias, "*?")
}

func proxyJumpAlias(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "none") || strings.Contains(value, ",") {
		return "", false
	}
	fields, e := splitSSHFields(value)
	if e != nil || len(fields) != 1 {
		return "", false
	}
	value = fields[0]
	if at := strings.LastIndex(value, "@"); at >= 0 {
		value = value[at+1:]
	}
	if strings.HasPrefix(value, "[") {
		if end := strings.Index(value, "]"); end > 0 {
			value = value[1:end]
		}
	} else if strings.Count(value, ":") == 1 {
		value = strings.SplitN(value, ":", 2)[0]
	}
	value = strings.TrimSpace(value)
	return value, concreteSSHAlias(value)
}

func prefixWarnings(alias string, warnings []string) []string {
	out := make([]string, 0, len(warnings))
	for _, warning := range warnings {
		if strings.TrimSpace(warning) != "" {
			out = append(out, alias+": "+warning)
		}
	}
	return out
}
