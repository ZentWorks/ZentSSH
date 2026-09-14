package app

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/crypto/ssh"
)

const maxCrontabBytes = 1024 * 1024

func (a *App) serverCrontab(w http.ResponseWriter, r *http.Request, serverID int64) {
	if _, _, err := a.loadServerForUser(uid(r), serverID); err != nil {
		jsonOut(w, http.StatusNotFound, map[string]string{"error": "server not found"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		content, err := a.readServerCrontab(serverID)
		if err != nil {
			a.writeSSHConnectError(w, err)
			return
		}
		jsonOut(w, http.StatusOK, map[string]any{"content": content})
	case http.MethodPut:
		var in struct {
			Content string `json:"content"`
		}
		if decode(r, &in) != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid crontab payload"})
			return
		}
		if len(in.Content) > maxCrontabBytes {
			jsonOut(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "crontab is larger than 1 MiB"})
			return
		}
		if err := a.writeServerCrontab(serverID, in.Content); err != nil {
			jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		a.audit(uid(r), "server.crontab.update", fmt.Sprintf("server=%d", serverID))
		jsonOut(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *App) readServerCrontab(serverID int64) (string, error) {
	client, cleanup, err := a.openSSHClient(serverID)
	if err != nil {
		return "", err
	}
	defer cleanup()

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	out, err := session.CombinedOutput("crontab -l")
	if err != nil {
		text := strings.TrimSpace(string(out))
		if isNoCrontabError(err, text) {
			return "", nil
		}
		if text == "" {
			text = err.Error()
		}
		return "", fmt.Errorf("crontab konnte nicht gelesen werden: %s", text)
	}
	return string(out), nil
}

func (a *App) writeServerCrontab(serverID int64, content string) error {
	if len(content) > maxCrontabBytes {
		return errors.New("crontab is larger than 1 MiB")
	}
	content = strings.ReplaceAll(content, "\r\n", "\n")
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}

	client, cleanup, err := a.openSSHClient(serverID)
	if err != nil {
		return err
	}
	defer cleanup()

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	session.Stdin = strings.NewReader(content)
	out, err := session.CombinedOutput("crontab -")
	if err != nil {
		text := strings.TrimSpace(string(out))
		if text == "" {
			text = err.Error()
		}
		return fmt.Errorf("crontab wurde nicht gespeichert: %s", text)
	}
	return nil
}

func isNoCrontabError(err error, output string) bool {
	var exitErr *ssh.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}
	lower := strings.ToLower(output)
	return strings.Contains(lower, "no crontab for") || strings.Contains(lower, "no crontab")
}
