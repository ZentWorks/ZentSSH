package app

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	"zentssh.local/backend/internal/sshx"
)

type LiveSession struct {
	ID         string
	UserID     int64
	ServerID   int64
	ServerName string
	Host       string
	Username   string
	Port       int
	Transient  bool
	CreatedAt  time.Time

	SSHSession *ssh.Session
	In         io.WriteCloser
	Out        io.Reader
	cleanup    func()

	Mu           sync.Mutex
	ioMu         sync.Mutex
	closeOnce    sync.Once
	Buffer       []byte
	LastActivity time.Time
	DetachedAt   time.Time
	Closed       bool
	EverAttached bool
	CloseReason  string
	Retention    time.Duration
	Attached     map[*sessionAttachment]struct{}
}

type sessionAttachment struct {
	ws   *websocket.Conn
	send chan []byte
	done chan struct{}
	once sync.Once
}

type sessionInfo struct {
	ID           string     `json:"id"`
	UserID       int64      `json:"userId,omitempty"`
	UserName     string     `json:"userName,omitempty"`
	ServerID     int64      `json:"serverId"`
	ServerName   string     `json:"serverName"`
	Host         string     `json:"host,omitempty"`
	Username     string     `json:"username,omitempty"`
	Port         int        `json:"port,omitempty"`
	Transient    bool       `json:"transient,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
	LastActivity time.Time  `json:"lastActivity"`
	DetachedAt   *time.Time `json:"detachedAt,omitempty"`
	Attached     bool       `json:"attached"`
	Attachments  int        `json:"attachments"`
	Retention    string     `json:"retention"`
}

func (s *LiveSession) info() sessionInfo {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	var detached *time.Time
	if !s.DetachedAt.IsZero() {
		t := s.DetachedAt
		detached = &t
	}
	retention := s.Retention.String()
	if s.Retention < 0 {
		retention = "unlimited"
	} else if s.Retention == 0 {
		retention = "immediate"
	}
	return sessionInfo{
		ID:           s.ID,
		UserID:       s.UserID,
		ServerID:     s.ServerID,
		ServerName:   s.ServerName,
		Host:         s.Host,
		Username:     s.Username,
		Port:         s.Port,
		Transient:    s.Transient,
		CreatedAt:    s.CreatedAt,
		LastActivity: s.LastActivity,
		DetachedAt:   detached,
		Attached:     len(s.Attached) > 0,
		Attachments:  len(s.Attached),
		Retention:    retention,
	}
}

func (a *App) reserveLiveSession(userID int64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.live)+a.sessionReservations >= a.cfg.MaxTotalSessions {
		return fmt.Errorf("global SSH session limit reached (%d)", a.cfg.MaxTotalSessions)
	}
	count := a.sessionReserveUser[userID]
	for _, s := range a.live {
		if s.UserID == userID {
			count++
		}
	}
	if count >= a.cfg.MaxSessionsPerUser {
		return fmt.Errorf("SSH session limit for user reached (%d)", a.cfg.MaxSessionsPerUser)
	}
	a.sessionReservations++
	a.sessionReserveUser[userID]++
	return nil
}

func (a *App) releaseLiveSessionReservation(userID int64) {
	a.mu.Lock()
	if a.sessionReservations > 0 {
		a.sessionReservations--
	}
	if a.sessionReserveUser[userID] <= 1 {
		delete(a.sessionReserveUser, userID)
	} else {
		a.sessionReserveUser[userID]--
	}
	a.mu.Unlock()
}

func (a *App) createLiveSession(userID, serverID int64, cols, rows int) (*LiveSession, error) {
	// Resolve ownership before consuming a session reservation or touching SSH.
	// Foreign ids deliberately fail as not found at the authorization boundary.
	server, _, err := a.loadServerForUser(userID, serverID)
	if err != nil {
		return nil, err
	}
	if err := a.reserveLiveSession(userID); err != nil {
		return nil, err
	}
	defer a.releaseLiveSessionReservation(userID)

	client, cleanup, err := a.openSSHClient(serverID)
	if err != nil {
		return nil, err
	}
	return a.activateLiveSession(userID, serverID, server.Name, server.Host, server.Username, server.Port, false, client, cleanup, cols, rows)
}

func (a *App) activateLiveSession(userID, serverID int64, serverName, host, username string, port int, transient bool, client *ssh.Client, cleanup func(), cols, rows int) (*LiveSession, error) {
	if client == nil {
		return nil, errors.New("SSH client is nil")
	}
	if cleanup == nil {
		cleanup = func() { _ = client.Close() }
	}
	if cols < 20 || cols > 1000 {
		cols = 120
	}
	if rows < 5 || rows > 500 {
		rows = 36
	}
	sshSession, in, out, err := sshx.Shell(client, "xterm-256color", cols, rows)
	if err != nil {
		cleanup()
		return nil, err
	}
	now := time.Now()
	s := &LiveSession{
		ID:           randID(24),
		UserID:       userID,
		ServerID:     serverID,
		ServerName:   serverName,
		Host:         host,
		Username:     username,
		Port:         port,
		Transient:    transient,
		CreatedAt:    now,
		SSHSession:   sshSession,
		In:           in,
		Out:          out,
		cleanup:      cleanup,
		LastActivity: now,
		DetachedAt:   now,
		Retention:    a.sessionRetentionForUser(userID),
		Attached:     map[*sessionAttachment]struct{}{},
	}

	a.mu.Lock()
	a.live[s.ID] = s
	a.mu.Unlock()
	go a.pumpSessionOutput(s)
	return s, nil
}

func (a *App) pumpSessionOutput(s *LiveSession) {
	buf := make([]byte, 32*1024)
	for {
		n, err := s.Out.Read(buf)
		if n > 0 {
			a.publishSessionOutput(s, buf[:n])
		}
		if err != nil {
			a.terminateLiveSession(s.ID, "remote_closed")
			return
		}
	}
}

func (a *App) publishSessionOutput(s *LiveSession, data []byte) {
	chunk := append([]byte(nil), data...)
	var slow []*sessionAttachment
	now := time.Now()
	s.Mu.Lock()
	if s.Closed {
		s.Mu.Unlock()
		return
	}
	s.LastActivity = now
	s.Buffer = append(s.Buffer, chunk...)
	if over := len(s.Buffer) - a.cfg.SessionBufferSize; over > 0 {
		copy(s.Buffer, s.Buffer[over:])
		s.Buffer = s.Buffer[:len(s.Buffer)-over]
	}
	for att := range s.Attached {
		select {
		case att.send <- chunk:
		default:
			delete(s.Attached, att)
			slow = append(slow, att)
		}
	}
	if len(s.Attached) == 0 && s.DetachedAt.IsZero() {
		s.DetachedAt = now
	}
	s.Mu.Unlock()
	for _, att := range slow {
		att.close()
	}
	if len(slow) > 0 && s.Retention == 0 {
		a.terminateIfDetached(s)
	}
}

func (a *App) getLiveSession(id string) *LiveSession {
	a.mu.Lock()
	s := a.live[id]
	a.mu.Unlock()
	return s
}

func (a *App) sessionAllowed(r *http.Request, s *LiveSession) bool {
	return s != nil && (s.UserID == uid(r) || isAdmin(r))
}

func (a *App) attachSession(s *LiveSession, ws *websocket.Conn) (*sessionAttachment, error) {
	att := &sessionAttachment{ws: ws, send: make(chan []byte, 128), done: make(chan struct{})}
	s.Mu.Lock()
	if s.Closed {
		s.Mu.Unlock()
		return nil, errors.New("SSH session is closed")
	}
	// Register and queue the snapshot while holding the same lock used by the
	// output publisher. This guarantees snapshot -> queued live output ordering.
	if len(s.Buffer) > 0 {
		att.send <- append([]byte(nil), s.Buffer...)
	}
	s.Attached[att] = struct{}{}
	s.EverAttached = true
	s.DetachedAt = time.Time{}
	s.LastActivity = time.Now()
	s.Mu.Unlock()
	return att, nil
}

func (a *App) detachSession(s *LiveSession, att *sessionAttachment) {
	att.close()
	now := time.Now()
	s.Mu.Lock()
	delete(s.Attached, att)
	if len(s.Attached) == 0 && !s.Closed {
		s.DetachedAt = now
	}
	s.Mu.Unlock()
	if s.Retention == 0 {
		a.terminateIfDetached(s)
	}
}

func (a *App) terminateIfDetached(s *LiveSession) {
	s.Mu.Lock()
	detached := len(s.Attached) == 0 && !s.Closed
	s.Mu.Unlock()
	if detached {
		a.terminateLiveSession(s.ID, "detached")
	}
}

func (att *sessionAttachment) close() {
	att.closeWithReason("")
}

func (att *sessionAttachment) closeWithReason(reason string) {
	att.once.Do(func() {
		close(att.done)
		if reason != "" {
			_ = att.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, reason), time.Now().Add(750*time.Millisecond))
		}
		_ = att.ws.Close()
	})
}

func (a *App) attachmentWriter(att *sessionAttachment) {
	for {
		select {
		case <-att.done:
			return
		case data := <-att.send:
			if len(data) == 0 {
				continue
			}
			_ = att.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := att.ws.WriteMessage(websocket.BinaryMessage, data); err != nil {
				att.close()
				return
			}
		}
	}
}

func (a *App) terminateLiveSession(id, reason string) {
	a.mu.Lock()
	s := a.live[id]
	if s != nil {
		delete(a.live, id)
	}
	a.mu.Unlock()
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		s.Mu.Lock()
		s.Closed = true
		s.CloseReason = reason
		attachments := make([]*sessionAttachment, 0, len(s.Attached))
		for att := range s.Attached {
			attachments = append(attachments, att)
		}
		s.Attached = map[*sessionAttachment]struct{}{}
		s.Mu.Unlock()
		for _, att := range attachments {
			att.closeWithReason(reason)
		}
		if s.In != nil {
			_ = s.In.Close()
		}
		if s.SSHSession != nil {
			_ = s.SSHSession.Close()
		}
		if s.cleanup != nil {
			s.cleanup()
		}
	})
}

func (a *App) terminateUserLiveSessions(userID int64, reason string) {
	a.mu.Lock()
	ids := make([]string, 0)
	for id, s := range a.live {
		if s.UserID == userID {
			ids = append(ids, id)
		}
	}
	a.mu.Unlock()
	for _, id := range ids {
		a.terminateLiveSession(id, reason)
	}
}

func (a *App) terminateServerLiveSessions(serverID int64, reason string) {
	a.mu.Lock()
	ids := make([]string, 0)
	for id, s := range a.live {
		if s.ServerID == serverID {
			ids = append(ids, id)
		}
	}
	a.mu.Unlock()
	for _, id := range ids {
		a.terminateLiveSession(id, reason)
	}
}

func (a *App) runMaintenance(now time.Time) {
	_, _ = a.DB.Exec("DELETE FROM sessions WHERE expires_at < ?", now)
	_, _ = a.DB.Exec("DELETE FROM mfa_challenges WHERE expires_at < ?", now)
	_, _ = a.DB.Exec("DELETE FROM mfa_setups WHERE expires_at < ?", now)
	_, _ = a.DB.Exec("DELETE FROM oidc_states WHERE expires_at < ?", now)
	if a.cfg.AuditRetention > 0 {
		_, _ = a.DB.Exec("DELETE FROM audit_logs WHERE created_at < ?", now.Add(-a.cfg.AuditRetention))
	}
}

func (a *App) maintenanceJanitor() {
	a.runMaintenance(time.Now())
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-a.sessionStop:
			return
		case now := <-ticker.C:
			a.runMaintenance(now)
		}
	}
}

func (a *App) sessionJanitor() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.sessionStop:
			return
		case now := <-ticker.C:
			var expired []string
			a.mu.Lock()
			for id, s := range a.live {
				s.Mu.Lock()
				detached := !s.Closed && len(s.Attached) == 0 && !s.DetachedAt.IsZero()
				if detached && !s.EverAttached && now.Sub(s.CreatedAt) >= 30*time.Second {
					expired = append(expired, id)
				} else if detached && s.EverAttached && s.Retention > 0 && now.Sub(s.DetachedAt) >= s.Retention {
					expired = append(expired, id)
				}
				s.Mu.Unlock()
			}
			a.mu.Unlock()
			for _, id := range expired {
				a.terminateLiveSession(id, "retention_expired")
			}
		}
	}
}

func (a *App) Close() {
	a.sessionStopOnce.Do(func() { close(a.sessionStop) })
	a.stopAllTransfers()
	a.mu.Lock()
	ids := make([]string, 0, len(a.live))
	for id := range a.live {
		ids = append(ids, id)
	}
	a.mu.Unlock()
	for _, id := range ids {
		a.terminateLiveSession(id, "server_shutdown")
	}
}

func (a *App) sessions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		all := isAdmin(r) && r.URL.Query().Get("all") == "1"
		a.mu.Lock()
		list := make([]*LiveSession, 0, len(a.live))
		for _, s := range a.live {
			if all || s.UserID == uid(r) {
				list = append(list, s)
			}
		}
		a.mu.Unlock()
		out := make([]sessionInfo, 0, len(list))
		for _, s := range list {
			info := s.info()
			if all {
				_ = a.DB.QueryRow("SELECT name FROM users WHERE id=?", info.UserID).Scan(&info.UserName)
			} else {
				info.UserID = 0
			}
			out = append(out, info)
		}
		jsonOut(w, 200, out)
	case http.MethodPost:
		var in struct {
			ServerID int64 `json:"serverId"`
			Cols     int   `json:"cols"`
			Rows     int   `json:"rows"`
		}
		if decode(r, &in) != nil || in.ServerID <= 0 {
			jsonOut(w, 400, map[string]string{"error": "serverId required"})
			return
		}
		s, err := a.createLiveSession(uid(r), in.ServerID, in.Cols, in.Rows)
		if err != nil {
			var hk *hostKeyActionError
			if errors.As(err, &hk) {
				jsonOut(w, http.StatusConflict, hk)
				return
			}
			jsonOut(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		a.audit(uid(r), "ssh.session.create", fmt.Sprintf("session=%s server=%d", s.ID, s.ServerID))
		jsonOut(w, http.StatusCreated, s.info())
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *App) sessionByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
	id = strings.Trim(id, "/")
	if id == "" || strings.Contains(id, "/") {
		jsonOut(w, 400, map[string]string{"error": "invalid session id"})
		return
	}
	s := a.getLiveSession(id)
	if !a.sessionAllowed(r, s) {
		jsonOut(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		info := s.info()
		if !isAdmin(r) {
			info.UserID = 0
		}
		jsonOut(w, 200, info)
	case http.MethodDelete:
		a.terminateLiveSession(id, "closed_by_user")
		a.audit(uid(r), "ssh.session.close", fmt.Sprintf("session=%s server=%d", id, s.ServerID))
		jsonOut(w, 200, map[string]bool{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *App) wsSSH(w http.ResponseWriter, r *http.Request) {
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/ws/ssh/"), "/")
	if id == "" || strings.Contains(id, "/") {
		http.Error(w, "bad session", http.StatusBadRequest)
		return
	}
	s := a.getLiveSession(id)
	if s == nil || s.UserID != uid(r) {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	ws, err := a.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("websocket upgrade rejected: origin=%q host=%q effective_host=%q effective_proto=%q client=%q error=%q",
			strings.TrimSpace(r.Header.Get("Origin")), strings.TrimSpace(r.Host), a.effectiveHost(r), a.effectiveProto(r), a.clientIP(r), err.Error())
		return
	}
	ws.SetReadLimit(1 << 20)
	att, err := a.attachSession(s, ws)
	if err != nil {
		_ = ws.Close()
		return
	}
	go a.attachmentWriter(att)
	defer a.detachSession(s, att)

	for {
		mt, b, err := ws.ReadMessage()
		if err != nil {
			return
		}
		if mt == websocket.TextMessage {
			var m struct {
				Type string `json:"type"`
				Data string `json:"data"`
				Cols int    `json:"cols"`
				Rows int    `json:"rows"`
			}
			if json.Unmarshal(b, &m) != nil {
				continue
			}
			s.ioMu.Lock()
			switch m.Type {
			case "resize":
				if m.Cols >= 20 && m.Cols <= 1000 && m.Rows >= 5 && m.Rows <= 500 {
					_ = s.SSHSession.WindowChange(m.Rows, m.Cols)
				}
			case "input":
				_, _ = s.In.Write([]byte(m.Data))
			}
			s.ioMu.Unlock()
		} else if mt == websocket.BinaryMessage {
			s.ioMu.Lock()
			_, _ = s.In.Write(b)
			s.ioMu.Unlock()
		}
		s.Mu.Lock()
		s.LastActivity = time.Now()
		s.Mu.Unlock()
	}
}

func (a *App) terminateUserWorkspaceSessions(userID, workspaceID int64, reason string) {
	if userID <= 0 || workspaceID <= 0 {
		return
	}
	type liveRef struct {
		id       string
		userID   int64
		serverID int64
	}
	a.mu.Lock()
	refs := make([]liveRef, 0, len(a.live))
	for id, s := range a.live {
		refs = append(refs, liveRef{id: id, userID: s.UserID, serverID: s.ServerID})
	}
	a.mu.Unlock()
	ids := make([]string, 0)
	for _, ref := range refs {
		if ref.userID != userID || ref.serverID <= 0 {
			continue
		}
		var wid sql.NullInt64
		if err := a.DB.QueryRow(`SELECT workspace_id FROM servers WHERE id=?`, ref.serverID).Scan(&wid); err == nil && wid.Valid && wid.Int64 == workspaceID {
			ids = append(ids, ref.id)
		}
	}
	for _, id := range ids {
		a.terminateLiveSession(id, reason)
	}
}

func (a *App) terminateWorkspaceSessions(workspaceID int64, reason string) {
	if workspaceID <= 0 {
		return
	}
	type liveRef struct {
		id       string
		serverID int64
	}
	a.mu.Lock()
	refs := make([]liveRef, 0, len(a.live))
	for id, s := range a.live {
		refs = append(refs, liveRef{id: id, serverID: s.ServerID})
	}
	a.mu.Unlock()
	ids := make([]string, 0)
	for _, ref := range refs {
		if ref.serverID <= 0 {
			continue
		}
		var wid sql.NullInt64
		if err := a.DB.QueryRow(`SELECT workspace_id FROM servers WHERE id=?`, ref.serverID).Scan(&wid); err == nil && wid.Valid && wid.Int64 == workspaceID {
			ids = append(ids, ref.id)
		}
	}
	for _, id := range ids {
		a.terminateLiveSession(id, reason)
	}
}

func (a *App) terminateTemplateSessions(templateID int64, reason string) {
	if templateID <= 0 {
		return
	}
	type liveRef struct {
		id       string
		serverID int64
	}
	a.mu.Lock()
	refs := make([]liveRef, 0, len(a.live))
	for id, s := range a.live {
		refs = append(refs, liveRef{id: id, serverID: s.ServerID})
	}
	a.mu.Unlock()
	ids := make([]string, 0)
	for _, ref := range refs {
		if ref.serverID <= 0 {
			continue
		}
		var tid sql.NullInt64
		if err := a.DB.QueryRow(`SELECT template_id FROM servers WHERE id=?`, ref.serverID).Scan(&tid); err == nil && tid.Valid && tid.Int64 == templateID {
			ids = append(ids, ref.id)
		}
	}
	for _, id := range ids {
		a.terminateLiveSession(id, reason)
	}
}
