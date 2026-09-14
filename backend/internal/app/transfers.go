package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"zentssh.local/backend/internal/sshx"
)

type activeTransfer struct {
	ID             string
	UserID         int64
	SourceServerID int64
	TargetServerID int64
	cancel         context.CancelFunc
	mu             sync.Mutex
	close          []io.Closer
	once           sync.Once
}

func (t *activeTransfer) stop() {
	t.once.Do(func() {
		if t.cancel != nil {
			t.cancel()
		}
		t.mu.Lock()
		closers := append([]io.Closer(nil), t.close...)
		t.mu.Unlock()
		for _, c := range closers {
			if c != nil {
				_ = c.Close()
			}
		}
	})
}

func (t *activeTransfer) addCloser(c io.Closer) {
	if c == nil {
		return
	}
	t.mu.Lock()
	t.close = append(t.close, c)
	t.mu.Unlock()
}

type transferRecord struct {
	ID             string     `json:"id"`
	UserID         int64      `json:"userId,omitempty"`
	UserName       string     `json:"userName,omitempty"`
	SourceServerID int64      `json:"sourceServerId"`
	SourceServer   string     `json:"sourceServer"`
	SourcePath     string     `json:"sourcePath"`
	TargetServerID int64      `json:"targetServerId"`
	TargetServer   string     `json:"targetServer"`
	TargetPath     string     `json:"targetPath"`
	Status         string     `json:"status"`
	BytesTotal     int64      `json:"bytesTotal"`
	BytesDone      int64      `json:"bytesDone"`
	SpeedBPS       int64      `json:"speedBps"`
	ETASeconds     int64      `json:"etaSeconds"`
	Error          string     `json:"error,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
	StartedAt      *time.Time `json:"startedAt,omitempty"`
	FinishedAt     *time.Time `json:"finishedAt,omitempty"`
}

func (a *App) initTransferHistory() {
	_, _ = a.DB.Exec(`UPDATE transfers SET status='interrupted',error='interrupted by ZentSSH restart',finished_at=CURRENT_TIMESTAMP WHERE status IN ('queued','running')`)
	_, _ = a.DB.Exec(`DELETE FROM transfers WHERE status IN ('completed','failed','cancelled','interrupted') AND finished_at IS NOT NULL AND finished_at < datetime('now','-30 days')`)
}

func (a *App) reserveTransfer(id string, userID, sourceServerID, targetServerID int64) (*activeTransfer, context.Context, error) {
	a.transferMu.Lock()
	defer a.transferMu.Unlock()
	if len(a.activeTransfers) >= a.cfg.MaxTotalTransfers {
		return nil, nil, fmt.Errorf("global transfer limit reached (%d)", a.cfg.MaxTotalTransfers)
	}
	perUser := 0
	for _, t := range a.activeTransfers {
		if t.UserID == userID {
			perUser++
		}
	}
	if perUser >= a.cfg.MaxTransfersPerUser {
		return nil, nil, fmt.Errorf("transfer limit for user reached (%d)", a.cfg.MaxTransfersPerUser)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t := &activeTransfer{ID: id, UserID: userID, SourceServerID: sourceServerID, TargetServerID: targetServerID, cancel: cancel}
	a.activeTransfers[id] = t
	return t, ctx, nil
}

func (a *App) releaseTransfer(id string) {
	a.transferMu.Lock()
	delete(a.activeTransfers, id)
	a.transferMu.Unlock()
}

func (a *App) transferByRuntimeID(id string) *activeTransfer {
	a.transferMu.Lock()
	t := a.activeTransfers[id]
	a.transferMu.Unlock()
	return t
}

func (a *App) stopAllTransfers() {
	a.transferMu.Lock()
	all := make([]*activeTransfer, 0, len(a.activeTransfers))
	for _, t := range a.activeTransfers {
		all = append(all, t)
	}
	a.transferMu.Unlock()
	for _, t := range all {
		t.stop()
	}
}

func (a *App) terminateUserTransfers(userID int64) {
	a.transferMu.Lock()
	list := make([]*activeTransfer, 0)
	for _, t := range a.activeTransfers {
		if t.UserID == userID {
			list = append(list, t)
		}
	}
	a.transferMu.Unlock()
	for _, t := range list {
		t.stop()
	}
}

func (a *App) terminateServerTransfers(serverID int64) {
	a.transferMu.Lock()
	list := make([]*activeTransfer, 0)
	for _, t := range a.activeTransfers {
		if t.SourceServerID == serverID || t.TargetServerID == serverID {
			list = append(list, t)
		}
	}
	a.transferMu.Unlock()
	for _, t := range list {
		t.stop()
	}
}

func (a *App) transfers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		all := isAdmin(r) && r.URL.Query().Get("all") == "1"
		query := `SELECT t.id,t.user_id,u.name,t.source_server_id,ss.name,t.source_path,t.target_server_id,ts.name,t.target_path,t.status,t.bytes_total,t.bytes_done,t.error,t.created_at,t.started_at,t.finished_at
			FROM transfers t JOIN users u ON u.id=t.user_id JOIN servers ss ON ss.id=t.source_server_id JOIN servers ts ON ts.id=t.target_server_id`
		args := []any{}
		if !all {
			query += " WHERE t.user_id=?"
			args = append(args, uid(r))
		}
		query += " ORDER BY t.created_at DESC LIMIT 300"
		rows, err := a.DB.Query(query, args...)
		if err != nil {
			a.internalError(w, "transfers", err)
			return
		}
		defer rows.Close()
		out := []transferRecord{}
		for rows.Next() {
			var tr transferRecord
			var started, finished sql.NullTime
			if err := rows.Scan(&tr.ID, &tr.UserID, &tr.UserName, &tr.SourceServerID, &tr.SourceServer, &tr.SourcePath, &tr.TargetServerID, &tr.TargetServer, &tr.TargetPath, &tr.Status, &tr.BytesTotal, &tr.BytesDone, &tr.Error, &tr.CreatedAt, &started, &finished); err != nil {
				a.internalError(w, "transfers", err)
				return
			}
			if started.Valid {
				tr.StartedAt = &started.Time
			}
			if finished.Valid {
				tr.FinishedAt = &finished.Time
			}
			a.transferRates(&tr)
			if !all {
				tr.UserID = 0
				tr.UserName = ""
			}
			out = append(out, tr)
		}
		jsonOut(w, 200, out)
	case http.MethodPost:
		var in struct {
			SourceServerID int64  `json:"sourceServerId"`
			SourcePath     string `json:"sourcePath"`
			TargetServerID int64  `json:"targetServerId"`
			TargetPath     string `json:"targetPath"`
		}
		if decode(r, &in) != nil || in.SourceServerID <= 0 || in.TargetServerID <= 0 || strings.TrimSpace(in.SourcePath) == "" || strings.TrimSpace(in.TargetPath) == "" {
			jsonOut(w, 400, map[string]string{"error": "source/target server and path are required"})
			return
		}
		tr, err := a.startTransfer(uid(r), in.SourceServerID, in.SourcePath, in.TargetServerID, in.TargetPath)
		if err != nil {
			var hk *hostKeyActionError
			if errors.As(err, &hk) {
				jsonOut(w, http.StatusConflict, hk)
				return
			}
			jsonOut(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		jsonOut(w, http.StatusCreated, tr)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *App) transferByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/transfers/"), "/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || parts[0] == "" {
		jsonOut(w, 400, map[string]string{"error": "invalid transfer id"})
		return
	}
	id := parts[0]
	tr, err := a.loadTransfer(id)
	if err != nil {
		jsonOut(w, 404, map[string]string{"error": "transfer not found"})
		return
	}
	if tr.UserID != uid(r) && !isAdmin(r) {
		jsonOut(w, 404, map[string]string{"error": "transfer not found"})
		return
	}
	if len(parts) == 2 && parts[1] == "retry" {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if tr.Status == "queued" || tr.Status == "running" {
			jsonOut(w, 409, map[string]string{"error": "transfer is still active"})
			return
		}
		copy, err := a.startTransfer(uid(r), tr.SourceServerID, tr.SourcePath, tr.TargetServerID, tr.TargetPath)
		if err != nil {
			var hk *hostKeyActionError
			if errors.As(err, &hk) {
				jsonOut(w, http.StatusConflict, hk)
				return
			}
			jsonOut(w, 502, map[string]string{"error": err.Error()})
			return
		}
		a.audit(uid(r), "transfer.retry", fmt.Sprintf("old=%s new=%s", tr.ID, copy.ID))
		jsonOut(w, 201, copy)
		return
	}
	if len(parts) != 1 {
		jsonOut(w, 404, map[string]string{"error": "not found"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.transferRates(&tr)
		if !isAdmin(r) {
			tr.UserID = 0
			tr.UserName = ""
		}
		jsonOut(w, 200, tr)
	case http.MethodDelete:
		active := a.transferByRuntimeID(id)
		if active == nil {
			jsonOut(w, 409, map[string]string{"error": "transfer is not active"})
			return
		}
		active.stop()
		jsonOut(w, 200, map[string]bool{"ok": true})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *App) loadTransfer(id string) (transferRecord, error) {
	var tr transferRecord
	var started, finished sql.NullTime
	err := a.DB.QueryRow(`SELECT t.id,t.user_id,u.name,t.source_server_id,ss.name,t.source_path,t.target_server_id,ts.name,t.target_path,t.status,t.bytes_total,t.bytes_done,t.error,t.created_at,t.started_at,t.finished_at
		FROM transfers t JOIN users u ON u.id=t.user_id JOIN servers ss ON ss.id=t.source_server_id JOIN servers ts ON ts.id=t.target_server_id WHERE t.id=?`, id).
		Scan(&tr.ID, &tr.UserID, &tr.UserName, &tr.SourceServerID, &tr.SourceServer, &tr.SourcePath, &tr.TargetServerID, &tr.TargetServer, &tr.TargetPath, &tr.Status, &tr.BytesTotal, &tr.BytesDone, &tr.Error, &tr.CreatedAt, &started, &finished)
	if started.Valid {
		tr.StartedAt = &started.Time
	}
	if finished.Valid {
		tr.FinishedAt = &finished.Time
	}
	return tr, err
}

func (a *App) transferRates(tr *transferRecord) {
	if tr.StartedAt == nil || tr.BytesDone <= 0 {
		return
	}
	elapsed := time.Since(*tr.StartedAt).Seconds()
	if elapsed <= 0 {
		return
	}
	tr.SpeedBPS = int64(float64(tr.BytesDone) / elapsed)
	if tr.SpeedBPS > 0 && tr.BytesTotal > tr.BytesDone {
		tr.ETASeconds = (tr.BytesTotal - tr.BytesDone) / tr.SpeedBPS
	}
}

func (a *App) startTransfer(userID, sourceServerID int64, sourcePath string, targetServerID int64, targetPath string) (transferRecord, error) {
	if _, _, err := a.loadServerForUser(userID, sourceServerID); err != nil {
		return transferRecord{}, errors.New("source server not found")
	}
	if _, _, err := a.loadServerForUser(userID, targetServerID); err != nil {
		return transferRecord{}, errors.New("target server not found")
	}
	id := randID(18)
	active, ctx, err := a.reserveTransfer(id, userID, sourceServerID, targetServerID)
	if err != nil {
		return transferRecord{}, err
	}
	fail := func(err error) (transferRecord, error) {
		active.stop()
		a.releaseTransfer(id)
		return transferRecord{}, err
	}

	sourceClient, sourceCleanup, err := a.openSSHClient(sourceServerID)
	if err != nil {
		return fail(err)
	}
	active.addCloser(sourceClient)
	sourceSFTP, err := sshx.SFTP(sourceClient)
	if err != nil {
		sourceCleanup()
		return fail(err)
	}
	active.addCloser(sourceSFTP)

	targetClient, targetCleanup, err := a.openSSHClient(targetServerID)
	if err != nil {
		sourceCleanup()
		return fail(err)
	}
	active.addCloser(targetClient)
	targetSFTP, err := sshx.SFTP(targetClient)
	if err != nil {
		sourceCleanup()
		targetCleanup()
		return fail(err)
	}
	active.addCloser(targetSFTP)

	src := path.Clean(sourcePath)
	dst := path.Clean(targetPath)
	info, err := sourceSFTP.Lstat(src)
	if err != nil {
		sourceCleanup()
		targetCleanup()
		return fail(fmt.Errorf("source: %w", err))
	}
	if info.Mode()&os.ModeSymlink != 0 {
		sourceCleanup()
		targetCleanup()
		return fail(errors.New("symbolic-link transfers are not supported"))
	}
	if sourceServerID == targetServerID {
		if src == dst {
			sourceCleanup()
			targetCleanup()
			return fail(errors.New("source and target are identical"))
		}
		if info.IsDir() && strings.HasPrefix(dst+"/", strings.TrimSuffix(src, "/")+"/") {
			sourceCleanup()
			targetCleanup()
			return fail(errors.New("target cannot be inside the source directory on the same server"))
		}
	}

	_, err = a.DB.Exec(`INSERT INTO transfers(id,user_id,source_server_id,source_path,target_server_id,target_path,status,created_at) VALUES(?,?,?,?,?,?,'queued',CURRENT_TIMESTAMP)`, id, userID, sourceServerID, src, targetServerID, dst)
	if err != nil {
		sourceCleanup()
		targetCleanup()
		return fail(err)
	}
	tr, _ := a.loadTransfer(id)
	a.audit(userID, "transfer.create", fmt.Sprintf("transfer=%s source=%d:%s target=%d:%s", id, sourceServerID, src, targetServerID, dst))
	go a.runTransfer(ctx, active, sourceSFTP, targetSFTP, sourceCleanup, targetCleanup, src, dst, info)
	return tr, nil
}

func (a *App) runTransfer(ctx context.Context, active *activeTransfer, source, target *sftp.Client, sourceCleanup, targetCleanup func(), src, dst string, root os.FileInfo) {
	defer a.releaseTransfer(active.ID)
	defer active.stop()
	defer sourceCleanup()
	defer targetCleanup()

	started := time.Now()
	_, _ = a.DB.Exec("UPDATE transfers SET status='running',started_at=?,error='' WHERE id=?", started, active.ID)
	total, err := countRemoteTree(ctx, source, src, root)
	if err != nil {
		a.finishTransfer(active.ID, ctx, err)
		return
	}
	_, _ = a.DB.Exec("UPDATE transfers SET bytes_total=? WHERE id=?", total, active.ID)

	progress := &transferProgress{app: a, id: active.ID, total: total, lastPersist: time.Now()}
	err = copyRemoteTree(ctx, source, target, src, dst, root, progress)
	if err == nil {
		progress.persist(true)
		_, _ = a.DB.Exec("UPDATE transfers SET status='completed',bytes_done=?,bytes_total=?,error='',finished_at=CURRENT_TIMESTAMP WHERE id=?", progress.done, total, active.ID)
		a.audit(active.UserID, "transfer.complete", fmt.Sprintf("transfer=%s bytes=%d", active.ID, progress.done))
		return
	}
	progress.persist(true)
	a.finishTransfer(active.ID, ctx, err)
}

func (a *App) finishTransfer(id string, ctx context.Context, err error) {
	status := "failed"
	message := ""
	if err != nil {
		message = err.Error()
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		status = "cancelled"
		message = "cancelled by user"
	}
	_, _ = a.DB.Exec("UPDATE transfers SET status=?,error=?,finished_at=CURRENT_TIMESTAMP WHERE id=?", status, message, id)
}

type transferProgress struct {
	app         *App
	id          string
	total       int64
	done        int64
	lastPersist time.Time
}

func (p *transferProgress) add(n int) {
	p.done += int64(n)
	p.persist(false)
}

func (p *transferProgress) persist(force bool) {
	if !force && time.Since(p.lastPersist) < 500*time.Millisecond {
		return
	}
	_, _ = p.app.DB.Exec("UPDATE transfers SET bytes_done=?,bytes_total=? WHERE id=?", p.done, p.total, p.id)
	p.lastPersist = time.Now()
}

func countRemoteTree(ctx context.Context, source *sftp.Client, src string, info os.FileInfo) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return 0, fmt.Errorf("symbolic link is not supported: %s", src)
	}
	if !info.IsDir() {
		return info.Size(), nil
	}
	entries, err := source.ReadDir(src)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, entry := range entries {
		child := path.Join(src, entry.Name())
		n, err := countRemoteTree(ctx, source, child, entry)
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}

func copyRemoteTree(ctx context.Context, source, target *sftp.Client, src, dst string, info os.FileInfo, progress *transferProgress) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symbolic link is not supported: %s", src)
	}
	if info.IsDir() {
		if err := target.MkdirAll(dst); err != nil {
			return err
		}
		entries, err := source.ReadDir(src)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := copyRemoteTree(ctx, source, target, path.Join(src, entry.Name()), path.Join(dst, entry.Name()), entry, progress); err != nil {
				return err
			}
		}
		return nil
	}
	if err := target.MkdirAll(path.Dir(dst)); err != nil {
		return err
	}
	in, err := source.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := target.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC)
	if err != nil {
		return err
	}
	defer out.Close()
	buf := make([]byte, 256*1024)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := in.Read(buf)
		if n > 0 {
			written := 0
			for written < n {
				if err := ctx.Err(); err != nil {
					return err
				}
				m, writeErr := out.Write(buf[written:n])
				if m > 0 {
					written += m
					progress.add(m)
				}
				if writeErr != nil {
					return writeErr
				}
				if m == 0 {
					return io.ErrShortWrite
				}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return readErr
		}
	}
	_ = target.Chmod(dst, info.Mode().Perm())
	return nil
}

func (a *App) activeTransferSnapshot() []*activeTransfer {
	a.transferMu.Lock()
	list := make([]*activeTransfer, 0, len(a.activeTransfers))
	for _, t := range a.activeTransfers {
		list = append(list, t)
	}
	a.transferMu.Unlock()
	return list
}

func (a *App) terminateUserWorkspaceTransfers(userID, workspaceID int64) {
	if userID <= 0 || workspaceID <= 0 {
		return
	}
	for _, t := range a.activeTransferSnapshot() {
		if t.UserID != userID {
			continue
		}
		if a.serverBelongsToWorkspace(t.SourceServerID, workspaceID) || a.serverBelongsToWorkspace(t.TargetServerID, workspaceID) {
			t.stop()
		}
	}
}

func (a *App) terminateWorkspaceTransfers(workspaceID int64) {
	if workspaceID <= 0 {
		return
	}
	for _, t := range a.activeTransferSnapshot() {
		if a.serverBelongsToWorkspace(t.SourceServerID, workspaceID) || a.serverBelongsToWorkspace(t.TargetServerID, workspaceID) {
			t.stop()
		}
	}
}

func (a *App) terminateTemplateTransfers(templateID int64) {
	if templateID <= 0 {
		return
	}
	for _, t := range a.activeTransferSnapshot() {
		if a.serverUsesTemplate(t.SourceServerID, templateID) || a.serverUsesTemplate(t.TargetServerID, templateID) {
			t.stop()
		}
	}
}

func (a *App) serverBelongsToWorkspace(serverID, workspaceID int64) bool {
	if serverID <= 0 || workspaceID <= 0 {
		return false
	}
	var wid sql.NullInt64
	return a.DB.QueryRow(`SELECT workspace_id FROM servers WHERE id=?`, serverID).Scan(&wid) == nil && wid.Valid && wid.Int64 == workspaceID
}

func (a *App) serverUsesTemplate(serverID, templateID int64) bool {
	if serverID <= 0 || templateID <= 0 {
		return false
	}
	var tid sql.NullInt64
	return a.DB.QueryRow(`SELECT template_id FROM servers WHERE id=?`, serverID).Scan(&tid) == nil && tid.Valid && tid.Int64 == templateID
}
