package app

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	zdb "zentssh.local/backend/internal/db"
)

const (
	backupFormatVersion        = 1
	backupChunkSize            = 1 << 20
	backupArgonTime     uint32 = 3
	backupArgonMemory   uint32 = 64 * 1024
	backupArgonThreads  uint8  = 2
	maxBackupHeader            = 64 << 10
	maxRestoreUpload    int64  = 4 << 30
	maxRestoreDatabase  int64  = 4 << 30
)

var backupMagic = []byte("ZENTSSH-BACKUP-V1\n")

type backupCryptoHeader struct {
	Format       string `json:"format"`
	Version      int    `json:"version"`
	KDF          string `json:"kdf"`
	Salt         string `json:"salt"`
	ArgonTime    uint32 `json:"argonTime"`
	ArgonMemory  uint32 `json:"argonMemoryKiB"`
	ArgonThreads uint8  `json:"argonThreads"`
	Cipher       string `json:"cipher"`
	NoncePrefix  string `json:"noncePrefix"`
	ChunkSize    int    `json:"chunkSize"`
}

type backupManifest struct {
	Format          string    `json:"format"`
	FormatVersion   int       `json:"formatVersion"`
	ZentSSHVersion  string    `json:"zentsshVersion"`
	CreatedAt       time.Time `json:"createdAt"`
	DatabaseSize    int64     `json:"databaseSize"`
	DatabaseSHA256  string    `json:"databaseSha256"`
	MasterKeySHA256 string    `json:"masterKeySha256"`
}

type backupState struct {
	LastBackupAt  *time.Time `json:"lastBackupAt,omitempty"`
	LastRestoreAt *time.Time `json:"lastRestoreAt,omitempty"`
}

type backupStatusResponse struct {
	DatabaseBytes       int64      `json:"databaseBytes"`
	WALBytes            int64      `json:"walBytes"`
	SHMBytes            int64      `json:"shmBytes"`
	StorageBytes        int64      `json:"storageBytes"`
	LastBackupAt        *time.Time `json:"lastBackupAt,omitempty"`
	LastRestoreAt       *time.Time `json:"lastRestoreAt,omitempty"`
	MasterKeySource     string     `json:"masterKeySource"`
	BackupFormatVersion int        `json:"backupFormatVersion"`
}

type encryptedBackupWriter struct {
	dst        io.Writer
	gcm        cipher.AEAD
	headerHash [32]byte
	nonceBase  [8]byte
	counter    uint32
	buf        []byte
	closed     bool
}

type encryptedBackupReader struct {
	src        io.Reader
	gcm        cipher.AEAD
	headerHash [32]byte
	nonceBase  [8]byte
	counter    uint32
	plain      []byte
	done       bool
}

func backupPasswordOK(password string) bool {
	return utf8.RuneCountInString(password) >= 10 && len(password) <= 1024
}

func deriveBackupKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, backupArgonTime, backupArgonMemory, backupArgonThreads, 32)
}

func newEncryptedBackupWriter(dst io.Writer, password string) (*encryptedBackupWriter, error) {
	if !backupPasswordOK(password) {
		return nil, errors.New("backup password must contain at least 10 characters")
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	var nonceBase [8]byte
	if _, err := io.ReadFull(rand.Reader, nonceBase[:]); err != nil {
		return nil, err
	}
	header := backupCryptoHeader{
		Format: "zentssh-backup", Version: backupFormatVersion, KDF: "argon2id",
		Salt: base64.RawStdEncoding.EncodeToString(salt), ArgonTime: backupArgonTime,
		ArgonMemory: backupArgonMemory, ArgonThreads: backupArgonThreads,
		Cipher: "aes-256-gcm-chunked", NoncePrefix: base64.RawStdEncoding.EncodeToString(nonceBase[:]),
		ChunkSize: backupChunkSize,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	if len(headerJSON) > maxBackupHeader {
		return nil, errors.New("backup header is too large")
	}
	key := deriveBackupKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if _, err = dst.Write(backupMagic); err != nil {
		return nil, err
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(headerJSON)))
	if _, err = dst.Write(size[:]); err != nil {
		return nil, err
	}
	if _, err = dst.Write(headerJSON); err != nil {
		return nil, err
	}
	return &encryptedBackupWriter{
		dst: dst, gcm: gcm, headerHash: sha256.Sum256(headerJSON), nonceBase: nonceBase,
		buf: make([]byte, 0, backupChunkSize),
	}, nil
}

func (w *encryptedBackupWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("backup writer is closed")
	}
	total := len(p)
	for len(p) > 0 {
		n := backupChunkSize - len(w.buf)
		if n > len(p) {
			n = len(p)
		}
		w.buf = append(w.buf, p[:n]...)
		p = p[n:]
		if len(w.buf) == backupChunkSize {
			if err := w.flush(); err != nil {
				return total - len(p), err
			}
		}
	}
	return total, nil
}

func backupNonce(base [8]byte, counter uint32) []byte {
	nonce := make([]byte, 12)
	copy(nonce, base[:])
	binary.BigEndian.PutUint32(nonce[8:], counter)
	return nonce
}

func backupAAD(headerHash [32]byte, counter uint32) []byte {
	aad := make([]byte, 36)
	copy(aad, headerHash[:])
	binary.BigEndian.PutUint32(aad[32:], counter)
	return aad
}

func (w *encryptedBackupWriter) flush() error {
	if len(w.buf) == 0 {
		return nil
	}
	if w.counter == ^uint32(0) {
		return errors.New("backup is too large")
	}
	sealed := w.gcm.Seal(nil, backupNonce(w.nonceBase, w.counter), w.buf, backupAAD(w.headerHash, w.counter))
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(sealed)))
	if _, err := w.dst.Write(size[:]); err != nil {
		return err
	}
	if _, err := w.dst.Write(sealed); err != nil {
		return err
	}
	w.counter++
	w.buf = w.buf[:0]
	return nil
}

func (w *encryptedBackupWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	if err := w.flush(); err != nil {
		return err
	}
	var end [4]byte
	_, err := w.dst.Write(end[:])
	return err
}

func newEncryptedBackupReader(src io.Reader, password string) (*encryptedBackupReader, error) {
	if !backupPasswordOK(password) {
		return nil, errors.New("invalid backup password or damaged backup")
	}
	magic := make([]byte, len(backupMagic))
	if _, err := io.ReadFull(src, magic); err != nil || !bytes.Equal(magic, backupMagic) {
		return nil, errors.New("invalid ZentSSH backup format")
	}
	var size [4]byte
	if _, err := io.ReadFull(src, size[:]); err != nil {
		return nil, errors.New("invalid ZentSSH backup header")
	}
	headerSize := binary.BigEndian.Uint32(size[:])
	if headerSize == 0 || headerSize > maxBackupHeader {
		return nil, errors.New("invalid ZentSSH backup header")
	}
	headerJSON := make([]byte, headerSize)
	if _, err := io.ReadFull(src, headerJSON); err != nil {
		return nil, errors.New("invalid ZentSSH backup header")
	}
	var header backupCryptoHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, errors.New("invalid ZentSSH backup header")
	}
	if header.Format != "zentssh-backup" || header.Version != backupFormatVersion || header.KDF != "argon2id" ||
		header.ArgonTime != backupArgonTime || header.ArgonMemory != backupArgonMemory || header.ArgonThreads != backupArgonThreads ||
		header.Cipher != "aes-256-gcm-chunked" || header.ChunkSize != backupChunkSize {
		return nil, errors.New("unsupported ZentSSH backup format")
	}
	salt, err := base64.RawStdEncoding.DecodeString(header.Salt)
	if err != nil || len(salt) != 16 {
		return nil, errors.New("invalid ZentSSH backup header")
	}
	noncePrefix, err := base64.RawStdEncoding.DecodeString(header.NoncePrefix)
	if err != nil || len(noncePrefix) != 8 {
		return nil, errors.New("invalid ZentSSH backup header")
	}
	var nonceBase [8]byte
	copy(nonceBase[:], noncePrefix)
	block, err := aes.NewCipher(deriveBackupKey(password, salt))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &encryptedBackupReader{src: src, gcm: gcm, headerHash: sha256.Sum256(headerJSON), nonceBase: nonceBase}, nil
}

func (r *encryptedBackupReader) Read(p []byte) (int, error) {
	for len(r.plain) == 0 && !r.done {
		var size [4]byte
		if _, err := io.ReadFull(r.src, size[:]); err != nil {
			return 0, errors.New("truncated ZentSSH backup")
		}
		cipherSize := binary.BigEndian.Uint32(size[:])
		if cipherSize == 0 {
			r.done = true
			break
		}
		if cipherSize > backupChunkSize+uint32(r.gcm.Overhead()) {
			return 0, errors.New("invalid ZentSSH backup chunk")
		}
		sealed := make([]byte, cipherSize)
		if _, err := io.ReadFull(r.src, sealed); err != nil {
			return 0, errors.New("truncated ZentSSH backup")
		}
		plain, err := r.gcm.Open(nil, backupNonce(r.nonceBase, r.counter), sealed, backupAAD(r.headerHash, r.counter))
		if err != nil {
			return 0, errors.New("invalid backup password or damaged backup")
		}
		r.counter++
		r.plain = plain
	}
	if len(r.plain) == 0 && r.done {
		return 0, io.EOF
	}
	n := copy(p, r.plain)
	r.plain = r.plain[n:]
	return n, nil
}

func sha256File(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func fileSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		return 0
	}
	return st.Size()
}

func (a *App) backupStatePath() string {
	return filepath.Join(a.dataDir, ".zentssh-backup-state.json")
}

func (a *App) loadBackupState() backupState {
	var state backupState
	if a.dataDir == "" {
		return state
	}
	b, err := os.ReadFile(a.backupStatePath())
	if err == nil {
		_ = json.Unmarshal(b, &state)
	}
	return state
}

func (a *App) saveBackupState(state backupState) error {
	b, err := json.Marshal(state)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(a.dataDir, ".backup-state-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(append(b, '\n'))
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, a.backupStatePath())
}

func (a *App) backupRuntimeReady() bool {
	return strings.TrimSpace(a.dataDir) != "" && len(a.masterKey) == 32
}

func (a *App) adminBackupStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !a.backupRuntimeReady() {
		jsonOut(w, http.StatusServiceUnavailable, map[string]string{"error": "backup/restore is not initialized"})
		return
	}
	dbPath := filepath.Join(a.dataDir, "zentssh.db")
	dbBytes := fileSize(dbPath)
	walBytes := fileSize(dbPath + "-wal")
	shmBytes := fileSize(dbPath + "-shm")
	state := a.loadBackupState()
	source := "persistent"
	if a.externalMasterKey {
		source = "environment"
	}
	jsonOut(w, http.StatusOK, backupStatusResponse{
		DatabaseBytes: dbBytes, WALBytes: walBytes, SHMBytes: shmBytes,
		StorageBytes: dbBytes + walBytes + shmBytes, LastBackupAt: state.LastBackupAt,
		LastRestoreAt: state.LastRestoreAt, MasterKeySource: source, BackupFormatVersion: backupFormatVersion,
	})
}

func (a *App) createDatabaseSnapshot() (string, error) {
	f, err := os.CreateTemp(a.dataDir, ".zentssh-snapshot-*.db")
	if err != nil {
		return "", err
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	if err := os.Remove(name); err != nil {
		return "", err
	}
	if _, err := a.DB.Exec(`VACUUM INTO ?`, name); err != nil {
		os.Remove(name)
		return "", fmt.Errorf("create consistent SQLite snapshot: %w", err)
	}
	if err := os.Chmod(name, 0600); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

func writeTarBytes(tw *tar.Writer, name string, data []byte, mode int64, modTime time.Time) error {
	h := &tar.Header{Name: name, Mode: mode, Size: int64(len(data)), ModTime: modTime, Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(h); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func writeTarFile(tw *tar.Writer, name, path string, size, mode int64, modTime time.Time) error {
	h := &tar.Header{Name: name, Mode: mode, Size: size, ModTime: modTime, Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(h); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := io.Copy(tw, f)
	if err == nil && n != size {
		err = io.ErrUnexpectedEOF
	}
	return err
}

func (a *App) createEncryptedBackup(path, password string) (backupManifest, error) {
	var manifest backupManifest
	snapshotPath, err := a.createDatabaseSnapshot()
	if err != nil {
		return manifest, err
	}
	defer os.Remove(snapshotPath)
	dbHash, dbSize, err := sha256File(snapshotPath)
	if err != nil {
		return manifest, err
	}
	keyHash := sha256.Sum256(a.masterKey)
	createdAt := time.Now().UTC()
	manifest = backupManifest{
		Format: "zentssh-backup", FormatVersion: backupFormatVersion, ZentSSHVersion: Version,
		CreatedAt: createdAt, DatabaseSize: dbSize, DatabaseSHA256: dbHash,
		MasterKeySHA256: hex.EncodeToString(keyHash[:]),
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return manifest, err
	}
	keyFile := []byte(base64.RawStdEncoding.EncodeToString(a.masterKey) + "\n")
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return manifest, err
	}
	failed := true
	defer func() {
		_ = out.Close()
		if failed {
			_ = os.Remove(path)
		}
	}()
	enc, err := newEncryptedBackupWriter(out, password)
	if err != nil {
		return manifest, err
	}
	gz := gzip.NewWriter(enc)
	tw := tar.NewWriter(gz)
	if err = writeTarBytes(tw, "manifest.json", manifestJSON, 0600, createdAt); err == nil {
		err = writeTarFile(tw, "zentssh.db", snapshotPath, dbSize, 0600, createdAt)
	}
	if err == nil {
		err = writeTarBytes(tw, "master.key", keyFile, 0600, createdAt)
	}
	if closeErr := tw.Close(); err == nil {
		err = closeErr
	}
	if closeErr := gz.Close(); err == nil {
		err = closeErr
	}
	if closeErr := enc.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = out.Sync()
	}
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return manifest, err
	}
	failed = false
	return manifest, nil
}

func (a *App) adminBackupExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !a.backupRuntimeReady() {
		jsonOut(w, http.StatusServiceUnavailable, map[string]string{"error": "backup/restore is not initialized"})
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if err := decode(r, &in); err != nil {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	if !backupPasswordOK(in.Password) {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "backup password must contain at least 10 characters"})
		return
	}
	a.backupMu.Lock()
	defer a.backupMu.Unlock()
	out, err := os.CreateTemp(a.dataDir, ".zentssh-backup-*.zsb")
	if err != nil {
		a.internalError(w, "create backup temp file", err)
		return
	}
	path := out.Name()
	_ = out.Close()
	_ = os.Remove(path)
	defer os.Remove(path)
	manifest, err := a.createEncryptedBackup(path, in.Password)
	if err != nil {
		a.internalError(w, "create encrypted backup", err)
		return
	}
	state := a.loadBackupState()
	now := time.Now().UTC()
	state.LastBackupAt = &now
	if err := a.saveBackupState(state); err != nil {
		// The backup itself is valid; do not discard it only because operational metadata failed.
		log.Printf("backup state write failed: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		a.internalError(w, "open encrypted backup", err)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		a.internalError(w, "stat encrypted backup", err)
		return
	}
	filename := "zentssh-backup-" + manifest.CreatedAt.Format("20060102-150405") + ".zsb"
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", st.Size()))
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, filename, manifest.CreatedAt, f)
}

func parseBackupMasterKey(data []byte) ([]byte, error) {
	text := strings.TrimSpace(string(data))
	key, err := base64.RawStdEncoding.DecodeString(text)
	if err != nil || len(key) != 32 {
		key, err = base64.StdEncoding.DecodeString(text)
	}
	if err != nil || len(key) != 32 {
		return nil, errors.New("backup contains an invalid master key")
	}
	return key, nil
}

func extractEncryptedBackup(src io.Reader, password, targetDir string) (backupManifest, []byte, string, error) {
	var manifest backupManifest
	dec, err := newEncryptedBackupReader(src, password)
	if err != nil {
		return manifest, nil, "", err
	}
	gz, err := gzip.NewReader(dec)
	if err != nil {
		return manifest, nil, "", errors.New("invalid backup password or damaged backup")
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	var key []byte
	dbPath := filepath.Join(targetDir, "zentssh.db")
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return manifest, nil, "", errors.New("invalid backup password or damaged backup")
		}
		if h.Typeflag != tar.TypeReg || seen[h.Name] {
			return manifest, nil, "", errors.New("invalid ZentSSH backup contents")
		}
		seen[h.Name] = true
		switch h.Name {
		case "manifest.json":
			if h.Size <= 0 || h.Size > 64<<10 {
				return manifest, nil, "", errors.New("invalid backup manifest")
			}
			b, err := io.ReadAll(io.LimitReader(tr, (64<<10)+1))
			if err != nil || int64(len(b)) != h.Size || json.Unmarshal(b, &manifest) != nil {
				return manifest, nil, "", errors.New("invalid backup manifest")
			}
		case "master.key":
			if h.Size <= 0 || h.Size > 1024 {
				return manifest, nil, "", errors.New("invalid backup master key")
			}
			b, err := io.ReadAll(io.LimitReader(tr, 1025))
			if err != nil || int64(len(b)) != h.Size {
				return manifest, nil, "", errors.New("invalid backup master key")
			}
			key, err = parseBackupMasterKey(b)
			if err != nil {
				return manifest, nil, "", err
			}
		case "zentssh.db":
			if h.Size <= 0 || h.Size > maxRestoreDatabase {
				return manifest, nil, "", errors.New("backup database is too large or empty")
			}
			f, err := os.OpenFile(dbPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return manifest, nil, "", err
			}
			n, copyErr := io.Copy(f, tr)
			syncErr := f.Sync()
			closeErr := f.Close()
			if copyErr != nil || n != h.Size {
				return manifest, nil, "", errors.New("invalid backup database")
			}
			if syncErr != nil {
				return manifest, nil, "", syncErr
			}
			if closeErr != nil {
				return manifest, nil, "", closeErr
			}
		default:
			return manifest, nil, "", errors.New("unsupported file in ZentSSH backup")
		}
	}
	if !seen["manifest.json"] || !seen["zentssh.db"] || !seen["master.key"] || len(key) != 32 {
		return manifest, nil, "", errors.New("incomplete ZentSSH backup")
	}
	if manifest.Format != "zentssh-backup" || manifest.FormatVersion != backupFormatVersion || strings.TrimSpace(manifest.ZentSSHVersion) == "" {
		return manifest, nil, "", errors.New("unsupported backup manifest")
	}
	dbHash, dbSize, err := sha256File(dbPath)
	if err != nil {
		return manifest, nil, "", err
	}
	keyHash := sha256.Sum256(key)
	if dbSize != manifest.DatabaseSize || subtle.ConstantTimeCompare([]byte(strings.ToLower(dbHash)), []byte(strings.ToLower(manifest.DatabaseSHA256))) != 1 ||
		subtle.ConstantTimeCompare([]byte(hex.EncodeToString(keyHash[:])), []byte(strings.ToLower(manifest.MasterKeySHA256))) != 1 {
		return manifest, nil, "", errors.New("backup checksum validation failed")
	}
	if err := zdb.ValidateSnapshot(dbPath); err != nil {
		return manifest, nil, "", fmt.Errorf("backup database validation failed: %w", err)
	}
	return manifest, key, dbPath, nil
}

func syncDir(path string) {
	if d, err := os.Open(path); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

func writeMasterKeyFile(path string, key []byte) error {
	tmp := path + ".pending-" + randID(6)
	if err := os.WriteFile(tmp, []byte(base64.RawStdEncoding.EncodeToString(key)+"\n"), 0600); err != nil {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_RDWR, 0600)
	if err == nil {
		err = f.Sync()
		_ = f.Close()
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (a *App) installRestore(restoredDB string, restoredKey []byte) (bool, error) {
	if len(restoredKey) != 32 {
		return false, errors.New("invalid restored master key")
	}
	if a.externalMasterKey && subtle.ConstantTimeCompare(restoredKey, a.masterKey) != 1 {
		return false, errors.New("backup master key does not match the externally configured MASTER_KEY")
	}
	dbPath := filepath.Join(a.dataDir, "zentssh.db")
	keyPath := filepath.Join(a.dataDir, "master.key")
	oldDB := filepath.Join(a.dataDir, ".zentssh.db.restore-old-"+randID(6))
	oldKey := filepath.Join(a.dataDir, ".master.key.restore-old-"+randID(6))

	// Make the rollback copy self-contained before the current database handle is closed.
	_, _ = a.DB.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	a.Close()
	if err := a.DB.Close(); err != nil {
		return true, fmt.Errorf("close current database: %w", err)
	}
	closed := true

	dbMoved := false
	keyMoved := false
	rollback := func() {
		_ = os.Remove(dbPath)
		if dbMoved {
			_ = os.Rename(oldDB, dbPath)
		}
		_ = os.Remove(keyPath)
		if keyMoved {
			_ = os.Rename(oldKey, keyPath)
		}
		_ = os.Remove(dbPath + "-wal")
		_ = os.Remove(dbPath + "-shm")
		syncDir(a.dataDir)
	}

	if _, err := os.Stat(dbPath); err == nil {
		if err := os.Rename(dbPath, oldDB); err != nil {
			return closed, fmt.Errorf("stage current database: %w", err)
		}
		dbMoved = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return closed, fmt.Errorf("inspect current database: %w", err)
	}
	if st, err := os.Lstat(keyPath); err == nil {
		if !st.Mode().IsRegular() {
			rollback()
			return closed, errors.New("current master key path cannot be replaced safely")
		}
		if err := os.Rename(keyPath, oldKey); err != nil {
			rollback()
			return closed, fmt.Errorf("stage current master key: %w", err)
		}
		keyMoved = true
	} else if !errors.Is(err, os.ErrNotExist) {
		rollback()
		return closed, fmt.Errorf("inspect current master key: %w", err)
	}
	_ = os.Remove(dbPath + "-wal")
	_ = os.Remove(dbPath + "-shm")
	if err := writeMasterKeyFile(keyPath, restoredKey); err != nil {
		rollback()
		return closed, fmt.Errorf("install restored master key: %w", err)
	}
	if err := os.Rename(restoredDB, dbPath); err != nil {
		rollback()
		return closed, fmt.Errorf("install restored database: %w", err)
	}
	if err := os.Chmod(dbPath, 0600); err != nil {
		rollback()
		return closed, fmt.Errorf("protect restored database: %w", err)
	}
	syncDir(a.dataDir)
	_ = os.Remove(oldDB)
	_ = os.Remove(oldKey)
	return closed, nil
}

func (a *App) scheduleRestart() {
	go func() {
		time.Sleep(750 * time.Millisecond)
		a.requestRestart()
	}()
}

func (a *App) adminBackupRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !a.backupRuntimeReady() {
		jsonOut(w, http.StatusServiceUnavailable, map[string]string{"error": "backup/restore is not initialized"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRestoreUpload)
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "invalid or too large backup upload"})
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	password := r.FormValue("password")
	if !backupPasswordOK(password) {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "backup password must contain at least 10 characters"})
		return
	}
	file, _, err := r.FormFile("backup")
	if err != nil {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": "backup file is required"})
		return
	}
	defer file.Close()

	a.backupMu.Lock()
	defer a.backupMu.Unlock()
	restoreDir, err := os.MkdirTemp(a.dataDir, ".zentssh-restore-*")
	if err != nil {
		a.internalError(w, "create restore staging directory", err)
		return
	}
	defer os.RemoveAll(restoreDir)
	manifest, restoredKey, restoredDB, err := extractEncryptedBackup(file, password, restoreDir)
	if err != nil {
		jsonOut(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if a.externalMasterKey && subtle.ConstantTimeCompare(restoredKey, a.masterKey) != 1 {
		jsonOut(w, http.StatusConflict, map[string]string{"error": "this backup uses a different master key; update the externally configured MASTER_KEY before restoring it"})
		return
	}
	closed, err := a.installRestore(restoredDB, restoredKey)
	if err != nil {
		a.internalError(w, "install restore", err)
		if closed {
			a.scheduleRestart()
		}
		return
	}
	now := time.Now().UTC()
	state := backupState{LastBackupAt: &manifest.CreatedAt, LastRestoreAt: &now}
	_ = a.saveBackupState(state)
	jsonOut(w, http.StatusOK, map[string]any{
		"ok": true, "restarting": true, "backupCreatedAt": manifest.CreatedAt, "backupVersion": manifest.ZentSSHVersion,
	})
	a.scheduleRestart()
}
