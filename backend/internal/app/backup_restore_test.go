package app

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	zcrypto "zentssh.local/backend/internal/crypto"
	zdb "zentssh.local/backend/internal/db"
)

func backupTestApp(t *testing.T, dir string, key []byte) *App {
	t.Helper()
	database, err := zdb.Open(filepath.Join(dir, "zentssh.db"))
	if err != nil {
		t.Fatal(err)
	}
	box, err := zcrypto.New(key)
	if err != nil {
		t.Fatal(err)
	}
	a := New(database, box, t.TempDir())
	a.ConfigureBackupRestore(dir, key, false, nil)
	return a
}

func addBackupUser(t *testing.T, a *App, name, email string) int64 {
	t.Helper()
	res, err := a.DB.Exec(`INSERT INTO users(name,email,password_hash,role,active) VALUES(?,?,?,?,1)`, name, email, hashPass("very-secret-password"), "admin")
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return id
}

func TestBackupArchiveRoundTripAndWrongPassword(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x42}, 32)
	a := backupTestApp(t, dir, key)
	defer a.Close()
	addBackupUser(t, a, "Backup Admin", "backup@example.test")

	archive := filepath.Join(dir, "test.zsb")
	manifest, err := a.createEncryptedBackup(archive, "backup-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.DatabaseSize <= 0 || manifest.DatabaseSHA256 == "" {
		t.Fatalf("invalid manifest: %#v", manifest)
	}

	wrong, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, wrongErr := extractEncryptedBackup(wrong, "wrong-password-123", t.TempDir())
	_ = wrong.Close()
	if wrongErr == nil {
		t.Fatal("wrong backup password was accepted")
	}

	tampered, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if len(tampered) < len(backupMagic)+8 {
		t.Fatal("backup archive is unexpectedly short")
	}
	headerLenOffset := len(backupMagic)
	headerLen := int(binary.BigEndian.Uint32(tampered[headerLenOffset : headerLenOffset+4]))
	cipherOffset := headerLenOffset + 4 + headerLen + 4
	if cipherOffset >= len(tampered) {
		t.Fatal("backup archive contains no encrypted payload")
	}
	tampered[cipherOffset] ^= 0x01
	tamperedPath := filepath.Join(dir, "tampered.zsb")
	if err := os.WriteFile(tamperedPath, tampered, 0600); err != nil {
		t.Fatal(err)
	}
	tamperedFile, err := os.Open(tamperedPath)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, tamperErr := extractEncryptedBackup(tamperedFile, "backup-password-123", t.TempDir())
	_ = tamperedFile.Close()
	if tamperErr == nil {
		t.Fatal("tampered backup was accepted")
	}

	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	restoredManifest, restoredKey, restoredDB, err := extractEncryptedBackup(f, "backup-password-123", t.TempDir())
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restoredKey, key) {
		t.Fatal("restored master key differs from backup key")
	}
	if restoredManifest.DatabaseSHA256 != manifest.DatabaseSHA256 {
		t.Fatal("restored manifest differs")
	}
	if err := zdb.ValidateSnapshot(restoredDB); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreCompletelyReplacesDatabaseAndMasterKey(t *testing.T) {
	password := "restore-password-123"
	key := bytes.Repeat([]byte{0x27}, 32)

	sourceDir := t.TempDir()
	source := backupTestApp(t, sourceDir, key)
	addBackupUser(t, source, "From Backup", "from-backup@example.test")
	archive := filepath.Join(sourceDir, "source.zsb")
	if _, err := source.createEncryptedBackup(archive, password); err != nil {
		t.Fatal(err)
	}
	source.Close()
	_ = source.DB.Close()

	targetDir := t.TempDir()
	target := backupTestApp(t, targetDir, key)
	addBackupUser(t, target, "Current Admin", "current@example.test")
	restarted := make(chan struct{}, 1)
	target.ConfigureBackupRestore(targetDir, key, false, func() { restarted <- struct{}{} })

	backupBytes, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("backup", "source.zsb")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(backupBytes); err != nil {
		t.Fatal(err)
	}
	if err := mw.WriteField("password", password); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/admin/backup/restore", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	target.adminBackupRestore(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("restore status=%d body=%s", rec.Code, rec.Body.String())
	}

	reopened, err := zdb.Open(filepath.Join(targetDir, "zentssh.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var backupCount, currentCount int
	if err := reopened.QueryRow(`SELECT COUNT(*) FROM users WHERE email=?`, "from-backup@example.test").Scan(&backupCount); err != nil {
		t.Fatal(err)
	}
	if err := reopened.QueryRow(`SELECT COUNT(*) FROM users WHERE email=?`, "current@example.test").Scan(&currentCount); err != nil {
		t.Fatal(err)
	}
	if backupCount != 1 || currentCount != 0 {
		t.Fatalf("restore did not replace database: backup=%d current=%d", backupCount, currentCount)
	}
	keyFile, err := os.ReadFile(filepath.Join(targetDir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(keyFile)))
	if err != nil || !bytes.Equal(decoded, key) {
		t.Fatal("restored master.key is invalid")
	}
	select {
	case <-restarted:
	case <-time.After(2 * time.Second):
		t.Fatal("restore did not request a restart")
	}
}

func TestRestoreRejectsDifferentExternalMasterKeyBeforeReplacement(t *testing.T) {
	password := "restore-password-123"
	sourceDir := t.TempDir()
	sourceKey := bytes.Repeat([]byte{0x11}, 32)
	source := backupTestApp(t, sourceDir, sourceKey)
	addBackupUser(t, source, "Backup Admin", "backup-external@example.test")
	archive := filepath.Join(sourceDir, "source.zsb")
	if _, err := source.createEncryptedBackup(archive, password); err != nil {
		t.Fatal(err)
	}
	source.Close()
	_ = source.DB.Close()

	targetDir := t.TempDir()
	targetKey := bytes.Repeat([]byte{0x22}, 32)
	target := backupTestApp(t, targetDir, targetKey)
	defer target.Close()
	addBackupUser(t, target, "Current Admin", "external-current@example.test")
	target.ConfigureBackupRestore(targetDir, targetKey, true, nil)

	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, _ := mw.CreateFormFile("backup", "source.zsb")
	_, _ = io.Copy(part, f)
	_ = mw.WriteField("password", password)
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/backup/restore", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	target.adminBackupRestore(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("external-key mismatch status=%d body=%s", rec.Code, rec.Body.String())
	}
	var count int
	if err := target.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE email=?`, "external-current@example.test").Scan(&count); err != nil {
		t.Fatal("live database was closed or replaced before external key validation: ", err)
	}
	if count != 1 {
		t.Fatal("current database was changed despite external key mismatch")
	}
}
