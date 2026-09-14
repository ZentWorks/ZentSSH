package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestDecodeMasterKey(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	encoded := base64.RawStdEncoding.EncodeToString(raw)
	got, err := decodeMasterKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatal("decoded key mismatch")
	}
	if _, err := decodeMasterKey("not-a-valid-key"); err == nil {
		t.Fatal("invalid key accepted")
	}
}

func TestInvalidMasterKeyEnvIsFatal(t *testing.T) {
	t.Setenv("MASTER_KEY", "broken")
	dir := t.TempDir()
	if _, err := masterKey(dir); err == nil {
		t.Fatal("invalid MASTER_KEY should fail")
	}
	if _, err := os.Stat(filepath.Join(dir, "master.key")); !os.IsNotExist(err) {
		t.Fatal("invalid env must not create a fallback key")
	}
}

func TestInvalidExistingMasterKeyIsNotOverwritten(t *testing.T) {
	t.Setenv("MASTER_KEY", "")
	dir := t.TempDir()
	p := filepath.Join(dir, "master.key")
	if err := os.WriteFile(p, []byte("broken\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := masterKey(dir); err == nil {
		t.Fatal("invalid existing key should fail")
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "broken\n" {
		t.Fatal("existing invalid key was overwritten")
	}
}

func TestMasterKeyGeneration(t *testing.T) {
	t.Setenv("MASTER_KEY", "")
	dir := t.TempDir()
	key, err := masterKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d", len(key))
	}
	st, err := os.Stat(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("mode = %04o", st.Mode().Perm())
	}
}
