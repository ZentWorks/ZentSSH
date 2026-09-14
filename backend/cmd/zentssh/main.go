package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"zentssh.local/backend/internal/app"
	zcrypto "zentssh.local/backend/internal/crypto"
	zdb "zentssh.local/backend/internal/db"
)

func main() {
	data := env("DATA_DIR", "/data")
	if err := os.MkdirAll(data, 0700); err != nil {
		log.Fatal(err)
	}
	key, err := masterKey(data)
	if err != nil {
		log.Fatal(err)
	}
	box, err := zcrypto.New(key)
	if err != nil {
		log.Fatal(err)
	}
	database, err := zdb.Open(filepath.Join(data, "zentssh.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer database.Close()

	a := app.New(database, box, env("WEB_DIR", "/app/web"))
	a.ConfigureBackupRestore(data, key, strings.TrimSpace(os.Getenv("MASTER_KEY")) != "", func() {
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
	})
	defer a.Close()
	addr := env("LISTEN_ADDR", ":8080")
	server := &http.Server{
		Addr:              addr,
		Handler:           a.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		a.Close()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTP shutdown: %v", err)
		}
	}()

	log.Printf("ZentSSH %s listening on %s", app.Version, addr)
	err = server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
	log.Printf("ZentSSH shutdown complete")
}

func masterKey(data string) ([]byte, error) {
	if text := strings.TrimSpace(os.Getenv("MASTER_KEY")); text != "" {
		key, err := decodeMasterKey(text)
		if err != nil {
			return nil, fmt.Errorf("MASTER_KEY is set but invalid: %w", err)
		}
		return key, nil
	}

	p := filepath.Join(data, "master.key")
	if st, err := os.Lstat(p); err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing symlink master key at %s", p)
		}
		if !st.Mode().IsRegular() {
			return nil, fmt.Errorf("master key path is not a regular file: %s", p)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read master key: %w", err)
		}
		key, err := decodeMasterKey(strings.TrimSpace(string(b)))
		if err != nil {
			return nil, fmt.Errorf("existing master key is invalid; refusing to overwrite %s: %w", p, err)
		}
		if st.Mode().Perm()&0077 != 0 {
			log.Printf("warning: %s permissions are %04o; recommended 0600", p, st.Mode().Perm())
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect master key: %w", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("create master key: %w", err)
	}
	encoded := base64.RawStdEncoding.EncodeToString(key) + "\n"
	if _, err = f.WriteString(encoded); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return nil, fmt.Errorf("write master key: %w", err)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close master key: %w", closeErr)
	}
	log.Printf("generated new master encryption key at %s", p)
	return key, nil
}

func decodeMasterKey(text string) ([]byte, error) {
	if key, err := base64.RawStdEncoding.DecodeString(text); err == nil && len(key) == 32 {
		return key, nil
	}
	if key, err := base64.StdEncoding.DecodeString(text); err == nil && len(key) == 32 {
		return key, nil
	}
	return nil, errors.New("expected exactly 32 bytes encoded as base64")
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
