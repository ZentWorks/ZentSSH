package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/pkg/sftp"
)

const maxURLUploadBytes int64 = 5 << 30 // 5 GiB hard safety ceiling per URL download.

var urlUploadBlockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
	netip.MustParsePrefix("198.18.0.0/15"), // benchmark networks, commonly internal
}

func validateURLUploadURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil {
		return nil, errors.New("invalid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("only http:// and https:// URLs are allowed")
	}
	if u.User != nil {
		return nil, errors.New("URLs with embedded credentials are not allowed")
	}
	if strings.TrimSpace(u.Hostname()) == "" {
		return nil, errors.New("URL host is required")
	}
	if strings.EqualFold(u.Hostname(), "localhost") || strings.HasSuffix(strings.ToLower(u.Hostname()), ".localhost") || strings.HasSuffix(strings.ToLower(u.Hostname()), ".local") {
		return nil, errors.New("local or private URL targets are not allowed")
	}
	return u, nil
}

func urlUploadIPAllowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, prefix := range urlUploadBlockedPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

func resolveSafeURLUploadHost(ctx context.Context, host string) ([]netip.Addr, error) {
	if parsed, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		if !urlUploadIPAllowed(parsed) {
			return nil, errors.New("local or private URL targets are not allowed")
		}
		return []netip.Addr{parsed}, nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve URL host: %w", err)
	}
	allowed := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if urlUploadIPAllowed(ip) {
			allowed = append(allowed, ip)
		}
	}
	if len(allowed) == 0 {
		return nil, errors.New("local or private URL targets are not allowed")
	}
	return allowed, nil
}

func safeURLUploadClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   12 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		ExpectContinueTimeout: 2 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, err := resolveSafeURLUploadHost(ctx, host)
			if err != nil {
				return nil, err
			}
			var lastErr error
			for _, ip := range ips {
				conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
			}
			if lastErr == nil {
				lastErr = errors.New("no public address available for URL host")
			}
			return nil, lastErr
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many URL redirects")
			}
			if _, err := validateURLUploadURL(req.URL.String()); err != nil {
				return err
			}
			return nil
		},
	}
}

func (a *App) uploadURLToRemote(ctx context.Context, sf *sftp.Client, rawURL, target string) error {
	u, err := validateURLUploadURL(rawURL)
	if err != nil {
		return err
	}
	target = strings.TrimSpace(target)
	if target == "" || target == "." || target == "/" || strings.HasSuffix(target, "/") {
		return errors.New("a destination file path is required")
	}
	if info, statErr := sf.Stat(target); statErr == nil && info.IsDir() {
		return errors.New("destination path points to a directory")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "ZentSSH/0.2.2-dev URL-Upload")
	client := safeURLUploadClient()
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download URL: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("download URL returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxURLUploadBytes {
		return fmt.Errorf("URL download exceeds the %d GiB safety limit", maxURLUploadBytes>>30)
	}

	dir := path.Dir(target)
	base := path.Base(target)
	tmp := path.Join(dir, fmt.Sprintf(".%s.zentssh-url-%s", base, randID(6)))
	out, err := sf.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return fmt.Errorf("create remote temporary file: %w", err)
	}
	limited := &io.LimitedReader{R: resp.Body, N: maxURLUploadBytes + 1}
	written, copyErr := io.Copy(out, limited)
	closeErr := out.Close()
	if copyErr != nil {
		_ = sf.Remove(tmp)
		return fmt.Errorf("stream URL to remote server: %w", copyErr)
	}
	if closeErr != nil {
		_ = sf.Remove(tmp)
		return fmt.Errorf("close remote file: %w", closeErr)
	}
	if written > maxURLUploadBytes {
		_ = sf.Remove(tmp)
		return fmt.Errorf("URL download exceeds the %d GiB safety limit", maxURLUploadBytes>>30)
	}

	// Keep an existing target recoverable until the fully downloaded temporary file
	// is ready. This avoids leaving a half-written destination on HTTP/SFTP errors.
	backup := ""
	if current, statErr := sf.Stat(target); statErr == nil {
		// Re-check immediately before replacement as the destination may have changed
		// while the HTTP body was being streamed. Never rename a directory away.
		if current.IsDir() {
			_ = sf.Remove(tmp)
			return errors.New("destination path points to a directory")
		}
		backup = path.Join(dir, fmt.Sprintf(".%s.zentssh-backup-%s", base, randID(6)))
		if err = sf.Rename(target, backup); err != nil {
			_ = sf.Remove(tmp)
			return fmt.Errorf("prepare existing destination: %w", err)
		}
	}
	if err = sf.Rename(tmp, target); err != nil {
		if backup != "" {
			_ = sf.Rename(backup, target)
		}
		_ = sf.Remove(tmp)
		return fmt.Errorf("move downloaded file into place: %w", err)
	}
	if backup != "" {
		_ = sf.Remove(backup)
	}
	return nil
}
