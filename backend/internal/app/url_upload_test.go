package app

import (
	"net/netip"
	"testing"
)

func TestValidateURLUploadURL(t *testing.T) {
	valid := []string{"https://example.com/file.tar.gz", "http://example.com:8080/a"}
	for _, raw := range valid {
		if _, err := validateURLUploadURL(raw); err != nil {
			t.Fatalf("expected %q to be valid: %v", raw, err)
		}
	}
	invalid := []string{"file:///etc/passwd", "ftp://example.com/a", "http://localhost/a", "http://x.local/a", "https://user:pass@example.com/a"}
	for _, raw := range invalid {
		if _, err := validateURLUploadURL(raw); err == nil {
			t.Fatalf("expected %q to be rejected", raw)
		}
	}
}

func TestURLUploadIPAllowed(t *testing.T) {
	allowed := []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"}
	for _, raw := range allowed {
		if !urlUploadIPAllowed(netip.MustParseAddr(raw)) {
			t.Fatalf("expected public address %s to be allowed", raw)
		}
	}
	blocked := []string{"127.0.0.1", "10.0.0.1", "172.16.1.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "198.18.0.1", "::1", "fc00::1", "fe80::1"}
	for _, raw := range blocked {
		if urlUploadIPAllowed(netip.MustParseAddr(raw)) {
			t.Fatalf("expected private/special address %s to be rejected", raw)
		}
	}
}
