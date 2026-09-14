package app

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func mustCIDR(t *testing.T, raw string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(raw)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestClientIPIgnoresForwardedHeaderFromUntrustedPeer(t *testing.T) {
	a := &App{cfg: runtimeConfig{TrustedProxyNets: []*net.IPNet{mustCIDR(t, "10.0.0.0/8")}}}
	r := httptest.NewRequest("GET", "http://zentssh.local/", nil)
	r.RemoteAddr = "203.0.113.9:4242"
	r.Header.Set("X-Forwarded-For", "198.51.100.5")
	if got := a.clientIP(r); got != "203.0.113.9" {
		t.Fatalf("client ip = %s", got)
	}
}

func TestClientIPUsesRightmostUntrustedHop(t *testing.T) {
	a := &App{cfg: runtimeConfig{TrustedProxyNets: []*net.IPNet{mustCIDR(t, "10.0.0.0/8")}}}
	r := httptest.NewRequest("GET", "http://zentssh.local/", nil)
	r.RemoteAddr = "10.0.0.2:4242"
	r.Header.Set("X-Forwarded-For", "192.0.2.66, 198.51.100.10")
	if got := a.clientIP(r); got != "198.51.100.10" {
		t.Fatalf("client ip = %s", got)
	}
}

func TestCSRFRequiresMatchingCookieAndHeader(t *testing.T) {
	a := &App{}
	r := httptest.NewRequest("POST", "http://zentssh.local/api/test", nil)
	r.AddCookie(&http.Cookie{Name: "zentssh_csrf", Value: "token123"})
	r.Header.Set("X-CSRF-Token", "token123")
	if !a.csrfOK(r) {
		t.Fatal("matching csrf token rejected")
	}
	r.Header.Set("X-CSRF-Token", "wrong")
	if a.csrfOK(r) {
		t.Fatal("mismatched csrf token accepted")
	}
}
