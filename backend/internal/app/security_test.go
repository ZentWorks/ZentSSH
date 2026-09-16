package app

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestWebSocketOriginAllowsDirectHTTPAndHTTPS(t *testing.T) {
	tests := []struct {
		name   string
		target string
		origin string
	}{
		{name: "http", target: "http://ssh.example.test/ws/ssh/session", origin: "http://ssh.example.test"},
		{name: "https", target: "https://ssh.example.test/ws/ssh/session", origin: "https://ssh.example.test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &App{}
			r := httptest.NewRequest(http.MethodGet, tt.target, nil)
			r.Host = "ssh.example.test"
			r.Header.Set("Origin", tt.origin)
			if !a.validWebSocketOrigin(r) {
				t.Fatalf("same-origin websocket rejected: target=%s origin=%s", tt.target, tt.origin)
			}
		})
	}
}

func TestWebSocketOriginAllowsHTTPSBrowserBehindHTTPProxy(t *testing.T) {
	a := &App{}
	r := httptest.NewRequest(http.MethodGet, "http://ssh.example.test/ws/ssh/session", nil)
	r.Host = "ssh.example.test"
	r.Header.Set("Origin", "https://ssh.example.test")
	if !a.validWebSocketOrigin(r) {
		t.Fatal("https browser origin was rejected when TLS is terminated before the backend")
	}
}

func TestWebSocketOriginUsesTrustedForwardedHostAndProto(t *testing.T) {
	a := &App{cfg: runtimeConfig{TrustedProxyNets: []*net.IPNet{mustCIDR(t, "10.0.0.0/8")}}}
	r := httptest.NewRequest(http.MethodGet, "http://zentssh:8080/ws/ssh/session", nil)
	r.Host = "zentssh:8080"
	r.RemoteAddr = "10.0.0.2:4321"
	r.Header.Set("X-Forwarded-Host", "ssh.example.test")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Origin", "https://ssh.example.test")
	if !a.validWebSocketOrigin(r) {
		t.Fatal("trusted reverse-proxy websocket origin rejected")
	}
}

func TestWebSocketOriginRejectsForeignHostAndUnsupportedScheme(t *testing.T) {
	a := &App{}
	for _, origin := range []string{"https://evil.example.test", "file://ssh.example.test", "javascript://ssh.example.test"} {
		r := httptest.NewRequest(http.MethodGet, "http://ssh.example.test/ws/ssh/session", nil)
		r.Host = "ssh.example.test"
		r.Header.Set("Origin", origin)
		if a.validWebSocketOrigin(r) {
			t.Fatalf("unsafe websocket origin accepted: %s", origin)
		}
	}
}

func TestWebSocketOriginBaseURLRemainsStrict(t *testing.T) {
	base, err := url.Parse("https://ssh.example.test")
	if err != nil {
		t.Fatal(err)
	}
	a := &App{cfg: runtimeConfig{BaseURL: base}}

	allowed := httptest.NewRequest(http.MethodGet, "http://zentssh:8080/ws/ssh/session", nil)
	allowed.Host = "zentssh:8080"
	allowed.Header.Set("Origin", "https://ssh.example.test")
	if !a.validWebSocketOrigin(allowed) {
		t.Fatal("origin matching BASE_URL rejected")
	}

	wrongScheme := httptest.NewRequest(http.MethodGet, "http://zentssh:8080/ws/ssh/session", nil)
	wrongScheme.Header.Set("Origin", "http://ssh.example.test")
	if a.validWebSocketOrigin(wrongScheme) {
		t.Fatal("BASE_URL scheme mismatch accepted")
	}

	wrongHost := httptest.NewRequest(http.MethodGet, "http://zentssh:8080/ws/ssh/session", nil)
	wrongHost.Header.Set("Origin", "https://evil.example.test")
	if a.validWebSocketOrigin(wrongHost) {
		t.Fatal("BASE_URL host mismatch accepted")
	}
}

func TestWebSocketOriginMissingRequiresExplicitOptIn(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://ssh.example.test/ws/ssh/session", nil)
	r.Host = "ssh.example.test"
	if (&App{}).validWebSocketOrigin(r) {
		t.Fatal("missing Origin accepted by default")
	}
	if !(&App{cfg: runtimeConfig{AllowWSNoOrigin: true}}).validWebSocketOrigin(r) {
		t.Fatal("missing Origin rejected despite explicit opt-in")
	}
}
