package app

import "testing"

func TestParseQuickTarget(t *testing.T) {
	tests := []struct {
		in       string
		user     string
		host     string
		port     int
		wantFail bool
	}{
		{"root@192.168.1.20", "root", "192.168.1.20", 22, false},
		{"deploy@example.com:2222", "deploy", "example.com", 2222, false},
		{"ssh ubuntu@server.example -p 2202", "ubuntu", "server.example", 2202, false},
		{"ssh -p 2022 admin@host", "admin", "host", 2022, false},
		{"ssh -l alice host.example", "alice", "host.example", 22, false},
		{"root@[2001:db8::1]:2222", "root", "2001:db8::1", 2222, false},
		{"root@[2001:db8::1]", "root", "2001:db8::1", 22, false},
		{"ssh root@host -o ProxyCommand=bad", "", "", 0, true},
		{"", "", "", 0, true},
	}
	for _, tt := range tests {
		got, err := parseQuickTarget(tt.in)
		if tt.wantFail {
			if err == nil {
				t.Errorf("parseQuickTarget(%q) expected failure, got %+v", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseQuickTarget(%q): %v", tt.in, err)
			continue
		}
		if got.User != tt.user || got.Host != tt.host || got.Port != tt.port {
			t.Errorf("parseQuickTarget(%q) = %+v, want user=%q host=%q port=%d", tt.in, got, tt.user, tt.host, tt.port)
		}
	}
}

func TestQuickRouteKey(t *testing.T) {
	if got := quickRouteKey(nil); got != "direct" {
		t.Fatalf("nil jump route = %q, want direct", got)
	}
	id := int64(42)
	if got := quickRouteKey(&id); got != "jump:42" {
		t.Fatalf("jump route = %q, want jump:42", got)
	}
}
