package app

import (
	"strings"
	"testing"
)

func TestParseOpenSSHConfig(t *testing.T) {
	cfg := `
Host web01
  HostName 10.0.0.10
  User deploy
  Port 2222
  IdentityFile "/home/me/key file" # local key hint
  PreferredAuthentications publickey
  ServerAliveInterval 20
  ProxyJump jump01

Host jump01 backup-*
  HostName bastion.example.com
  User root

Host wildcard-*
  HostName 10.0.0.50

Match host *.internal
  User ignored
Include ~/.ssh/conf.d/*
`
	p := parseOpenSSHConfig(cfg)
	if len(p.Entries) != 2 {
		t.Fatalf("expected 2 concrete entries, got %d: %#v", len(p.Entries), p.Entries)
	}
	web := p.Entries[0]
	if web.Alias != "web01" || web.HostName != "10.0.0.10" || web.User != "deploy" || web.Port != 2222 || web.IdentityFile != "/home/me/key file" || web.ProxyJump != "jump01" || web.ServerAliveInterval != 20 {
		t.Fatalf("unexpected web entry: %#v", web)
	}
	if p.Entries[1].Alias != "jump01" {
		t.Fatalf("unexpected second entry: %#v", p.Entries[1])
	}
	joined := strings.Join(p.Warnings, "\n")
	for _, want := range []string{"backup-*", "wildcard-*", "Match blocks", "Include is not expanded"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected warning containing %q, got %q", want, joined)
		}
	}
}

func TestSplitSSHFieldsCommentsAndQuotes(t *testing.T) {
	got, e := splitSSHFields(`IdentityFile "/home/me/key file" # comment`)
	if e != nil {
		t.Fatal(e)
	}
	if len(got) != 2 || got[1] != "/home/me/key file" {
		t.Fatalf("unexpected fields: %#v", got)
	}
}

func TestProxyJumpAlias(t *testing.T) {
	cases := map[string]string{
		"jump01":             "jump01",
		"root@jump01":        "jump01",
		"root@jump01:2222":   "jump01",
		"root@[2001:db8::1]": "2001:db8::1",
	}
	for in, want := range cases {
		got, ok := proxyJumpAlias(in)
		if !ok || got != want {
			t.Fatalf("proxyJumpAlias(%q) = %q,%v want %q,true", in, got, ok, want)
		}
	}
	if _, ok := proxyJumpAlias("jump1,jump2"); ok {
		t.Fatal("multi-hop ProxyJump must not map automatically")
	}
}
