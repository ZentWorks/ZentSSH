package app

import "testing"

func TestBrowserUILanguage(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{"de-DE,de;q=0.9,en;q=0.8", "de"},
		{"de-CH", "de"},
		{"en-US,en;q=0.9", "en"},
		{"fr-FR,fr;q=0.9", "en"},
		{"", "en"},
	}
	for _, tt := range tests {
		if got := browserUILanguage(tt.header); got != tt.want {
			t.Fatalf("browserUILanguage(%q) = %q, want %q", tt.header, got, tt.want)
		}
	}
}

func TestNormalizeUILanguage(t *testing.T) {
	for input, want := range map[string]string{"de": "de", "de-DE": "de", "EN": "en", "en-GB": "en", "en-CA": "en", "de-LU": "de"} {
		got, ok := normalizeUILanguage(input)
		if !ok || got != want {
			t.Fatalf("normalizeUILanguage(%q) = %q, %t; want %q, true", input, got, ok, want)
		}
	}
	if _, ok := normalizeUILanguage("fr"); ok {
		t.Fatal("unsupported language accepted")
	}
}

func TestCollapsedFolderIDsRoundTrip(t *testing.T) {
	input := []int64{4, 2, 4, 0, -1, 9}
	encoded := encodeCollapsedFolderIDs(input)
	got := decodeCollapsedFolderIDs(encoded)
	want := []int64{4, 2, 9}
	if len(got) != len(want) {
		t.Fatalf("decoded folder IDs = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("decoded folder IDs = %#v, want %#v", got, want)
		}
	}
}

func TestDecodeCollapsedFolderIDsRejectsInvalidJSON(t *testing.T) {
	got := decodeCollapsedFolderIDs("not-json")
	if got == nil || len(got) != 0 {
		t.Fatalf("decodeCollapsedFolderIDs invalid JSON = %#v, want empty slice", got)
	}
}
