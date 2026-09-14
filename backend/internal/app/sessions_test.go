package app

import (
	"io"
	"os"
	"testing"
	"time"
)

type testCloser struct{ closed bool }

func (c *testCloser) Write(p []byte) (int, error) { return len(p), nil }
func (c *testCloser) Close() error                { c.closed = true; return nil }

func TestSessionBufferIsBounded(t *testing.T) {
	a := &App{cfg: runtimeConfig{SessionBufferSize: 8}}
	s := &LiveSession{Attached: map[*sessionAttachment]struct{}{}, LastActivity: time.Now()}
	a.publishSessionOutput(s, []byte("123456"))
	a.publishSessionOutput(s, []byte("abcdef"))
	if got := string(s.Buffer); got != "56abcdef" {
		t.Fatalf("bounded ring buffer = %q, want %q", got, "56abcdef")
	}
}

func TestSessionReservationLimits(t *testing.T) {
	a := &App{
		live:               map[string]*LiveSession{"one": {UserID: 7}},
		cfg:                runtimeConfig{MaxSessionsPerUser: 2, MaxTotalSessions: 3},
		sessionReserveUser: map[int64]int{},
	}
	if err := a.reserveLiveSession(7); err != nil {
		t.Fatalf("first reservation failed: %v", err)
	}
	defer a.releaseLiveSessionReservation(7)
	if err := a.reserveLiveSession(7); err == nil {
		t.Fatal("expected per-user session limit")
	}
	if err := a.reserveLiveSession(8); err != nil {
		t.Fatalf("different user should fit global limit: %v", err)
	}
	a.releaseLiveSessionReservation(8)
}

func TestTerminateSessionClosesResources(t *testing.T) {
	input := &testCloser{}
	cleaned := false
	a := &App{live: map[string]*LiveSession{}}
	s := &LiveSession{
		ID:       "s1",
		In:       input,
		Out:      io.NopCloser(nilReader{}),
		cleanup:  func() { cleaned = true },
		Attached: map[*sessionAttachment]struct{}{},
	}
	a.live[s.ID] = s
	a.terminateLiveSession(s.ID, "test")
	if !input.closed || !cleaned {
		t.Fatalf("resources not closed: input=%t cleanup=%t", input.closed, cleaned)
	}
	if a.getLiveSession(s.ID) != nil {
		t.Fatal("terminated session still present")
	}
}

type nilReader struct{}

func (nilReader) Read([]byte) (int, error) { return 0, io.EOF }

func TestParseDurationAllowZeroUnlimited(t *testing.T) {
	const key = "ZENTSSH_TEST_RETENTION"
	old, had := os.LookupEnv(key)
	defer func() {
		if had {
			_ = os.Setenv(key, old)
		} else {
			_ = os.Unsetenv(key)
		}
	}()
	_ = os.Setenv(key, "unlimited")
	if got := parseDurationAllowZero(key, 30*time.Minute, 24*time.Hour); got != -1 {
		t.Fatalf("unlimited parsed as %s", got)
	}
	_ = os.Setenv(key, "0")
	if got := parseDurationAllowZero(key, 30*time.Minute, 24*time.Hour); got != 0 {
		t.Fatalf("off parsed as %s", got)
	}
}
