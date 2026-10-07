package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

func TestWebSocketHeartbeatWindowAllowsMultiplePings(t *testing.T) {
	if websocketPingInterval <= 0 {
		t.Fatal("websocket ping interval must be positive")
	}
	if websocketReadTimeout < 2*websocketPingInterval {
		t.Fatalf("websocket read timeout %s is too short for ping interval %s", websocketReadTimeout, websocketPingInterval)
	}
	if websocketWriteTimeout <= 0 || websocketWriteTimeout >= websocketReadTimeout {
		t.Fatalf("invalid websocket write timeout %s for read timeout %s", websocketWriteTimeout, websocketReadTimeout)
	}
}

func TestSessionControllerMovesOnInputOwner(t *testing.T) {
	first := &sessionAttachment{}
	second := &sessionAttachment{}
	s := &LiveSession{Attached: map[*sessionAttachment]struct{}{first: {}, second: {}}}
	s.claimController(first)
	if !s.controllerIs(first) || s.controllerIs(second) {
		t.Fatal("first attachment should control the PTY")
	}
	s.claimController(second)
	if !s.controllerIs(second) || s.controllerIs(first) {
		t.Fatal("controller should move to the latest active attachment")
	}
}

func TestSessionOrderIsPerUserAndRejectsForeignSession(t *testing.T) {
	a := &App{live: map[string]*LiveSession{
		"a":       {ID: "a", UserID: 7, Order: 0, CreatedAt: time.Now()},
		"b":       {ID: "b", UserID: 7, Order: 1, CreatedAt: time.Now().Add(time.Second)},
		"foreign": {ID: "foreign", UserID: 8, Order: 0, CreatedAt: time.Now()},
	}}

	req := httptest.NewRequest(http.MethodPatch, "/api/sessions/order", strings.NewReader(`{"ids":["b","a"]}`))
	req = req.WithContext(context.WithValue(req.Context(), userCtxKey{}, int64(7)))
	rec := httptest.NewRecorder()
	a.sessionOrder(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("session order status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if got := a.live["b"].orderValue(); got != 0 {
		t.Fatalf("b order = %d, want 0", got)
	}
	if got := a.live["a"].orderValue(); got != 1 {
		t.Fatalf("a order = %d, want 1", got)
	}
	if got := a.live["foreign"].orderValue(); got != 0 {
		t.Fatalf("foreign session order changed to %d", got)
	}

	req = httptest.NewRequest(http.MethodPatch, "/api/sessions/order", strings.NewReader(`{"ids":["foreign"]}`))
	req = req.WithContext(context.WithValue(req.Context(), userCtxKey{}, int64(7)))
	rec = httptest.NewRecorder()
	a.sessionOrder(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("foreign session order status = %d, want 400", rec.Code)
	}
}
