package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestMediumOpenAppliesBusyTimeoutAndPoolLimit(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "medium.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if got := d.Stats().MaxOpenConnections; got != 16 {
		t.Fatalf("MaxOpenConnections=%d want=16", got)
	}
	ctx := context.Background()
	conns := make([]*sql.Conn, 0, 3)
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()
	for i := 0; i < 3; i++ {
		conn, err := d.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
		var timeout int
		if err := conn.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&timeout); err != nil {
			t.Fatal(err)
		}
		if timeout < 5000 {
			t.Fatalf("connection %d busy_timeout=%d want>=5000", i+1, timeout)
		}
	}
}
