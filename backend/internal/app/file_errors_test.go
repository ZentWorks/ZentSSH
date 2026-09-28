package app

import (
	"errors"
	"fmt"
	"os"
	"testing"
)

func TestIsPermissionDeniedError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "os permission", err: os.ErrPermission, want: true},
		{name: "wrapped permission", err: fmt.Errorf("remote write: %w", os.ErrPermission), want: true},
		{name: "sftp permission text", err: errors.New("sftp: permission denied"), want: true},
		{name: "operation not permitted", err: errors.New("operation not permitted"), want: true},
		{name: "unrelated", err: errors.New("connection reset by peer"), want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isPermissionDeniedError(test.err); got != test.want {
				t.Fatalf("isPermissionDeniedError(%v) = %v, want %v", test.err, got, test.want)
			}
		})
	}
}
