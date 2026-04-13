package runner

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"
)

func TestRunnerTimeoutReturnsErrTimeout(t *testing.T) {
	r := NewRunner(slog.Default())
	_, err := r.Run(context.Background(), RunConfig{
		Bin:     "/bin/sh",
		Args:    []string{"-c", "sleep 0.2"},
		Timeout: 10 * time.Millisecond,
	})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected ErrTimeout, got %v", err)
	}
}

func TestRunnerMissingBinaryReturnsExecError(t *testing.T) {
	r := NewRunner(slog.Default())
	_, err := r.Run(context.Background(), RunConfig{Bin: "this-binary-should-not-exist-xyz"})
	var execErr *ExecError
	if !errors.As(err, &execErr) {
		t.Fatalf("expected ExecError, got %v", err)
	}
}

func TestRunnerNonZeroExitReturnsResultNoError(t *testing.T) {
	r := NewRunner(slog.Default())
	res, err := r.Run(context.Background(), RunConfig{Bin: "/bin/sh", Args: []string{"-c", "echo hi; exit 7"}})
	if err != nil {
		t.Fatalf("expected nil error for non-zero exit, got %v", err)
	}
	if res.ExitCode != 7 {
		t.Fatalf("expected exit code 7, got %d", res.ExitCode)
	}
}
