// Package runner handles subprocess execution for external tools. It provides
// timeout enforcement, stdout/stderr stream capture, and retry logic.
// The engine calls runner.Run() for each enricher invocation.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"time"
)

// ErrTimeout is returned when a tool exceeds its configured timeout.
var ErrTimeout = errors.New("tool execution timed out")

// Result holds the output of a subprocess execution.
type Result struct {
	Stdout   *bytes.Buffer
	Stderr   *bytes.Buffer
	ExitCode int
	Duration time.Duration
}

// RunConfig configures a single tool invocation.
type RunConfig struct {
	Bin     string        // path or name of the binary
	Args    []string      // expanded arguments
	Stdin   string        // optional data to pipe to the tool's stdin
	Timeout time.Duration // max execution time (0 = no timeout)
	Retries int           // number of retry attempts (0 = no retry)
}

// Runner executes external tools as subprocesses.
type Runner struct {
	logger *slog.Logger
}

// NewRunner creates a runner with the given logger.
func NewRunner(logger *slog.Logger) *Runner {
	return &Runner{logger: logger}
}

// Run executes a tool subprocess and captures its output streams.
// On timeout, the process is killed and ErrTimeout is returned.
// On non-zero exit, the result is still returned with the exit code
// so parsers can inspect stderr for partial results.
func (r *Runner) Run(ctx context.Context, cfg RunConfig) (*Result, error) {
	var lastErr error

	attempts := 1 + cfg.Retries
	for attempt := 1; attempt <= attempts; attempt++ {
		result, err := r.runOnce(ctx, cfg)
		if err == nil {
			return result, nil
		}
		lastErr = err

		if errors.Is(err, ErrTimeout) {
			r.logger.Warn("tool timed out",
				"bin", cfg.Bin,
				"attempt", attempt,
				"timeout", cfg.Timeout,
			)
		} else {
			r.logger.Warn("tool failed",
				"bin", cfg.Bin,
				"attempt", attempt,
				"error", err,
			)
		}

		// Don't retry on context cancellation.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		// Brief backoff between retries.
		if attempt < attempts {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}
	}

	return nil, fmt.Errorf("after %d attempts: %w", attempts, lastErr)
}

// runOnce executes a single subprocess attempt.
func (r *Runner) runOnce(ctx context.Context, cfg RunConfig) (*Result, error) {
	// Apply timeout if configured.
	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}

	start := time.Now()
	cmd := exec.CommandContext(ctx, cfg.Bin, cfg.Args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Pipe stdin if provided.
	if cfg.Stdin != "" {
		cmd.Stdin = bytes.NewBufferString(cfg.Stdin)
	}

	r.logger.Debug("running tool",
		"bin", cfg.Bin,
		"args", cfg.Args,
	)

	err := cmd.Run()
	duration := time.Since(start)

	result := &Result{
		Stdout:   &stdout,
		Stderr:   &stderr,
		Duration: duration,
	}

	if err != nil {
		// Check if it was a timeout.
		if ctx.Err() == context.DeadlineExceeded {
			return result, ErrTimeout
		}

		// Extract exit code from ExitError.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
			// Non-zero exit is not necessarily fatal — some tools use exit codes
			// for findings. Return the result so parsers can decide.
			r.logger.Debug("tool exited non-zero",
				"bin", cfg.Bin,
				"exit_code", result.ExitCode,
				"duration", duration,
			)
			return result, nil
		}

		// Other errors (binary not found, permission denied, etc.)
		return nil, fmt.Errorf("exec %s: %w", cfg.Bin, err)
	}

	r.logger.Debug("tool completed",
		"bin", cfg.Bin,
		"duration", duration,
		"stdout_bytes", stdout.Len(),
		"stderr_bytes", stderr.Len(),
	)

	return result, nil
}

// StdoutReader returns an io.Reader for the result's stdout.
// Convenience method for passing to parsers.
func (r *Result) StdoutReader() io.Reader {
	return bytes.NewReader(r.Stdout.Bytes())
}

// StderrReader returns an io.Reader for the result's stderr.
func (r *Result) StderrReader() io.Reader {
	return bytes.NewReader(r.Stderr.Bytes())
}
