package engine

import (
	"errors"
	"os/exec"
	"testing"

	"github.com/resistanceisuseless/autotron/internal/runner"
)

func TestClassifyRunError(t *testing.T) {
	if got := classifyRunError(nil); got != jobOutcomeSuccess {
		t.Fatalf("expected success, got %s", got)
	}

	if got := classifyRunError(runner.ErrTimeout); got != jobOutcomeTransient {
		t.Fatalf("expected transient for timeout, got %s", got)
	}

	execErr := &runner.ExecError{Bin: "missing", Err: &exec.Error{Name: "missing", Err: errors.New("not found")}}
	if got := classifyRunError(execErr); got != jobOutcomeFatal {
		t.Fatalf("expected fatal for exec error, got %s", got)
	}
}

func TestClassifyParseError(t *testing.T) {
	if got := classifyParseError(nil); got != jobOutcomeSuccess {
		t.Fatalf("expected success, got %s", got)
	}
	if got := classifyParseError(errors.New("decode EOF")); got != jobOutcomeFatal {
		t.Fatalf("expected fatal parse classification, got %s", got)
	}
}
