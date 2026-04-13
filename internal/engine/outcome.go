package engine

import (
	"errors"

	"github.com/resistanceisuseless/autotron/internal/runner"
)

type jobOutcome string

const (
	jobOutcomeSuccess   jobOutcome = "success"
	jobOutcomeNoData    jobOutcome = "no_data"
	jobOutcomeTransient jobOutcome = "transient_error"
	jobOutcomeFatal     jobOutcome = "fatal_error"
)

func classifyRunError(err error) jobOutcome {
	if err == nil {
		return jobOutcomeSuccess
	}
	if errors.Is(err, runner.ErrTimeout) {
		return jobOutcomeTransient
	}
	var execErr *runner.ExecError
	if errors.As(err, &execErr) {
		return jobOutcomeFatal
	}
	return jobOutcomeTransient
}

func classifyParseError(err error) jobOutcome {
	if err == nil {
		return jobOutcomeSuccess
	}
	return jobOutcomeFatal
}
