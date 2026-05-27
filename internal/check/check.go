package check

import "fmt"

// Status is the outcome of a single check or finding.
type Status int

const (
	StatusPass Status = iota
	StatusWarn
	StatusFail
	StatusSkip
)

func (s Status) String() string {
	switch s {
	case StatusPass:
		return "pass"
	case StatusWarn:
		return "warn"
	case StatusFail:
		return "fail"
	case StatusSkip:
		return "skip"
	}
	return "unknown"
}

// MarshalJSON renders Status as its string form.
func (s Status) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// Finding is a single observation from a check.
type Finding struct {
	Status  Status `json:"status"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

// Result is the output of running one check against one hostname.
type Result struct {
	Check    string    `json:"check"`
	Hostname string    `json:"hostname"`
	Status   Status    `json:"status"`
	Findings []Finding `json:"findings,omitempty"`
}

// Report aggregates the results of every check across every hostname.
type Report struct {
	Results []Result `json:"results"`
	Summary Summary  `json:"summary"`
}

// Summary counts findings by status across the whole report.
type Summary struct {
	Pass int `json:"pass"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
	Skip int `json:"skip"`
}

// ExitError carries an explicit process exit code out of cmd.Execute.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit %d", e.Code)
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error { return e.Err }
