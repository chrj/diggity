package check

import (
	"errors"
	"testing"
)

func TestStatusStringAndMarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status Status
		text   string
	}{
		{StatusPass, "pass"},
		{StatusWarn, "warn"},
		{StatusFail, "fail"},
		{StatusSkip, "skip"},
		{Status(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.status.String(); got != tt.text {
			t.Fatalf("Status(%d).String() = %q, want %q", tt.status, got, tt.text)
		}
		raw, err := tt.status.MarshalJSON()
		if err != nil {
			t.Fatalf("Status(%d).MarshalJSON() error = %v", tt.status, err)
		}
		if got, want := string(raw), `"`+tt.text+`"`; got != want {
			t.Fatalf("Status(%d).MarshalJSON() = %q, want %q", tt.status, got, want)
		}
	}
}

func TestAggregateIgnoresSkip(t *testing.T) {
	t.Parallel()

	got := Aggregate([]Finding{
		{Status: StatusSkip},
		{Status: StatusPass},
		{Status: StatusWarn},
		{Status: StatusSkip},
	})

	if got != StatusWarn {
		t.Fatalf("Aggregate() = %v, want %v", got, StatusWarn)
	}
}

func TestFailReplacesFindings(t *testing.T) {
	t.Parallel()

	res := Fail(Result{
		Check:    "ttl",
		Hostname: "example.com",
		Status:   StatusPass,
		Findings: []Finding{{Status: StatusPass, Message: "ok"}},
	}, "boom")

	if res.Status != StatusFail {
		t.Fatalf("Fail().Status = %v, want %v", res.Status, StatusFail)
	}
	if len(res.Findings) != 1 || res.Findings[0].Message != "boom" || res.Findings[0].Status != StatusFail {
		t.Fatalf("Fail().Findings = %#v", res.Findings)
	}
}

func TestExitErrorErrorAndUnwrap(t *testing.T) {
	t.Parallel()

	cause := errors.New("usage")
	err := &ExitError{Code: 3, Err: cause}

	if got := err.Error(); got != "usage" {
		t.Fatalf("Error() = %q, want %q", got, "usage")
	}
	if !errors.Is(err, cause) {
		t.Fatal("errors.Is(ExitError, cause) = false, want true")
	}

	if got := (&ExitError{Code: 2}).Error(); got != "exit 2" {
		t.Fatalf("Error() without cause = %q, want %q", got, "exit 2")
	}
}
