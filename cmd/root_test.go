package cmd

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/chrj/diggity/internal/check"
	"github.com/chrj/diggity/internal/version"
)

func TestStripPorts(t *testing.T) {
	t.Parallel()

	got := stripPorts([]string{"1.1.1.1:53", "[2001:db8::1]:53", "resolver"})
	want := []string{"1.1.1.1", "2001:db8::1", "resolver"}

	if len(got) != len(want) {
		t.Fatalf("stripPorts length = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("stripPorts[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSkipped(t *testing.T) {
	t.Parallel()

	got := skipped("dnssec", "example.com")

	if got.Check != "dnssec" || got.Hostname != "example.com" || got.Status != check.StatusSkip {
		t.Fatalf("skipped() = %#v", got)
	}
	if len(got.Findings) != 1 || got.Findings[0].Message != "skipped" || got.Findings[0].Status != check.StatusSkip {
		t.Fatalf("skipped findings = %#v", got.Findings)
	}
}

func TestNewRootCmdRequiresHostname(t *testing.T) {
	t.Parallel()

	cmd, _ := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(nil)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() error = nil, want ExitError")
	}

	var exitErr *check.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("Execute() error = %T, want *check.ExitError", err)
	}
	if exitErr.Code != 3 {
		t.Fatalf("ExitError.Code = %d, want 3", exitErr.Code)
	}
	if !strings.Contains(out.String(), "diggity [flags] <hostname>...") {
		t.Fatalf("help output missing usage line: %q", out.String())
	}
}

func TestNewRootCmdVersion(t *testing.T) {
	orig := version.Version
	version.Version = "1.2.3"
	defer func() { version.Version = orig }()

	cmd, _ := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got, want := out.String(), "diggity 1.2.3\n"; got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}
