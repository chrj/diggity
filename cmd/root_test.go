package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/chrj/diggity/internal/check"
	"github.com/chrj/diggity/internal/resolver"
	"github.com/chrj/diggity/internal/trace"
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

func TestBuildReportAndRunWithResolver(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Hostnames:     []string{"example.com"},
		Trace:         true,
		Output:        "text",
		NoColor:       true,
		NoDelegation:  true,
		NoTTL:         true,
		NoDNSSEC:      true,
		NoConsistency: true,
	}
	r := &fakeRunResolver{
		fallbackUsed: true,
		fallbackFrom: []string{"127.0.0.53:53"},
		fallbackTo:   []string{"1.1.1.1:53", "8.8.8.8:53"},
	}

	report, exitCode := buildReport(context.Background(), r, cfg)
	if report.Summary.Skip != 4 || exitCode != 0 {
		t.Fatalf("buildReport() = summary %#v exitCode %d", report.Summary, exitCode)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	var walked []string
	err := runWithResolver(
		context.Background(),
		&out,
		cfg,
		r,
		runtimeDeps{
			errOut: &errOut,
			walk: func(_ context.Context, _ resolver.Querier, host string) []trace.Hop {
				walked = append(walked, host)
				return []trace.Hop{{}}
			},
			render: func(w io.Writer, host string, _ []trace.Hop) {
				_, _ = io.WriteString(w, "trace "+host+"\n")
			},
		},
	)
	if err != nil {
		t.Fatalf("runWithResolver() error = %v", err)
	}
	if len(walked) != 1 || walked[0] != "example.com" {
		t.Fatalf("trace walk calls = %#v", walked)
	}
	if !strings.Contains(out.String(), "summary: 0 pass, 0 warn, 0 fail, 4 skip") {
		t.Fatalf("run output = %q", out.String())
	}
	if !strings.Contains(errOut.String(), "trace example.com") {
		t.Fatalf("trace stderr = %q", errOut.String())
	}
	if !strings.Contains(errOut.String(), "127.0.0.53 refused DNSSEC queries; used 1.1.1.1, 8.8.8.8 instead") {
		t.Fatalf("fallback stderr = %q", errOut.String())
	}
}

func TestExitCodeForReport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		report check.Report
		want   int
	}{
		{report: check.Report{Summary: check.Summary{Pass: 1}}, want: 0},
		{report: check.Report{Summary: check.Summary{Warn: 1}}, want: 1},
		{report: check.Report{Summary: check.Summary{Fail: 1}}, want: 2},
	}

	for _, tt := range tests {
		if got := exitCodeForReport(tt.report); got != tt.want {
			t.Fatalf("exitCodeForReport(%#v) = %d, want %d", tt.report.Summary, got, tt.want)
		}
	}
}

type fakeRunResolver struct {
	fallbackUsed bool
	fallbackFrom []string
	fallbackTo   []string
}

func (*fakeRunResolver) Resolve(context.Context, string, uint16) (*dns.Msg, error) {
	return nil, errors.New("unexpected Resolve call")
}

func (*fakeRunResolver) Query(context.Context, string, string, uint16) (*dns.Msg, error) {
	return nil, errors.New("unexpected Query call")
}

func (*fakeRunResolver) QueryTCP(context.Context, string, string, uint16) (*dns.Msg, error) {
	return nil, errors.New("unexpected QueryTCP call")
}

func (f *fakeRunResolver) FallbackInfo() (bool, []string, []string) {
	return f.fallbackUsed, append([]string(nil), f.fallbackFrom...), append([]string(nil), f.fallbackTo...)
}
