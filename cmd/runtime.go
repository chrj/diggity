package cmd

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/mattn/go-isatty"

	"github.com/chrj/diggity/internal/check"
	"github.com/chrj/diggity/internal/checks/consistency"
	"github.com/chrj/diggity/internal/checks/delegation"
	"github.com/chrj/diggity/internal/checks/dnssec"
	"github.com/chrj/diggity/internal/checks/ttl"
	"github.com/chrj/diggity/internal/output"
	"github.com/chrj/diggity/internal/resolver"
	"github.com/chrj/diggity/internal/trace"
)

type fallbackAware interface {
	FallbackInfo() (used bool, from, to []string)
}

type runtimeQuerier interface {
	resolver.Querier
	fallbackAware
}

type traceWalker func(context.Context, resolver.Querier, string) []trace.Hop
type traceRenderer func(io.Writer, string, []trace.Hop)

type runtimeDeps struct {
	errOut io.Writer
	walk   traceWalker
	render traceRenderer
}

func run(ctx context.Context, out io.Writer, cfg *Config) error {
	r := resolver.New(resolver.Config{
		Resolvers: cfg.Resolvers,
		Timeout:   cfg.Timeout,
		Retries:   cfg.Retries,
		TCP:       cfg.TCP,
		IPv4Only:  cfg.IPv4Only,
		IPv6Only:  cfg.IPv6Only,
		Trace:     cfg.Trace,
	})
	return runWithResolver(ctx, out, cfg, r, runtimeDeps{
		errOut: os.Stderr,
		walk:   trace.Walk,
		render: trace.Render,
	})
}

func runWithResolver(ctx context.Context, out io.Writer, cfg *Config, r runtimeQuerier, deps runtimeDeps) error {
	renderTraces(ctx, cfg, r, deps)
	report, exitCode := buildReport(ctx, r, cfg)
	w, err := output.New(cfg.Output)
	if err != nil {
		return &check.ExitError{Code: 3, Err: err}
	}
	if tw, ok := w.(*output.TextWriter); ok {
		tw.Color = !cfg.NoColor && isTerminal(out)
		tw.Unicode = tw.Color && localeIsUTF8()
		tw.Quiet = cfg.Quiet
	}
	if err := w.Write(out, report); err != nil {
		return err
	}
	if msg, ok := fallbackMessage(r); ok {
		_, _ = fmt.Fprintln(deps.errOut, msg)
	}
	if exitCode != 0 {
		return &check.ExitError{Code: exitCode}
	}
	return nil
}

func buildReport(ctx context.Context, r resolver.Querier, cfg *Config) (check.Report, int) {
	var results []check.Result
	for _, host := range cfg.Hostnames {
		results = append(results, runChecks(ctx, r, host, cfg)...)
	}
	report := reportFromResults(results)
	return report, exitCodeForReport(report)
}

// reportFromResults summarizes per-check results into a report-wide status
// count so rendering and exit-code selection can share one source of truth.
func reportFromResults(results []check.Result) check.Report {
	report := check.Report{Results: results}
	for _, res := range results {
		switch res.Status {
		case check.StatusPass:
			report.Summary.Pass++
		case check.StatusWarn:
			report.Summary.Warn++
		case check.StatusFail:
			report.Summary.Fail++
		case check.StatusSkip:
			report.Summary.Skip++
		}
	}
	return report
}

func exitCodeForReport(report check.Report) int {
	switch {
	case report.Summary.Fail > 0:
		return 2
	case report.Summary.Warn > 0:
		return 1
	default:
		return 0
	}
}

func renderTraces(ctx context.Context, cfg *Config, r resolver.Querier, deps runtimeDeps) {
	if !cfg.Trace {
		return
	}
	for _, host := range cfg.Hostnames {
		deps.render(deps.errOut, host, deps.walk(ctx, r, host))
	}
}

// fallbackMessage formats the resolver fallback notice once, so the runtime
// can keep stderr output decisions separate from fallback detection.
func fallbackMessage(r fallbackAware) (string, bool) {
	used, from, to := r.FallbackInfo()
	if !used {
		return "", false
	}
	return fmt.Sprintf("diggity: %s refused DNSSEC queries; used %s instead (override with -r)",
		strings.Join(stripPorts(from), ", "), strings.Join(stripPorts(to), ", ")), true
}

// isTerminal reports whether w is a terminal stdout/stderr. It returns false
// for buffers, files, and pipes so coloured/Unicode output stays out of
// captured logs.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
}

// localeIsUTF8 reports whether the user's locale advertises UTF-8 so the
// renderer can use box-drawing and glyph characters without garbling
// terminals stuck on legacy encodings.
func localeIsUTF8() bool {
	for _, key := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		v := os.Getenv(key)
		if v == "" {
			continue
		}
		v = strings.ToUpper(v)
		return strings.Contains(v, "UTF-8") || strings.Contains(v, "UTF8")
	}
	return false
}

func stripPorts(addrs []string) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		if host, _, err := net.SplitHostPort(a); err == nil {
			out[i] = host
		} else {
			out[i] = a
		}
	}
	return out
}

func runChecks(ctx context.Context, r resolver.Querier, host string, cfg *Config) []check.Result {
	var results []check.Result

	if cfg.NoDelegation {
		results = append(results, check.Skip(delegation.Name, host, "skipped"))
	} else {
		results = append(results, delegation.Run(ctx, r, host))
	}

	if cfg.NoTTL {
		results = append(results, check.Skip(ttl.Name, host, "skipped"))
	} else {
		results = append(results, ttl.Run(ctx, r, host, ttl.Options{
			Min:        cfg.TTLMin,
			Max:        cfg.TTLMax,
			ExtraTypes: cfg.Types,
		}))
	}

	if cfg.NoDNSSEC {
		results = append(results, check.Skip(dnssec.Name, host, "skipped"))
	} else {
		results = append(results, dnssec.Run(ctx, r, host, dnssec.Options{
			ExpiryWarn: cfg.ExpiryWarn,
		}))
	}

	if cfg.NoConsistency {
		results = append(results, check.Skip(consistency.Name, host, "skipped"))
	} else {
		results = append(results, consistency.Run(ctx, r, host))
	}

	return results
}
