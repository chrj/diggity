package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/chrj/diggity/internal/check"
	"github.com/chrj/diggity/internal/checks/consistency"
	"github.com/chrj/diggity/internal/checks/delegation"
	"github.com/chrj/diggity/internal/checks/dnssec"
	"github.com/chrj/diggity/internal/checks/ttl"
	"github.com/chrj/diggity/internal/output"
	"github.com/chrj/diggity/internal/resolver"
	"github.com/chrj/diggity/internal/trace"
	"github.com/chrj/diggity/internal/version"
)

// Config holds all parsed CLI flags.
type Config struct {
	NoDelegation  bool
	NoTTL         bool
	NoDNSSEC      bool
	NoConsistency bool

	Resolvers []string
	Trace     bool
	IPv4Only  bool
	IPv6Only  bool
	TCP       bool
	Timeout   time.Duration
	Retries   int
	Types     []string

	Output     string
	Verbose    bool
	Quiet      bool
	NoColor    bool
	TTLMin     time.Duration
	TTLMax     time.Duration
	ExpiryWarn time.Duration

	ShowVersion bool
	CheckUpdate bool

	Hostnames []string
}

const longDescription = `diggity walks the delegation chain for each hostname, compares NS records
at the parent and child, samples TTLs, and validates the DNSSEC chain of
trust from the root. It reports pass / warn / fail per check.

Exit codes:
  0  all checks passed
  1  warnings only
  2  one or more checks failed
  3  usage error
  4  network / resolver error before any check ran`

const examplesText = `  diggity example.com
  diggity --no-dnssec example.com sub.example.com
  diggity --trace example.com
  diggity -o json example.com | jq '.results[] | select(.status!="pass")'
  diggity -r 1.1.1.1 -r 8.8.8.8 example.com`

func newRootCmd() (*cobra.Command, *Config) {
	cfg := &Config{}

	cmd := &cobra.Command{
		Use:           "diggity [flags] <hostname>...",
		Short:         "DNS delegation, TTL & DNSSEC inspector",
		Long:          longDescription,
		Example:       examplesText,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(c *cobra.Command, args []string) error {
			if cfg.ShowVersion {
				fmt.Fprintln(c.OutOrStdout(), version.String())
				return nil
			}
			if len(args) == 0 {
				_ = c.Help()
				return &check.ExitError{Code: 3, Err: errors.New("at least one hostname is required")}
			}
			cfg.Hostnames = args
			return run(c.Context(), c.OutOrStdout(), cfg)
		},
	}

	f := cmd.Flags()

	f.BoolVar(&cfg.NoDelegation, "no-delegation", false, "skip the delegation check")
	f.BoolVar(&cfg.NoTTL, "no-ttl", false, "skip the TTL check")
	f.BoolVar(&cfg.NoDNSSEC, "no-dnssec", false, "skip the DNSSEC check")
	f.BoolVar(&cfg.NoConsistency, "no-consistency", false, "skip the authoritative-consistency check")

	f.StringSliceVarP(&cfg.Resolvers, "resolver", "r", nil, "resolver address (repeatable; default: system)")
	f.BoolVar(&cfg.Trace, "trace", false, "iterative walk from the root; print every hop")
	f.BoolVarP(&cfg.IPv4Only, "ipv4", "4", false, "restrict to IPv4 transport")
	f.BoolVarP(&cfg.IPv6Only, "ipv6", "6", false, "restrict to IPv6 transport")
	f.BoolVar(&cfg.TCP, "tcp", false, "force TCP")
	f.DurationVar(&cfg.Timeout, "timeout", 3*time.Second, "per-query timeout")
	f.IntVar(&cfg.Retries, "retries", 2, "retries per query")
	f.StringSliceVarP(&cfg.Types, "type", "t", nil, "extra record type(s) to sample (repeatable)")

	f.StringVarP(&cfg.Output, "output", "o", "text", "output format: text | json | ndjson | sarif")
	f.BoolVarP(&cfg.Verbose, "verbose", "v", false, "show every query and response")
	f.BoolVarP(&cfg.Quiet, "quiet", "q", false, "only print failures")
	f.BoolVar(&cfg.NoColor, "no-color", false, "disable ANSI colour")
	f.DurationVar(&cfg.TTLMin, "ttl-min", 60*time.Second, "warn below this TTL")
	f.DurationVar(&cfg.TTLMax, "ttl-max", 24*time.Hour, "warn above this TTL")
	f.DurationVar(&cfg.ExpiryWarn, "expiry-warn", 72*time.Hour, "warn if any RRSIG expires within this window")

	f.BoolVarP(&cfg.ShowVersion, "version", "V", false, "show version")
	f.BoolVar(&cfg.CheckUpdate, "check-update", false, "check for a newer release")

	return cmd, cfg
}

// Execute parses arguments and runs the root command.
func Execute() error {
	rootCmd, _ := newRootCmd()
	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)
	if err := rootCmd.ExecuteContext(context.Background()); err != nil {
		var ce *check.ExitError
		if errors.As(err, &ce) {
			return err
		}
		return &check.ExitError{Code: 3, Err: err}
	}
	return nil
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

	if cfg.Trace {
		for _, host := range cfg.Hostnames {
			hops := trace.Walk(ctx, r, host)
			trace.Render(os.Stderr, host, hops)
		}
	}

	var report check.Report
	for _, host := range cfg.Hostnames {
		report.Results = append(report.Results, runChecks(ctx, r, host, cfg)...)
	}

	for _, res := range report.Results {
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

	w, err := output.New(cfg.Output)
	if err != nil {
		return &check.ExitError{Code: 3, Err: err}
	}
	if tw, ok := w.(*output.TextWriter); ok {
		tw.NoColor = cfg.NoColor
		tw.Quiet = cfg.Quiet
	}
	if err := w.Write(out, report); err != nil {
		return err
	}

	if used, from, to := r.FallbackInfo(); used {
		fmt.Fprintf(os.Stderr, "diggity: %s refused DNSSEC queries; used %s instead (override with -r)\n",
			strings.Join(stripPorts(from), ", "), strings.Join(stripPorts(to), ", "))
	}

	switch {
	case report.Summary.Fail > 0:
		return &check.ExitError{Code: 2}
	case report.Summary.Warn > 0:
		return &check.ExitError{Code: 1}
	}
	return nil
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

func runChecks(ctx context.Context, r *resolver.Resolver, host string, cfg *Config) []check.Result {
	var results []check.Result

	if cfg.NoDelegation {
		results = append(results, skipped(delegation.Name, host))
	} else {
		results = append(results, delegation.Run(ctx, r, host))
	}

	if cfg.NoTTL {
		results = append(results, skipped(ttl.Name, host))
	} else {
		results = append(results, ttl.Run(ctx, r, host, ttl.Options{
			Min:        cfg.TTLMin,
			Max:        cfg.TTLMax,
			ExtraTypes: cfg.Types,
		}))
	}

	if cfg.NoDNSSEC {
		results = append(results, skipped(dnssec.Name, host))
	} else {
		results = append(results, dnssec.Run(ctx, r, host, dnssec.Options{
			ExpiryWarn: cfg.ExpiryWarn,
		}))
	}

	if cfg.NoConsistency {
		results = append(results, skipped(consistency.Name, host))
	} else {
		results = append(results, consistency.Run(ctx, r, host))
	}

	return results
}

func skipped(name, host string) check.Result {
	return check.Result{
		Check:    name,
		Hostname: host,
		Status:   check.StatusSkip,
		Findings: []check.Finding{{Status: check.StatusSkip, Message: "skipped"}},
	}
}
