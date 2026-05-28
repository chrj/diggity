package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/chrj/diggity/internal/check"
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

	Output      string
	Quiet       bool
	NoColor     bool
	TTLMin      time.Duration
	TTLMax      time.Duration
	ExpiryWarn  time.Duration
	ShowVersion bool

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
			if cfg.IPv4Only && cfg.IPv6Only {
				return &check.ExitError{Code: 3, Err: errors.New("--ipv4 and --ipv6 are mutually exclusive")}
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
	f.BoolVarP(&cfg.Quiet, "quiet", "q", false, "only print failures")
	f.BoolVar(&cfg.NoColor, "no-color", false, "disable ANSI colour")
	f.DurationVar(&cfg.TTLMin, "ttl-min", 60*time.Second, "warn below this TTL")
	f.DurationVar(&cfg.TTLMax, "ttl-max", 24*time.Hour, "warn above this TTL")
	f.DurationVar(&cfg.ExpiryWarn, "expiry-warn", 72*time.Hour, "warn if any RRSIG expires within this window")

	f.BoolVarP(&cfg.ShowVersion, "version", "V", false, "show version")

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
