package ttl

import (
	"context"
	"time"

	"github.com/chrj/diggity/internal/check"
	"github.com/chrj/diggity/internal/resolver"
)

// Name is the identifier used in reports.
const Name = "ttl"

// Options controls TTL warning thresholds.
type Options struct {
	Min        time.Duration
	Max        time.Duration
	ExtraTypes []string
}

// Run samples TTLs for SOA, NS, A, AAAA, MX (plus any opts.ExtraTypes) and
// warns when a TTL falls outside [opts.Min, opts.Max] or when sibling RRs
// disagree.
func Run(_ context.Context, _ *resolver.Resolver, hostname string, _ Options) check.Result {
	return check.Result{
		Check:    Name,
		Hostname: hostname,
		Status:   check.StatusSkip,
		Findings: []check.Finding{{
			Status:  check.StatusSkip,
			Message: "TTL check not implemented yet",
		}},
	}
}
