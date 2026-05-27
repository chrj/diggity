package dnssec

import (
	"context"
	"time"

	"github.com/chrj/diggity/internal/check"
	"github.com/chrj/diggity/internal/resolver"
)

// Name is the identifier used in reports.
const Name = "dnssec"

// Options controls DNSSEC validation behaviour.
type Options struct {
	ExpiryWarn time.Duration
}

// Run validates the DNSSEC chain of trust for hostname.
//
// Planned behaviour:
//   - fetch DS at the parent and DNSKEY at the child; verify each DS digest
//   - verify RRSIGs over DNSKEY, SOA, and sampled RRsets
//   - walk DS/DNSKEY upward to the root and validate against the bundled
//     IANA root trust anchor in trustanchor.go
//   - flag deprecated algorithms, undersized keys, and signatures expiring
//     within opts.ExpiryWarn
//   - verify NSEC/NSEC3 proof of non-existence for a synthesised name
//   - "unsigned" (no DS at parent) is a pass with a note, not a fail
func Run(_ context.Context, _ *resolver.Resolver, hostname string, _ Options) check.Result {
	return check.Result{
		Check:    Name,
		Hostname: hostname,
		Status:   check.StatusSkip,
		Findings: []check.Finding{{
			Status:  check.StatusSkip,
			Message: "DNSSEC check not implemented yet",
		}},
	}
}
