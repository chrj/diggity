package consistency

import (
	"context"

	"github.com/chrj/diggity/internal/check"
	"github.com/chrj/diggity/internal/resolver"
)

// Name is the identifier used in reports.
const Name = "consistency"

// Run queries every authoritative NS for SOA, NS, A, and AAAA of hostname
// and verifies that every server returns identical answers and serials.
func Run(_ context.Context, _ *resolver.Resolver, hostname string) check.Result {
	return check.Result{
		Check:    Name,
		Hostname: hostname,
		Status:   check.StatusSkip,
		Findings: []check.Finding{{
			Status:  check.StatusSkip,
			Message: "consistency check not implemented yet",
		}},
	}
}
