package delegation

import (
	"context"

	"github.com/chrj/diggity/internal/check"
	"github.com/chrj/diggity/internal/resolver"
)

// Name is the identifier used in reports.
const Name = "delegation"

// Run performs the delegation check for hostname using r.
//
// Planned behaviour:
//   - find the parent zone by walking up labels until an SOA is found
//   - fetch NS at the parent and at each authoritative server directly
//   - compare sets exactly; report missing-at-parent and missing-at-child
//   - require glue A/AAAA for in-bailiwick NS and that it matches the child
//   - require UDP/53 + TCP/53 reachability and the AA bit at every NS
//   - detect lame delegation (NS listed but not authoritative)
func Run(_ context.Context, _ *resolver.Resolver, hostname string) check.Result {
	return check.Result{
		Check:    Name,
		Hostname: hostname,
		Status:   check.StatusSkip,
		Findings: []check.Finding{{
			Status:  check.StatusSkip,
			Message: "delegation check not implemented yet",
		}},
	}
}
