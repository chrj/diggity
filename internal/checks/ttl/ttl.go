package ttl

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"

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

var defaultTypes = []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeA, dns.TypeAAAA, dns.TypeMX}

// Run samples TTLs for SOA, NS, A, AAAA, MX (plus any opts.ExtraTypes) at
// hostname. Findings warn when a TTL falls outside [opts.Min, opts.Max] or
// when sibling RRs disagree on TTL.
func Run(ctx context.Context, r resolver.RecursiveClient, hostname string, opts Options) check.Result {
	res := check.Result{Check: Name, Hostname: hostname}

	types := append([]uint16(nil), defaultTypes...)
	for _, t := range opts.ExtraTypes {
		if qt, ok := dns.StringToType[strings.ToUpper(t)]; ok {
			types = appendUnique(types, qt)
		} else {
			res.Findings = append(res.Findings, check.Finding{
				Status:  check.StatusWarn,
				Message: fmt.Sprintf("unknown record type %q", t),
			})
		}
	}

	var sampled int
	for _, qt := range types {
		ttls, src, err := sampleTTLs(ctx, r, hostname, qt)
		if err != nil {
			res.Findings = append(res.Findings, check.Finding{
				Status:  check.StatusWarn,
				Message: fmt.Sprintf("%s: query failed: %v", dns.TypeToString[qt], err),
			})
			continue
		}
		if len(ttls) == 0 {
			continue
		}
		sampled++

		unique := uniqueSorted(ttls)
		if len(unique) > 1 {
			res.Findings = append(res.Findings, check.Finding{
				Status:  check.StatusWarn,
				Message: fmt.Sprintf("%s%s sibling RRs disagree on TTL: %s", dns.TypeToString[qt], src, formatTTLs(unique)),
			})
		}

		minD := time.Duration(unique[0]) * time.Second
		maxD := time.Duration(unique[len(unique)-1]) * time.Second
		label := dns.TypeToString[qt] + src
		ttlText := formatTTLs(unique)

		switch {
		case minD < opts.Min:
			res.Findings = append(res.Findings, check.Finding{
				Status:  check.StatusWarn,
				Message: fmt.Sprintf("%s TTL %s below ttl-min %s", label, ttlText, opts.Min),
			})
		case maxD > opts.Max:
			res.Findings = append(res.Findings, check.Finding{
				Status:  check.StatusWarn,
				Message: fmt.Sprintf("%s TTL %s above ttl-max %s", label, ttlText, opts.Max),
			})
		default:
			res.Findings = append(res.Findings, check.Finding{
				Status:  check.StatusPass,
				Message: fmt.Sprintf("%s TTL %s", label, ttlText),
			})
		}
	}

	if sampled == 0 && len(res.Findings) == 0 {
		res.Findings = append(res.Findings, check.Finding{
			Status:  check.StatusWarn,
			Message: "no records sampled for any of the queried types",
		})
	}

	res.Status = check.Aggregate(res.Findings)
	return res
}

// sampleTTLs returns the TTLs found for qt at hostname. It first looks at
// the answer section; if empty, it falls back to records of the same type
// in the authority section (useful for SOA / NS at non-apex names, where
// the SOA's TTL represents the negative-caching TTL).
func sampleTTLs(ctx context.Context, r resolver.RecursiveClient, hostname string, qt uint16) ([]uint32, string, error) {
	msg, err := r.Resolve(ctx, hostname, qt)
	if err != nil {
		return nil, "", err
	}
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return nil, "", fmt.Errorf("rcode %s", dns.RcodeToString[msg.Rcode])
	}
	var out []uint32
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == qt {
			out = append(out, rr.Header().Ttl)
		}
	}
	if len(out) > 0 {
		return out, "", nil
	}
	for _, rr := range msg.Ns {
		if rr.Header().Rrtype == qt {
			out = append(out, rr.Header().Ttl)
		}
	}
	if len(out) > 0 {
		return out, " (negative cache)", nil
	}
	return nil, "", nil
}

func uniqueSorted(ttls []uint32) []uint32 {
	seen := map[uint32]struct{}{}
	var out []uint32
	for _, t := range ttls {
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func formatTTLs(ttls []uint32) string {
	parts := make([]string, len(ttls))
	for i, t := range ttls {
		parts[i] = (time.Duration(t) * time.Second).String()
	}
	return strings.Join(parts, ", ")
}

func appendUnique(list []uint16, qt uint16) []uint16 {
	for _, x := range list {
		if x == qt {
			return list
		}
	}
	return append(list, qt)
}
