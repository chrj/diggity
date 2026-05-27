package consistency

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"

	"github.com/chrj/diggity/internal/check"
	"github.com/chrj/diggity/internal/dnsutil"
	"github.com/chrj/diggity/internal/resolver"
)

// Name is the identifier used in reports.
const Name = "consistency"

// Run queries every authoritative NS for SOA, NS, A, and AAAA of hostname
// and verifies that every server returns identical answers and serials.
func Run(ctx context.Context, r resolver.Querier, hostname string) check.Result {
	res := check.NewResult(Name, hostname)

	zone, err := dnsutil.FindZone(ctx, r, hostname)
	if err != nil {
		return check.Fail(res, fmt.Sprintf("could not find zone for %s: %v", hostname, err))
	}

	nsHosts, err := dnsutil.AuthoritativeNSHosts(ctx, r, zone)
	if err != nil {
		return check.Fail(res, fmt.Sprintf("could not list authoritative NS for %s: %v", dnsutil.TrimDot(zone), err))
	}
	if len(nsHosts) < 2 {
		return check.Skip(Name, hostname, fmt.Sprintf("only %d NS authoritative for %s — nothing to compare", len(nsHosts), dnsutil.TrimDot(zone)))
	}
	targets, _ := dnsutil.ResolveNameServerTargets(ctx, r, nsHosts, nil)

	var findings []check.Finding
	snapshots := map[string]snapshot{}
	for _, t := range targets {
		label := fmt.Sprintf("%s/%s", dnsutil.TrimDot(t.Host), t.IP)
		snap, err := takeSnapshot(ctx, r, t.Addr, zone, hostname)
		if err != nil {
			findings = append(findings, check.Finding{
				Status:  check.StatusWarn,
				Message: fmt.Sprintf("%s excluded from comparison: %v", label, err),
			})
			continue
		}
		snap.family = t.Family
		snapshots[label] = snap
	}

	if len(snapshots) < 2 {
		findings = append(findings, check.Finding{
			Status:  check.StatusFail,
			Message: fmt.Sprintf("only %d authoritative server(s) usable for comparison", len(snapshots)),
		})
		return check.Finalize(res, findings)
	}

	findings = append(findings,
		compareField(snapshots, "SOA serial", func(s snapshot) string { return fmt.Sprintf("%d", s.serial) }),
		compareField(snapshots, fmt.Sprintf("NS %s", dnsutil.TrimDot(zone)), func(s snapshot) string { return s.ns }),
		compareField(snapshots, fmt.Sprintf("A %s", hostname), func(s snapshot) string { return s.a }),
		compareField(snapshots, fmt.Sprintf("AAAA %s", hostname), func(s snapshot) string { return s.aaaa }),
	)

	return check.Finalize(res, findings)
}

type snapshot struct {
	serial uint32
	ns     string
	a      string
	aaaa   string
	family int
}

// takeSnapshot queries server for SOA + NS at zone and A + AAAA at hostname.
// The server must set the AA bit on the SOA response; otherwise the response
// is not authoritative and the server is excluded from the comparison.
func takeSnapshot(ctx context.Context, r resolver.Querier, server, zone, hostname string) (snapshot, error) {
	var snap snapshot

	soaMsg, err := r.Query(ctx, server, dnsutil.TrimDot(zone), dns.TypeSOA)
	if err != nil {
		return snap, err
	}
	if soaMsg.Rcode != dns.RcodeSuccess {
		return snap, fmt.Errorf("SOA rcode %s", dns.RcodeToString[soaMsg.Rcode])
	}
	if !soaMsg.Authoritative {
		return snap, fmt.Errorf("did not set AA bit")
	}
	if soa := dnsutil.FirstSOA(soaMsg); soa != nil {
		snap.serial = soa.Serial
	}

	nsMsg, err := r.Query(ctx, server, dnsutil.TrimDot(zone), dns.TypeNS)
	if err != nil {
		return snap, err
	}
	snap.ns = canonicalNames(dnsutil.NSHostnames(nsMsg))

	if aMsg, err := r.Query(ctx, server, hostname, dns.TypeA); err == nil {
		snap.a = canonicalIPs(dnsutil.AnswerIPs(aMsg, dns.TypeA))
	}
	if aaaaMsg, err := r.Query(ctx, server, hostname, dns.TypeAAAA); err == nil {
		snap.aaaa = canonicalIPs(dnsutil.AnswerIPs(aaaaMsg, dns.TypeAAAA))
	}

	return snap, nil
}

func canonicalNames(names []string) string {
	names = append([]string(nil), names...)
	for i, name := range names {
		names[i] = strings.ToLower(dns.Fqdn(name))
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

func canonicalIPs(addrs []net.IP) string {
	if len(addrs) == 0 {
		return ""
	}
	var texts []string
	for _, ip := range addrs {
		texts = append(texts, ip.String())
	}
	sort.Strings(texts)
	return strings.Join(texts, ",")
}

func compareField(snapshots map[string]snapshot, fieldName string, getter func(snapshot) string) check.Finding {
	grouped := map[string][]string{}
	for label, snap := range snapshots {
		grouped[getter(snap)] = append(grouped[getter(snap)], label)
	}

	if len(grouped) == 1 {
		var value string
		for k := range grouped {
			value = k
		}
		display := displayValue(value)
		if display == "" {
			display = "(no records)"
		}
		return check.Finding{
			Status:  check.StatusPass,
			Message: fmt.Sprintf("all servers agree on %s: %s", fieldName, display),
		}
	}

	// Detect topology-aware DNS: each IP family is internally consistent
	// but the two families disagree. That is usually a CDN routing decision
	// (Akamai, geo-DNS, etc.), not real zone-data drift, so downgrade to WARN.
	if v4Ans, v6Ans, ok := v4v6Split(snapshots, getter); ok {
		return check.Finding{
			Status:  check.StatusWarn,
			Message: fmt.Sprintf("%s differs by transport — looks like topology-aware DNS / CDN, not zone drift", fieldName),
			Detail:  fmt.Sprintf("via IPv4 → %s\nvia IPv6 → %s", displayOr(v4Ans), displayOr(v6Ans)),
		}
	}

	var lines []string
	for value, servers := range grouped {
		sort.Strings(servers)
		display := displayValue(value)
		if display == "" {
			display = "(no records)"
		}
		lines = append(lines, fmt.Sprintf("%s — %s", display, strings.Join(servers, ", ")))
	}
	sort.Strings(lines)
	return check.Finding{
		Status:  check.StatusFail,
		Message: fmt.Sprintf("servers disagree on %s", fieldName),
		Detail:  strings.Join(lines, "\n"),
	}
}

// v4v6Split reports whether the answers across snapshots split cleanly along
// IP transport: every v4-contacted server returned the same value, every
// v6-contacted server returned the same value, and the two values differ.
// Both families must be represented for the pattern to match.
func v4v6Split(snapshots map[string]snapshot, getter func(snapshot) string) (string, string, bool) {
	v4Answers := map[string]struct{}{}
	v6Answers := map[string]struct{}{}
	var v4Count, v6Count int
	for _, snap := range snapshots {
		switch snap.family {
		case 4:
			v4Answers[getter(snap)] = struct{}{}
			v4Count++
		case 6:
			v6Answers[getter(snap)] = struct{}{}
			v6Count++
		}
	}
	if v4Count == 0 || v6Count == 0 {
		return "", "", false
	}
	if len(v4Answers) != 1 || len(v6Answers) != 1 {
		return "", "", false
	}
	var v4, v6 string
	for a := range v4Answers {
		v4 = a
	}
	for a := range v6Answers {
		v6 = a
	}
	if v4 == v6 {
		return "", "", false
	}
	return v4, v6, true
}

func displayOr(v string) string {
	d := displayValue(v)
	if d == "" {
		return "(no records)"
	}
	return d
}

func displayValue(v string) string {
	if v == "" {
		return ""
	}
	return strings.ReplaceAll(v, ",", ", ")
}
