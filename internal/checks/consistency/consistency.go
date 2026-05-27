package consistency

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"

	"github.com/chrj/diggity/internal/check"
	"github.com/chrj/diggity/internal/resolver"
)

// Name is the identifier used in reports.
const Name = "consistency"

// Run queries every authoritative NS for SOA, NS, A, and AAAA of hostname
// and verifies that every server returns identical answers and serials.
func Run(ctx context.Context, r *resolver.Resolver, hostname string) check.Result {
	res := check.Result{Check: Name, Hostname: hostname}

	zone, err := findZone(ctx, r, hostname)
	if err != nil {
		return fail(res, fmt.Sprintf("could not find zone for %s: %v", hostname, err))
	}

	nsHosts, err := authoritativeNSHosts(ctx, r, zone)
	if err != nil {
		return fail(res, fmt.Sprintf("could not list authoritative NS for %s: %v", trimDot(zone), err))
	}
	if len(nsHosts) < 2 {
		return check.Result{
			Check:    Name,
			Hostname: hostname,
			Status:   check.StatusSkip,
			Findings: []check.Finding{{
				Status:  check.StatusSkip,
				Message: fmt.Sprintf("only %d NS authoritative for %s — nothing to compare", len(nsHosts), trimDot(zone)),
			}},
		}
	}

	type target struct {
		label  string
		addr   string
		family int // 4 or 6 — IP family of the NS address contacted
	}
	var targets []target
	for _, host := range nsHosts {
		ips, err := resolveIPs(ctx, r, host)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			fam := 4
			if ip.To4() == nil {
				fam = 6
			}
			targets = append(targets, target{
				label:  fmt.Sprintf("%s/%s", trimDot(host), ip),
				addr:   net.JoinHostPort(ip.String(), "53"),
				family: fam,
			})
		}
	}

	var findings []check.Finding
	snapshots := map[string]snapshot{}
	for _, t := range targets {
		snap, err := takeSnapshot(ctx, r, t.addr, zone, hostname)
		if err != nil {
			findings = append(findings, check.Finding{
				Status:  check.StatusWarn,
				Message: fmt.Sprintf("%s excluded from comparison: %v", t.label, err),
			})
			continue
		}
		snap.family = t.family
		snapshots[t.label] = snap
	}

	if len(snapshots) < 2 {
		findings = append(findings, check.Finding{
			Status:  check.StatusFail,
			Message: fmt.Sprintf("only %d authoritative server(s) usable for comparison", len(snapshots)),
		})
		res.Findings = findings
		res.Status = aggregateStatus(findings)
		return res
	}

	findings = append(findings,
		compareField(snapshots, "SOA serial", func(s snapshot) string { return fmt.Sprintf("%d", s.serial) }),
		compareField(snapshots, fmt.Sprintf("NS %s", trimDot(zone)), func(s snapshot) string { return s.ns }),
		compareField(snapshots, fmt.Sprintf("A %s", hostname), func(s snapshot) string { return s.a }),
		compareField(snapshots, fmt.Sprintf("AAAA %s", hostname), func(s snapshot) string { return s.aaaa }),
	)

	res.Findings = findings
	res.Status = aggregateStatus(findings)
	return res
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
func takeSnapshot(ctx context.Context, r *resolver.Resolver, server, zone, hostname string) (snapshot, error) {
	var snap snapshot

	soaMsg, err := r.Query(ctx, server, trimDot(zone), dns.TypeSOA)
	if err != nil {
		return snap, err
	}
	if soaMsg.Rcode != dns.RcodeSuccess {
		return snap, fmt.Errorf("SOA rcode %s", dns.RcodeToString[soaMsg.Rcode])
	}
	if !soaMsg.Authoritative {
		return snap, fmt.Errorf("did not set AA bit")
	}
	for _, rr := range soaMsg.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			snap.serial = soa.Serial
			break
		}
	}

	nsMsg, err := r.Query(ctx, server, trimDot(zone), dns.TypeNS)
	if err != nil {
		return snap, err
	}
	snap.ns = canonicalNames(nsMsg, dns.TypeNS)

	if aMsg, err := r.Query(ctx, server, hostname, dns.TypeA); err == nil {
		snap.a = canonicalIPs(aMsg, dns.TypeA)
	}
	if aaaaMsg, err := r.Query(ctx, server, hostname, dns.TypeAAAA); err == nil {
		snap.aaaa = canonicalIPs(aaaaMsg, dns.TypeAAAA)
	}

	return snap, nil
}

func canonicalNames(msg *dns.Msg, qtype uint16) string {
	var names []string
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype != qtype {
			continue
		}
		if ns, ok := rr.(*dns.NS); ok {
			names = append(names, strings.ToLower(dns.Fqdn(ns.Ns)))
		}
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

func canonicalIPs(msg *dns.Msg, qtype uint16) string {
	var ips []string
	for _, rr := range msg.Answer {
		switch x := rr.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				ips = append(ips, x.A.String())
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				ips = append(ips, x.AAAA.String())
			}
		}
	}
	sort.Strings(ips)
	return strings.Join(ips, ",")
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

func authoritativeNSHosts(ctx context.Context, r *resolver.Resolver, zone string) ([]string, error) {
	msg, err := r.Resolve(ctx, trimDot(zone), dns.TypeNS)
	if err != nil {
		return nil, err
	}
	if msg.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("NS rcode %s", dns.RcodeToString[msg.Rcode])
	}
	var hosts []string
	for _, rr := range msg.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			hosts = append(hosts, ns.Ns)
		}
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no NS records for %s", trimDot(zone))
	}
	return hosts, nil
}

func resolveIPs(ctx context.Context, r *resolver.Resolver, host string) ([]net.IP, error) {
	var ips []net.IP
	if msg, err := r.Resolve(ctx, trimDot(host), dns.TypeA); err == nil {
		for _, rr := range msg.Answer {
			if a, ok := rr.(*dns.A); ok {
				ips = append(ips, a.A)
			}
		}
	}
	if msg, err := r.Resolve(ctx, trimDot(host), dns.TypeAAAA); err == nil {
		for _, rr := range msg.Answer {
			if a, ok := rr.(*dns.AAAA); ok {
				ips = append(ips, a.AAAA)
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no A/AAAA records")
	}
	return ips, nil
}

func findZone(ctx context.Context, r *resolver.Resolver, name string) (string, error) {
	msg, err := r.Resolve(ctx, dns.Fqdn(name), dns.TypeSOA)
	if err != nil {
		return "", err
	}
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return "", fmt.Errorf("rcode %s", dns.RcodeToString[msg.Rcode])
	}
	for _, rr := range msg.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Hdr.Name, nil
		}
	}
	for _, rr := range msg.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Hdr.Name, nil
		}
	}
	return "", fmt.Errorf("no SOA in response")
}

func trimDot(s string) string { return strings.TrimSuffix(s, ".") }

func aggregateStatus(findings []check.Finding) check.Status {
	status := check.StatusPass
	for _, f := range findings {
		if f.Status == check.StatusSkip {
			continue
		}
		if f.Status > status && f.Status <= check.StatusFail {
			status = f.Status
		}
	}
	return status
}

func fail(res check.Result, msg string) check.Result {
	res.Status = check.StatusFail
	res.Findings = []check.Finding{{Status: check.StatusFail, Message: msg}}
	return res
}
