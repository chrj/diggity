package delegation

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
const Name = "delegation"

// Run performs the delegation check for hostname using r.
func Run(ctx context.Context, r *resolver.Resolver, hostname string) check.Result {
	res := check.Result{Check: Name, Hostname: hostname}

	zone, err := dnsutil.FindZone(ctx, r, hostname)
	if err != nil {
		return check.Fail(res, fmt.Sprintf("could not find zone for %s: %v", hostname, err))
	}

	parent, ok := dnsutil.ParentName(zone)
	if !ok {
		return check.Fail(res, fmt.Sprintf("%s has no parent zone (cannot check delegation of the root)", dnsutil.TrimDot(zone)))
	}

	parentServers, err := authoritativeAddrs(ctx, r, parent)
	if err != nil {
		return check.Fail(res, fmt.Sprintf("could not resolve authoritative servers for %s: %v", dnsutil.TrimDot(parent), err))
	}

	parentSide, glue, err := referral(ctx, r, parentServers, zone)
	if err != nil {
		return check.Fail(res, fmt.Sprintf("could not fetch delegation of %s from parent: %v", dnsutil.TrimDot(zone), err))
	}
	if len(parentSide) == 0 {
		return check.Fail(res, fmt.Sprintf("parent %s has no NS records for %s", dnsutil.TrimDot(parent), dnsutil.TrimDot(zone)))
	}

	var findings []check.Finding

	// Resolve each parent-side NS to one or more IPs. Prefer glue when present.
	type target struct {
		host string
		ip   net.IP
		glue bool
	}
	var targets []target
	for _, ns := range parentSide {
		if ips, ok := glue[strings.ToLower(ns)]; ok && len(ips) > 0 {
			for _, ip := range ips {
				targets = append(targets, target{host: ns, ip: ip, glue: true})
			}
			continue
		}
		ips, err := dnsutil.ResolveIPs(ctx, r, ns)
		if err != nil || len(ips) == 0 {
			findings = append(findings, check.Finding{
				Status:  check.StatusFail,
				Message: fmt.Sprintf("NS %s has no A/AAAA records", dnsutil.TrimDot(ns)),
			})
			continue
		}
		for _, ip := range ips {
			targets = append(targets, target{host: ns, ip: ip})
		}
	}

	// Query each target for the zone's NS records (and SOA over TCP for
	// serial + TCP reachability).
	childSets := map[string][]string{}
	serials := map[string]uint32{}
	for _, t := range targets {
		label := fmt.Sprintf("%s/%s", dnsutil.TrimDot(t.host), t.ip)
		srv := net.JoinHostPort(t.ip.String(), "53")

		nsMsg, err := r.Query(ctx, srv, dnsutil.TrimDot(zone), dns.TypeNS)
		if err != nil {
			findings = append(findings, check.Finding{
				Status:  check.StatusFail,
				Message: fmt.Sprintf("%s unreachable on UDP/53: %v", label, err),
			})
			continue
		}
		if nsMsg.Rcode != dns.RcodeSuccess {
			findings = append(findings, check.Finding{
				Status:  check.StatusFail,
				Message: fmt.Sprintf("%s answered NS query with rcode %s", label, dns.RcodeToString[nsMsg.Rcode]),
			})
			continue
		}
		if !nsMsg.Authoritative {
			findings = append(findings, check.Finding{
				Status:  check.StatusFail,
				Message: fmt.Sprintf("%s did not set AA bit (lame delegation)", label),
			})
		}
		var hosts []string
		for _, rr := range nsMsg.Answer {
			if n, ok := rr.(*dns.NS); ok {
				hosts = append(hosts, strings.ToLower(dns.Fqdn(n.Ns)))
			}
		}
		sort.Strings(hosts)
		childSets[label] = hosts

		soaMsg, err := r.QueryTCP(ctx, srv, dnsutil.TrimDot(zone), dns.TypeSOA)
		if err != nil {
			findings = append(findings, check.Finding{
				Status:  check.StatusFail,
				Message: fmt.Sprintf("%s unreachable on TCP/53: %v", label, err),
			})
			continue
		}
		if soaMsg.Rcode != dns.RcodeSuccess {
			findings = append(findings, check.Finding{
				Status:  check.StatusFail,
				Message: fmt.Sprintf("%s answered SOA query with rcode %s", label, dns.RcodeToString[soaMsg.Rcode]),
			})
			continue
		}
		for _, rr := range soaMsg.Answer {
			if soa, ok := rr.(*dns.SOA); ok {
				serials[label] = soa.Serial
				break
			}
		}
	}

	// Compare parent-side and child-side NS sets.
	parentSet := normaliseSet(parentSide)
	childSet := unionSet(childSets)
	if len(childSet) == 0 {
		findings = append(findings, check.Finding{
			Status:  check.StatusFail,
			Message: "no authoritative server returned a usable NS RRset",
		})
	} else if !equalSets(parentSet, childSet) {
		missingAtChild := diffSets(parentSet, childSet)
		extraAtChild := diffSets(childSet, parentSet)
		var detail []string
		if len(missingAtChild) > 0 {
			detail = append(detail, "at parent only: "+strings.Join(stripDots(missingAtChild), ", "))
		}
		if len(extraAtChild) > 0 {
			detail = append(detail, "at child only:  "+strings.Join(stripDots(extraAtChild), ", "))
		}
		findings = append(findings, check.Finding{
			Status:  check.StatusFail,
			Message: "parent-side and child-side NS records disagree",
			Detail:  strings.Join(detail, "\n"),
		})
	} else {
		findings = append(findings, check.Finding{
			Status:  check.StatusPass,
			Message: fmt.Sprintf("parent and child agree on %d NS: %s", len(parentSet), strings.Join(stripDots(parentSet), ", ")),
		})
	}

	// Glue check: in-bailiwick NS names must have glue at the parent.
	var missingGlue []string
	for _, ns := range parentSide {
		if !inBailiwick(ns, zone) {
			continue
		}
		if len(glue[strings.ToLower(ns)]) == 0 {
			missingGlue = append(missingGlue, dnsutil.TrimDot(ns))
		}
	}
	if len(missingGlue) > 0 {
		findings = append(findings, check.Finding{
			Status:  check.StatusFail,
			Message: fmt.Sprintf("in-bailiwick NS missing glue at parent: %s", strings.Join(missingGlue, ", ")),
		})
	}

	// SOA serial consistency across reachable servers.
	if len(serials) > 1 {
		grouped := map[uint32][]string{}
		for k, s := range serials {
			grouped[s] = append(grouped[s], k)
		}
		if len(grouped) > 1 {
			var parts []string
			for s, ks := range grouped {
				sort.Strings(ks)
				parts = append(parts, fmt.Sprintf("serial %d: %s", s, strings.Join(ks, ", ")))
			}
			sort.Strings(parts)
			findings = append(findings, check.Finding{
				Status:  check.StatusWarn,
				Message: "SOA serial differs across authoritative servers",
				Detail:  strings.Join(parts, "\n"),
			})
		}
	}

	res.Findings = findings
	res.Status = check.Aggregate(findings)
	return res
}

func authoritativeAddrs(ctx context.Context, r *resolver.Resolver, zone string) ([]string, error) {
	msg, err := r.Resolve(ctx, dnsutil.TrimDot(zone), dns.TypeNS)
	if err != nil {
		return nil, err
	}
	if msg.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("NS query rcode %s", dns.RcodeToString[msg.Rcode])
	}
	var hosts []string
	for _, rr := range msg.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			hosts = append(hosts, ns.Ns)
		}
	}
	if len(hosts) == 0 {
		for _, rr := range msg.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				hosts = append(hosts, ns.Ns)
			}
		}
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no NS for %s", dnsutil.TrimDot(zone))
	}

	var addrs []string
	for _, h := range hosts {
		ips, err := dnsutil.ResolveIPs(ctx, r, h)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			addrs = append(addrs, net.JoinHostPort(ip.String(), "53"))
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no NS for %s resolved to an IP", dnsutil.TrimDot(zone))
	}
	return addrs, nil
}

// referral asks each server in turn for the zone's NS records (RD=0) and
// returns the first usable response: the parent-side NS hostnames and any
// glue A/AAAA records present in the additional section, keyed by lowercase
// owner name.
func referral(ctx context.Context, r *resolver.Resolver, servers []string, zone string) ([]string, map[string][]net.IP, error) {
	var lastErr error
	for _, srv := range servers {
		msg, err := r.Query(ctx, srv, dnsutil.TrimDot(zone), dns.TypeNS)
		if err != nil {
			lastErr = err
			continue
		}
		if msg.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("%s: rcode %s", srv, dns.RcodeToString[msg.Rcode])
			continue
		}
		var nsHosts []string
		for _, rr := range msg.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				nsHosts = append(nsHosts, ns.Ns)
			}
		}
		if len(nsHosts) == 0 {
			for _, rr := range msg.Answer {
				if ns, ok := rr.(*dns.NS); ok {
					nsHosts = append(nsHosts, ns.Ns)
				}
			}
		}
		if len(nsHosts) == 0 {
			lastErr = fmt.Errorf("%s: no NS records", srv)
			continue
		}
		glue := map[string][]net.IP{}
		for _, rr := range msg.Extra {
			switch x := rr.(type) {
			case *dns.A:
				k := strings.ToLower(x.Hdr.Name)
				glue[k] = append(glue[k], x.A)
			case *dns.AAAA:
				k := strings.ToLower(x.Hdr.Name)
				glue[k] = append(glue[k], x.AAAA)
			}
		}
		return nsHosts, glue, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no servers to query")
	}
	return nil, nil, lastErr
}

func inBailiwick(ns, zone string) bool {
	ns = dns.Fqdn(strings.ToLower(ns))
	zone = dns.Fqdn(strings.ToLower(zone))
	if ns == zone {
		return true
	}
	if zone == "." {
		return true
	}
	return strings.HasSuffix(ns, "."+zone)
}

func normaliseSet(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, n := range in {
		n = strings.ToLower(dns.Fqdn(n))
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func unionSet(sets map[string][]string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, set := range sets {
		for _, n := range set {
			if _, ok := seen[n]; ok {
				continue
			}
			seen[n] = struct{}{}
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func equalSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func diffSets(a, b []string) []string {
	bs := map[string]struct{}{}
	for _, x := range b {
		bs[x] = struct{}{}
	}
	var out []string
	for _, x := range a {
		if _, ok := bs[x]; !ok {
			out = append(out, x)
		}
	}
	return out
}

func stripDots(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = dnsutil.TrimDot(s)
	}
	return out
}
