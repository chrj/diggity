// Package dnsutil contains small DNS helpers shared across diggity's checks.
package dnsutil

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"

	"github.com/chrj/diggity/internal/resolver"
)

// FindZone returns the apex of the zone that name lives in by asking the
// configured recursive resolver for SOA. The SOA is found either in the
// answer section (when name is the apex) or the authority section (when
// name is below the apex).
func FindZone(ctx context.Context, r resolver.RecursiveQuerier, name string) (string, error) {
	msg, err := r.Resolve(ctx, dns.Fqdn(name), dns.TypeSOA)
	if err != nil {
		return "", err
	}
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return "", fmt.Errorf("rcode %s", dns.RcodeToString[msg.Rcode])
	}
	if soa := FirstSOA(msg); soa != nil {
		return soa.Hdr.Name, nil
	}
	return "", fmt.Errorf("no SOA in response")
}

// ParentName returns the immediate parent of name as an FQDN. The parent
// of "example.com." is "com."; the parent of "com." is ".". For the root
// it returns ("", false).
func ParentName(name string) (string, bool) {
	name = dns.Fqdn(name)
	if name == "." {
		return "", false
	}
	i := strings.IndexByte(name, '.')
	if i < 0 {
		return "", false
	}
	if i+1 >= len(name) {
		return ".", true
	}
	return name[i+1:], true
}

// TrimDot strips one trailing dot, for display.
func TrimDot(s string) string {
	return strings.TrimSuffix(s, ".")
}

// ResolveIPs returns every A and AAAA address for host via the recursive
// resolver. Errors from either query are absorbed; only an empty result is
// reported.
func ResolveIPs(ctx context.Context, r resolver.RecursiveQuerier, host string) ([]net.IP, error) {
	var ips []net.IP
	if msg, err := r.Resolve(ctx, TrimDot(host), dns.TypeA); err == nil {
		ips = append(ips, AnswerIPs(msg, dns.TypeA)...)
	}
	if msg, err := r.Resolve(ctx, TrimDot(host), dns.TypeAAAA); err == nil {
		ips = append(ips, AnswerIPs(msg, dns.TypeAAAA)...)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no A/AAAA for %s", host)
	}
	return ips, nil
}
