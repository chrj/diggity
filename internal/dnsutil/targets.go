package dnsutil

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"

	"github.com/chrj/diggity/internal/resolver"
)

// NameServerTarget is a concrete IP endpoint for an NS hostname.
type NameServerTarget struct {
	Host     string
	IP       net.IP
	Addr     string
	Family   int
	FromGlue bool
}

// AuthoritativeNSHosts returns the NS hostnames published for zone.
func AuthoritativeNSHosts(ctx context.Context, r resolver.RecursiveQuerier, zone string) ([]string, error) {
	msg, err := r.Resolve(ctx, TrimDot(zone), dns.TypeNS)
	if err != nil {
		return nil, err
	}
	if msg.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("NS rcode %s", dns.RcodeToString[msg.Rcode])
	}
	hosts := NSHostnames(msg)
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no NS records for %s", TrimDot(zone))
	}
	return hosts, nil
}

// ResolveNameServerTargets resolves NS hostnames to concrete server targets,
// preferring glue addresses when available. It returns unresolved hostnames
// separately so callers can decide whether to warn, fail, or skip them.
func ResolveNameServerTargets(ctx context.Context, r resolver.RecursiveQuerier, hosts []string, glue map[string][]net.IP) ([]NameServerTarget, []string) {
	targets := make([]NameServerTarget, 0, len(hosts))
	var unresolved []string
	for _, host := range hosts {
		ips, fromGlue := glueIPs(glue, host)
		if len(ips) == 0 {
			resolved, err := ResolveIPs(ctx, r, host)
			if err != nil || len(resolved) == 0 {
				unresolved = append(unresolved, host)
				continue
			}
			ips = resolved
		}
		for _, ip := range ips {
			family := 4
			if ip.To4() == nil {
				family = 6
			}
			targets = append(targets, NameServerTarget{
				Host:     host,
				IP:       ip,
				Addr:     net.JoinHostPort(ip.String(), "53"),
				Family:   family,
				FromGlue: fromGlue,
			})
		}
	}
	return targets, unresolved
}

// AuthoritativeTargets resolves the authoritative NS hostnames for zone to
// concrete server endpoints.
func AuthoritativeTargets(ctx context.Context, r resolver.RecursiveQuerier, zone string) ([]NameServerTarget, error) {
	hosts, err := AuthoritativeNSHosts(ctx, r, zone)
	if err != nil {
		return nil, err
	}
	targets, _ := ResolveNameServerTargets(ctx, r, hosts, nil)
	if len(targets) == 0 {
		return nil, fmt.Errorf("no NS for %s resolved to an IP", TrimDot(zone))
	}
	return targets, nil
}

func glueIPs(glue map[string][]net.IP, host string) ([]net.IP, bool) {
	if glue == nil {
		return nil, false
	}
	ips := glue[strings.ToLower(host)]
	if len(ips) == 0 {
		return nil, false
	}
	return ips, true
}
