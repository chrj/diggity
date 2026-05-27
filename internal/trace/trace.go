package trace

import (
	"context"
	"fmt"
	"io"
	"net"
	"sort"

	"github.com/miekg/dns"

	"github.com/chrj/diggity/internal/dnsutil"
	"github.com/chrj/diggity/internal/resolver"
)

// rootHint is one root nameserver's name and IPv4 address. The list is
// bundled at build time from https://www.internic.net/domain/named.root so
// the iterative walk does not depend on the configured recursor finding the
// root NS for us. Refresh per release.
type rootHint struct {
	Name string
	IP   string
}

var rootHints = []rootHint{
	{"a.root-servers.net.", "198.41.0.4"},
	{"b.root-servers.net.", "170.247.170.2"},
	{"c.root-servers.net.", "192.33.4.12"},
	{"d.root-servers.net.", "199.7.91.13"},
	{"e.root-servers.net.", "192.203.230.10"},
	{"f.root-servers.net.", "192.5.5.241"},
	{"g.root-servers.net.", "192.112.36.4"},
	{"h.root-servers.net.", "198.97.190.53"},
	{"i.root-servers.net.", "192.36.148.17"},
	{"j.root-servers.net.", "192.58.128.30"},
	{"k.root-servers.net.", "193.0.14.129"},
	{"l.root-servers.net.", "199.7.83.42"},
	{"m.root-servers.net.", "202.12.27.33"},
}

const maxHops = 16

// Hop is one step in an iterative resolution.
type Hop struct {
	ServerName    string // NS hostname contacted, e.g. "a.root-servers.net."
	ServerAddr    string // IP:port we contacted, e.g. "198.41.0.4:53"
	Rcode         int
	Authoritative bool
	Referral      string   // owner name of NS records in the response, if a referral
	NS            []string // NS records returned (target hostnames)
	Glue          []string // human-readable glue records, e.g. "ns1.foo. A 1.2.3.4"
	Err           error
}

// Walk performs an iterative resolution for name starting from the bundled
// root hints and returns every hop. It stops at the first AA response, when
// a referral dead-ends, or after maxHops to avoid loops.
func Walk(ctx context.Context, r resolver.Querier, name string) []Hop {
	target := dns.Fqdn(name)

	type srv struct {
		name string
		addr string
	}
	var servers []srv
	for _, h := range rootHints {
		servers = append(servers, srv{name: h.Name, addr: net.JoinHostPort(h.IP, "53")})
	}

	var hops []Hop
	for i := 0; i < maxHops && len(servers) > 0; i++ {
		var msg *dns.Msg
		var used srv
		var lastErr error
		for _, s := range servers {
			m, err := r.Query(ctx, s.addr, target, dns.TypeNS)
			if err != nil {
				lastErr = err
				continue
			}
			msg = m
			used = s
			break
		}
		if msg == nil {
			hops = append(hops, Hop{Err: lastErr})
			break
		}

		hop := Hop{
			ServerName:    used.name,
			ServerAddr:    used.addr,
			Rcode:         msg.Rcode,
			Authoritative: msg.Authoritative,
		}

		var nsRecs []*dns.NS
		for _, rr := range msg.Answer {
			if ns, ok := rr.(*dns.NS); ok {
				nsRecs = append(nsRecs, ns)
			}
		}
		if len(nsRecs) == 0 {
			for _, rr := range msg.Ns {
				if ns, ok := rr.(*dns.NS); ok {
					nsRecs = append(nsRecs, ns)
				}
			}
		}
		for _, ns := range nsRecs {
			hop.NS = append(hop.NS, ns.Ns)
		}
		sort.Strings(hop.NS)
		if len(nsRecs) > 0 {
			hop.Referral = nsRecs[0].Hdr.Name
		}

		glueMap := dnsutil.AdditionalIPs(msg)
		for _, rr := range msg.Extra {
			switch x := rr.(type) {
			case *dns.A:
				hop.Glue = append(hop.Glue, fmt.Sprintf("%s A %s", dnsutil.TrimDot(x.Hdr.Name), x.A))
			case *dns.AAAA:
				hop.Glue = append(hop.Glue, fmt.Sprintf("%s AAAA %s", dnsutil.TrimDot(x.Hdr.Name), x.AAAA))
			}
		}
		sort.Strings(hop.Glue)

		hops = append(hops, hop)

		if msg.Authoritative {
			break
		}
		if len(nsRecs) == 0 {
			break
		}

		var nsHosts []string
		for _, ns := range nsRecs {
			nsHosts = append(nsHosts, ns.Ns)
		}
		targets, _ := dnsutil.ResolveNameServerTargets(ctx, r, nsHosts, glueMap)
		var next []srv
		for _, target := range targets {
			next = append(next, srv{name: target.Host, addr: target.Addr})
		}
		if len(next) == 0 {
			break
		}
		servers = next
	}

	return hops
}

// Render writes a human-readable trace of hops to w, prefaced by name.
func Render(w io.Writer, name string, hops []Hop) {
	fmt.Fprintf(w, "iterative walk for %s:\n", dnsutil.TrimDot(dns.Fqdn(name)))
	for i, h := range hops {
		num := fmt.Sprintf("%2d", i+1)
		if h.Err != nil {
			fmt.Fprintf(w, "  %s. unreachable: %v\n", num, h.Err)
			continue
		}
		aa := ""
		if h.Authoritative {
			aa = "  AA"
		}
		fmt.Fprintf(w, "  %s. @%s (%s)  rcode=%s%s\n", num, dnsutil.TrimDot(h.ServerName), h.ServerAddr, dns.RcodeToString[h.Rcode], aa)
		if h.Referral != "" && !h.Authoritative {
			fmt.Fprintf(w, "        referral to %s:\n", dnsutil.TrimDot(h.Referral))
		} else if h.Authoritative && len(h.NS) > 0 {
			fmt.Fprintf(w, "        NS %s:\n", dnsutil.TrimDot(h.Referral))
		}
		for _, ns := range h.NS {
			fmt.Fprintf(w, "          - %s\n", dnsutil.TrimDot(ns))
		}
		for _, g := range h.Glue {
			fmt.Fprintf(w, "          + %s\n", g)
		}
	}
	fmt.Fprintln(w)
}
