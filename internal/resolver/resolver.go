package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// Config controls how the resolver makes queries.
type Config struct {
	Resolvers []string
	Timeout   time.Duration
	Retries   int
	TCP       bool
	IPv4Only  bool
	IPv6Only  bool
	Trace     bool
}

// Resolver issues DNS queries on behalf of the checks.
type Resolver struct {
	cfg          Config
	recursors    []string
	udp          *dns.Client
	tcp          *dns.Client
	userProvided bool     // true if cfg.Resolvers was non-empty
	fallbackList []string // public resolvers used when the system resolver refuses DNSSEC
	fellBack     bool
	fellBackFrom []string
}

// Public DNS resolvers used as a safety net when the system resolver
// returns SERVFAIL / REFUSED for DNSSEC queries (a common quirk of
// systemd-resolved). Both Cloudflare and Google are DNSSEC-aware.
var (
	defaultFallbackResolvers4 = []string{"1.1.1.1:53", "8.8.8.8:53"}
	defaultFallbackResolvers6 = []string{"[2606:4700:4700::1111]:53", "[2001:4860:4860::8888]:53"}
)

// New returns a Resolver configured with cfg. When cfg.Resolvers is empty,
// the system resolvers from /etc/resolv.conf are used; if those refuse
// DNSSEC queries, the resolver transparently switches to public fallbacks.
// When cfg.IPv4Only or cfg.IPv6Only is set, the transport and every server
// address list is restricted to the matching address family.
func New(cfg Config) *Resolver {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	udpNet, tcpNet := "udp", "tcp"
	switch {
	case cfg.IPv4Only:
		udpNet, tcpNet = "udp4", "tcp4"
	case cfg.IPv6Only:
		udpNet, tcpNet = "udp6", "tcp6"
	}
	fallbackList := defaultFallbackResolvers4
	if cfg.IPv6Only {
		fallbackList = defaultFallbackResolvers6
	}
	r := &Resolver{
		cfg:          cfg,
		udp:          &dns.Client{Net: udpNet, Timeout: cfg.Timeout},
		tcp:          &dns.Client{Net: tcpNet, Timeout: cfg.Timeout},
		fallbackList: fallbackList,
	}

	if len(cfg.Resolvers) > 0 {
		r.userProvided = true
		for _, addr := range cfg.Resolvers {
			r.recursors = append(r.recursors, ensurePort(addr))
		}
		r.recursors = filterByFamily(r.recursors, cfg)
		return r
	}

	if cc, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cc.Servers) > 0 {
		port := cc.Port
		if port == "" {
			port = "53"
		}
		for _, s := range cc.Servers {
			r.recursors = append(r.recursors, net.JoinHostPort(s, port))
		}
		r.recursors = filterByFamily(r.recursors, cfg)
		if len(r.recursors) > 0 {
			return r
		}
	}

	r.recursors = r.fallbackList
	return r
}

// Family returns 4 or 6 if the resolver is restricted to a single address
// family, or 0 if both families are allowed.
func (r *Resolver) Family() int {
	switch {
	case r.cfg.IPv4Only:
		return 4
	case r.cfg.IPv6Only:
		return 6
	default:
		return 0
	}
}

// filterByFamily keeps only addresses whose host part matches the family
// selected by cfg. Hostnames (non-IP) are kept as-is; the OS resolver will
// pick a matching A or AAAA at dial time anyway, and the family-restricted
// dns.Client will refuse the wrong one.
func filterByFamily(addrs []string, cfg Config) []string {
	if !cfg.IPv4Only && !cfg.IPv6Only {
		return addrs
	}
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		ip := net.ParseIP(host)
		if ip == nil {
			out = append(out, addr)
			continue
		}
		isV4 := ip.To4() != nil
		if cfg.IPv4Only && isV4 {
			out = append(out, addr)
		}
		if cfg.IPv6Only && !isV4 {
			out = append(out, addr)
		}
	}
	return out
}

// Recursors returns the recursive resolvers in use.
func (r *Resolver) Recursors() []string {
	return append([]string(nil), r.recursors...)
}

// FallbackInfo reports whether the resolver transparently switched away
// from the configured system recursors to public DNSSEC-aware resolvers,
// along with the addresses involved.
func (r *Resolver) FallbackInfo() (used bool, from, to []string) {
	if !r.fellBack {
		return false, nil, nil
	}
	return true, append([]string(nil), r.fellBackFrom...), append([]string(nil), r.recursors...)
}

// Resolve sends a recursive query (RD=1) via one of the configured recursors.
// If the system resolver answers a DNSKEY/DS query with SERVFAIL or REFUSED
// (typical of systemd-resolved, which hides root DNSKEY from clients), the
// resolver transparently switches to public DNSSEC-aware fallbacks and
// retries. Triggered at most once per Resolver, and never when the user
// supplied resolvers via -r.
func (r *Resolver) Resolve(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	msg, err := r.exchangeFirst(ctx, r.recursors, name, qtype, true, r.cfg.TCP)

	if !r.userProvided && !r.fellBack && shouldFallback(msg, qtype) {
		r.fellBackFrom = append([]string(nil), r.recursors...)
		r.recursors = r.fallbackList
		r.fellBack = true
		return r.exchangeFirst(ctx, r.recursors, name, qtype, true, r.cfg.TCP)
	}
	return msg, err
}

// shouldFallback decides whether the current response from the system
// resolver warrants switching to a public fallback. We deliberately scope
// this to DNSKEY and DS queries: a SERVFAIL on those is the systemd-resolved
// quirk we want to paper over, while a SERVFAIL on any other query type is
// usually a genuine upstream problem we should surface, not hide.
func shouldFallback(msg *dns.Msg, qtype uint16) bool {
	if msg == nil {
		return false
	}
	if msg.Rcode != dns.RcodeServerFailure && msg.Rcode != dns.RcodeRefused {
		return false
	}
	return qtype == dns.TypeDNSKEY || qtype == dns.TypeDS
}

// Query sends a non-recursive query (RD=0) directly to server.
// server may be "host" (port 53 assumed) or "host:port".
func (r *Resolver) Query(ctx context.Context, server, name string, qtype uint16) (*dns.Msg, error) {
	return r.exchange(ctx, ensurePort(server), name, qtype, false, r.cfg.TCP)
}

// QueryTCP forces TCP. Used for reachability checks where the protocol matters.
func (r *Resolver) QueryTCP(ctx context.Context, server, name string, qtype uint16) (*dns.Msg, error) {
	return r.exchange(ctx, ensurePort(server), name, qtype, false, true)
}

func (r *Resolver) exchangeFirst(ctx context.Context, servers []string, name string, qtype uint16, rd, tcp bool) (*dns.Msg, error) {
	if len(servers) == 0 {
		return nil, errors.New("no servers configured")
	}
	var lastErr error
	for _, s := range servers {
		msg, err := r.exchange(ctx, s, name, qtype, rd, tcp)
		if err == nil {
			return msg, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (r *Resolver) exchange(ctx context.Context, server, name string, qtype uint16, rd, tcp bool) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = rd
	m.SetEdns0(4096, true)

	client := r.udp
	if tcp || r.cfg.TCP {
		client = r.tcp
	}

	attempts := r.cfg.Retries + 1
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	for i := 0; i < attempts; i++ {
		msg, _, err := client.ExchangeContext(ctx, m, server)
		if err != nil {
			lastErr = err
			continue
		}
		if msg.Truncated && client == r.udp {
			msg, _, err = r.tcp.ExchangeContext(ctx, m, server)
			if err != nil {
				lastErr = err
				continue
			}
		}
		return msg, nil
	}
	return nil, fmt.Errorf("%s %s @%s: %w", name, dns.TypeToString[qtype], server, lastErr)
}

func ensurePort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, "53")
}
