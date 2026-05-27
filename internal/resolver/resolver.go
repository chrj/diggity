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
	cfg       Config
	recursors []string
	udp       *dns.Client
	tcp       *dns.Client
}

// New returns a Resolver configured with cfg. When cfg.Resolvers is empty,
// the system resolvers from /etc/resolv.conf are used; if that file is
// missing or empty, well-known public resolvers are used as a fallback.
func New(cfg Config) *Resolver {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	r := &Resolver{
		cfg: cfg,
		udp: &dns.Client{Net: "udp", Timeout: cfg.Timeout},
		tcp: &dns.Client{Net: "tcp", Timeout: cfg.Timeout},
	}

	if len(cfg.Resolvers) > 0 {
		for _, addr := range cfg.Resolvers {
			r.recursors = append(r.recursors, ensurePort(addr))
		}
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
		return r
	}

	r.recursors = []string{"1.1.1.1:53", "8.8.8.8:53"}
	return r
}

// Recursors returns the recursive resolvers in use.
func (r *Resolver) Recursors() []string {
	return append([]string(nil), r.recursors...)
}

// Resolve sends a recursive query (RD=1) via one of the configured recursors.
func (r *Resolver) Resolve(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	return r.exchangeFirst(ctx, r.recursors, name, qtype, true, r.cfg.TCP)
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
