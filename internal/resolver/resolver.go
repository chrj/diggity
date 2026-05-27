package resolver

import (
	"context"
	"errors"
	"time"
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
	cfg Config
}

// New returns a Resolver configured with cfg.
func New(cfg Config) *Resolver {
	return &Resolver{cfg: cfg}
}

// ErrNotImplemented is returned by stub methods.
var ErrNotImplemented = errors.New("resolver: not implemented")

// Query is the placeholder for the future query API. The real signature
// will use github.com/miekg/dns types and accept a server hint, an EDNS0
// payload size, and a DO bit toggle.
func (r *Resolver) Query(_ context.Context, _ string, _ uint16) (any, error) {
	return nil, ErrNotImplemented
}
