package resolver

import (
	"context"

	"github.com/miekg/dns"
)

// RecursiveQuerier resolves records via recursive resolvers.
type RecursiveQuerier interface {
	Resolve(ctx context.Context, name string, qtype uint16) (*dns.Msg, error)
}

// AuthoritativeQuerier queries authoritative servers directly.
type AuthoritativeQuerier interface {
	Query(ctx context.Context, server, name string, qtype uint16) (*dns.Msg, error)
	QueryTCP(ctx context.Context, server, name string, qtype uint16) (*dns.Msg, error)
}

// Querier can perform both recursive and authoritative queries.
type Querier interface {
	RecursiveQuerier
	AuthoritativeQuerier
}
