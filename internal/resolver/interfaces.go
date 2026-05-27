package resolver

import (
	"context"

	"github.com/miekg/dns"
)

// RecursiveClient resolves records via recursive resolvers.
type RecursiveClient interface {
	Resolve(ctx context.Context, name string, qtype uint16) (*dns.Msg, error)
}

// AuthoritativeClient queries authoritative servers directly.
type AuthoritativeClient interface {
	Query(ctx context.Context, server, name string, qtype uint16) (*dns.Msg, error)
	QueryTCP(ctx context.Context, server, name string, qtype uint16) (*dns.Msg, error)
}

// Client can perform both recursive and authoritative queries.
type Client interface {
	RecursiveClient
	AuthoritativeClient
}
