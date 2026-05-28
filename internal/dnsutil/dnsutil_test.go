package dnsutil

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestParentName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want string
		ok   bool
	}{
		{"www.example.com", "example.com.", true},
		{"example.com.", "com.", true},
		{"com.", ".", true},
		{".", "", false},
	}

	for _, tt := range tests {
		got, ok := ParentName(tt.name)
		if got != tt.want || ok != tt.ok {
			t.Fatalf("ParentName(%q) = (%q, %v), want (%q, %v)", tt.name, got, ok, tt.want, tt.ok)
		}
	}
}

func TestTrimDot(t *testing.T) {
	t.Parallel()

	if got := TrimDot("example.com."); got != "example.com" {
		t.Fatalf("TrimDot() = %q, want %q", got, "example.com")
	}
	if got := TrimDot("example.com"); got != "example.com" {
		t.Fatalf("TrimDot() without dot = %q, want unchanged", got)
	}
}

func TestFindZone(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		msg  *dns.Msg
		want string
		err  string
	}{
		{
			name: "answer section",
			msg: &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}, Answer: []dns.RR{
				&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA}},
			}},
			want: "example.com.",
		},
		{
			name: "authority section",
			msg: &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}, Ns: []dns.RR{
				&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA}},
			}},
			want: "example.com.",
		},
		{
			name: "bad rcode",
			msg:  &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}},
			err:  "rcode SERVFAIL",
		},
	}

	for _, tt := range tests {
		got, err := FindZone(context.Background(), fakeRecursiveClient{msg: tt.msg}, "www.example.com")
		if tt.err != "" {
			if err == nil || err.Error() != tt.err {
				t.Fatalf("%s: FindZone() error = %v, want %q", tt.name, err, tt.err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Fatalf("%s: FindZone() = (%q, %v), want (%q, nil)", tt.name, got, err, tt.want)
		}
	}
}

func TestResolveIPs(t *testing.T) {
	t.Parallel()

	r := fakeRecursiveClient{
		byType: map[uint16]*dns.Msg{
			dns.TypeA: {
				Answer: []dns.RR{
					&dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA}, A: net.ParseIP("192.0.2.1")},
				},
			},
			dns.TypeAAAA: {
				Answer: []dns.RR{
					&dns.AAAA{Hdr: dns.RR_Header{Rrtype: dns.TypeAAAA}, AAAA: net.ParseIP("2001:db8::1")},
				},
			},
		},
	}

	ips, err := ResolveIPs(context.Background(), r, "ns1.example.com.")
	if err != nil {
		t.Fatalf("ResolveIPs() error = %v", err)
	}
	if len(ips) != 2 || !ips[0].Equal(net.ParseIP("192.0.2.1")) || !ips[1].Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("ResolveIPs() = %#v", ips)
	}

	_, err = ResolveIPs(context.Background(), fakeRecursiveClient{err: errors.New("boom")}, "ns1.example.com.")
	if err == nil || err.Error() != "no A/AAAA for ns1.example.com." {
		t.Fatalf("ResolveIPs() error = %v, want no A/AAAA error", err)
	}
}

type fakeRecursiveClient struct {
	msg    *dns.Msg
	err    error
	byType map[uint16]*dns.Msg
}

func (f fakeRecursiveClient) Resolve(_ context.Context, _ string, qtype uint16) (*dns.Msg, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.byType != nil {
		if msg, ok := f.byType[qtype]; ok {
			return msg, nil
		}
	}
	if f.msg != nil {
		return f.msg, nil
	}
	return &dns.Msg{}, nil
}

type familyRestrictedClient struct {
	fakeRecursiveClient
	family int
}

func (f familyRestrictedClient) Family() int { return f.family }

func TestResolveNameServerTargetsFilterByFamily(t *testing.T) {
	t.Parallel()

	r := familyRestrictedClient{
		fakeRecursiveClient: fakeRecursiveClient{
			byType: map[uint16]*dns.Msg{
				dns.TypeA: {
					Answer: []dns.RR{
						&dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA}, A: net.ParseIP("192.0.2.1")},
					},
				},
				dns.TypeAAAA: {
					Answer: []dns.RR{
						&dns.AAAA{Hdr: dns.RR_Header{Rrtype: dns.TypeAAAA}, AAAA: net.ParseIP("2001:db8::1")},
					},
				},
			},
		},
		family: 4,
	}

	targets, unresolved := ResolveNameServerTargets(context.Background(), r, []string{"ns1.example.com."}, nil)
	if len(unresolved) != 0 {
		t.Fatalf("unresolved = %v, want empty", unresolved)
	}
	if len(targets) != 1 || targets[0].Family != 4 || targets[0].IP.String() != "192.0.2.1" {
		t.Fatalf("targets = %#v, want one IPv4 target", targets)
	}

	r.family = 6
	targets, unresolved = ResolveNameServerTargets(context.Background(), r, []string{"ns1.example.com."}, nil)
	if len(unresolved) != 0 {
		t.Fatalf("unresolved = %v, want empty", unresolved)
	}
	if len(targets) != 1 || targets[0].Family != 6 || targets[0].IP.String() != "2001:db8::1" {
		t.Fatalf("targets = %#v, want one IPv6 target", targets)
	}
}

func TestResolveNameServerTargetsFilterMarksUnresolvedWhenNoMatch(t *testing.T) {
	t.Parallel()

	r := familyRestrictedClient{
		fakeRecursiveClient: fakeRecursiveClient{
			byType: map[uint16]*dns.Msg{
				dns.TypeA: {
					Answer: []dns.RR{
						&dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA}, A: net.ParseIP("192.0.2.1")},
					},
				},
			},
		},
		family: 6,
	}

	targets, unresolved := ResolveNameServerTargets(context.Background(), r, []string{"ns1.example.com."}, nil)
	if len(targets) != 0 {
		t.Fatalf("targets = %#v, want empty (no IPv6)", targets)
	}
	if len(unresolved) != 1 || unresolved[0] != "ns1.example.com." {
		t.Fatalf("unresolved = %v, want [ns1.example.com.]", unresolved)
	}
}
