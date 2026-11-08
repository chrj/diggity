package consistency

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/chrj/diggity/internal/check"
	"github.com/chrj/diggity/internal/dnsutil"
)

func TestCanonicalNamesAndIPs(t *testing.T) {
	t.Parallel()

	msg := &dns.Msg{
		Answer: []dns.RR{
			&dns.NS{Hdr: dns.RR_Header{Rrtype: dns.TypeNS}, Ns: "b.example.com."},
			&dns.NS{Hdr: dns.RR_Header{Rrtype: dns.TypeNS}, Ns: "A.example.com."},
			&dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA}, A: []byte{192, 0, 2, 10}},
			&dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA}, A: []byte{192, 0, 2, 1}},
			&dns.AAAA{Hdr: dns.RR_Header{Rrtype: dns.TypeAAAA}, AAAA: []byte{
				0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 1,
			}},
		},
	}

	if got, want := canonicalNames(dnsutil.NSHostnames(msg)), "a.example.com.,b.example.com."; got != want {
		t.Fatalf("canonicalNames() = %q, want %q", got, want)
	}
	if got, want := canonicalIPs(dnsutil.AnswerIPs(msg, dns.TypeA)), "192.0.2.1,192.0.2.10"; got != want {
		t.Fatalf("canonicalIPs(A) = %q, want %q", got, want)
	}
	if got, want := canonicalIPs([]net.IP{net.ParseIP("2001:db8::1")}), "2001:db8::1"; got != want {
		t.Fatalf("canonicalIPs(AAAA) = %q, want %q", got, want)
	}
}

func TestCompareFieldVariants(t *testing.T) {
	t.Parallel()

	pass := compareField(map[string]snapshot{
		"ns1": {serial: 1, family: 4},
		"ns2": {serial: 1, family: 6},
	}, "SOA serial", func(s snapshot) string { return "1" })
	if pass.Status != check.StatusPass || !strings.Contains(pass.Message, "all servers agree on SOA serial") {
		t.Fatalf("compareField(pass) = %#v", pass)
	}

	warn := compareField(map[string]snapshot{
		"ns1": {a: "192.0.2.1", family: 4},
		"ns2": {a: "192.0.2.1", family: 4},
		"ns3": {a: "2001:db8::1", family: 6},
	}, "A example.com", func(s snapshot) string { return s.a })
	if warn.Status != check.StatusWarn || !strings.Contains(warn.Message, "topology-aware DNS / CDN") {
		t.Fatalf("compareField(warn) = %#v", warn)
	}

	fail := compareField(map[string]snapshot{
		"ns1": {ns: "a.example.com.", family: 4},
		"ns2": {ns: "b.example.com.", family: 4},
	}, "NS example.com", func(s snapshot) string { return s.ns })
	if fail.Status != check.StatusFail || !strings.Contains(fail.Detail, "a.example.com.") || !strings.Contains(fail.Detail, "b.example.com.") {
		t.Fatalf("compareField(fail) = %#v", fail)
	}
}

func TestDisplayHelpersAndSplit(t *testing.T) {
	t.Parallel()

	if got, want := displayValue("a,b"), "a, b"; got != want {
		t.Fatalf("displayValue() = %q, want %q", got, want)
	}
	if got, want := displayOr(""), "(no records)"; got != want {
		t.Fatalf("displayOr(empty) = %q, want %q", got, want)
	}

	v4, v6, ok := v4v6Split(map[string]snapshot{
		"ns1": {a: "192.0.2.1", family: 4},
		"ns2": {a: "2001:db8::1", family: 6},
	}, func(s snapshot) string { return s.a })
	if !ok || v4 != "192.0.2.1" || v6 != "2001:db8::1" {
		t.Fatalf("v4v6Split() = (%q, %q, %v)", v4, v6, ok)
	}
}

// fakeZone answers for a zone example.com. with the NS hosts in ns. A host
// without an entry in addrs has no A record. Each server gives the same
// authoritative answers.
type fakeZone struct {
	ns    []string
	addrs map[string]string
}

func (f fakeZone) Resolve(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
	msg := &dns.Msg{}
	switch qtype {
	case dns.TypeSOA:
		msg.Answer = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA}, Serial: 1}}
	case dns.TypeNS:
		for _, h := range f.ns {
			msg.Answer = append(msg.Answer, &dns.NS{Hdr: dns.RR_Header{Rrtype: dns.TypeNS}, Ns: h})
		}
	case dns.TypeA:
		if ip, ok := f.addrs[dns.Fqdn(name)]; ok {
			msg.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA}, A: net.ParseIP(ip)}}
		}
	}
	return msg, nil
}

func (f fakeZone) Query(ctx context.Context, _, name string, qtype uint16) (*dns.Msg, error) {
	msg, err := f.Resolve(ctx, name, qtype)
	if err != nil {
		return nil, err
	}
	msg.Authoritative = true
	if qtype == dns.TypeA && dns.Fqdn(name) == "www.example.com." {
		msg.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA}, A: net.ParseIP("192.0.2.80")}}
	}
	return msg, nil
}

func (f fakeZone) QueryTCP(ctx context.Context, server, name string, qtype uint16) (*dns.Msg, error) {
	return f.Query(ctx, server, name, qtype)
}

func TestRunWarnsAboutUnresolvedNameServers(t *testing.T) {
	t.Parallel()

	r := fakeZone{
		ns: []string{"ns1.example.com.", "ns2.example.com.", "ns3.example.com."},
		addrs: map[string]string{
			"ns1.example.com.": "192.0.2.1",
			"ns2.example.com.": "192.0.2.2",
		},
	}

	res := Run(context.Background(), r, "www.example.com")

	if res.Status != check.StatusWarn {
		t.Fatalf("Status = %q, want %q; findings: %#v", res.Status, check.StatusWarn, res.Findings)
	}
	want := "NS ns3.example.com excluded from comparison: no A/AAAA record that can be used"
	var found bool
	for _, f := range res.Findings {
		if f.Status == check.StatusWarn && f.Message == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("findings = %#v, want a warning %q", res.Findings, want)
	}
}
