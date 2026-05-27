package resolver

import (
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestEnsurePort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		addr string
		want string
	}{
		{"1.1.1.1", "1.1.1.1:53"},
		{"8.8.8.8:54", "8.8.8.8:54"},
		{"2001:db8::1", "[2001:db8::1]:53"},
	}

	for _, tt := range tests {
		if got := ensurePort(tt.addr); got != tt.want {
			t.Fatalf("ensurePort(%q) = %q, want %q", tt.addr, got, tt.want)
		}
	}
}

func TestShouldFallback(t *testing.T) {
	t.Parallel()

	msg := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}}
	if !shouldFallback(msg, dns.TypeDNSKEY) {
		t.Fatal("shouldFallback(SERVFAIL, DNSKEY) = false, want true")
	}
	if !shouldFallback(&dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeRefused}}, dns.TypeDS) {
		t.Fatal("shouldFallback(REFUSED, DS) = false, want true")
	}
	if shouldFallback(msg, dns.TypeA) {
		t.Fatal("shouldFallback(SERVFAIL, A) = true, want false")
	}
	if shouldFallback(&dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}, dns.TypeDNSKEY) {
		t.Fatal("shouldFallback(NOERROR, DNSKEY) = true, want false")
	}
	if shouldFallback(nil, dns.TypeDNSKEY) {
		t.Fatal("shouldFallback(nil, DNSKEY) = true, want false")
	}
}

func TestNewWithResolversUsesConfiguredServers(t *testing.T) {
	t.Parallel()

	r := New(Config{
		Resolvers: []string{"1.1.1.1", "8.8.8.8:54"},
		Timeout:   5 * time.Second,
	})

	if !r.userProvided {
		t.Fatal("userProvided = false, want true")
	}
	if got, want := r.Recursors(), []string{"1.1.1.1:53", "8.8.8.8:54"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Recursors() = %#v, want %#v", got, want)
	}
	if r.udp.Timeout != 5*time.Second || r.tcp.Timeout != 5*time.Second {
		t.Fatalf("timeouts = udp:%s tcp:%s, want %s", r.udp.Timeout, r.tcp.Timeout, 5*time.Second)
	}
}

func TestFallbackInfoCopiesSlices(t *testing.T) {
	t.Parallel()

	r := New(Config{Resolvers: []string{"1.1.1.1"}})
	r.fellBack = true
	r.fellBackFrom = []string{"127.0.0.53:53"}
	r.recursors = []string{"1.1.1.1:53", "8.8.8.8:53"}

	used, from, to := r.FallbackInfo()
	if !used {
		t.Fatal("FallbackInfo().used = false, want true")
	}
	from[0] = "mutated"
	to[0] = "mutated"

	if r.fellBackFrom[0] != "127.0.0.53:53" || r.recursors[0] != "1.1.1.1:53" {
		t.Fatalf("FallbackInfo() did not return copies: from=%#v to=%#v", r.fellBackFrom, r.recursors)
	}
}
