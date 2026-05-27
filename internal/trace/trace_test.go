package trace

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestRender(t *testing.T) {
	t.Parallel()

	hops := []Hop{
		{
			ServerName: "a.root-servers.net.",
			ServerAddr: "198.41.0.4:53",
			Rcode:      dns.RcodeSuccess,
			Referral:   "com.",
			NS:         []string{"b.gtld-servers.net.", "a.gtld-servers.net."},
			Glue:       []string{"a.gtld-servers.net A 192.5.6.30"},
		},
		{
			ServerName:    "a.gtld-servers.net.",
			ServerAddr:    "192.5.6.30:53",
			Rcode:         dns.RcodeSuccess,
			Authoritative: true,
			Referral:      "example.com.",
			NS:            []string{"ns1.example.com."},
		},
		{Err: errors.New("timeout")},
	}

	var buf bytes.Buffer
	Render(&buf, "example.com", hops)
	out := buf.String()

	for _, want := range []string{
		"iterative walk for example.com:",
		"@a.root-servers.net (198.41.0.4:53)  rcode=NOERROR",
		"referral to com:",
		"- a.gtld-servers.net",
		"+ a.gtld-servers.net A 192.5.6.30",
		"@a.gtld-servers.net (192.5.6.30:53)  rcode=NOERROR  AA",
		"NS example.com:",
		"unreachable: timeout",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("Render() output missing %q in %q", want, out)
		}
	}
}
