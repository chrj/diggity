package dnssec

import (
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/chrj/diggity/internal/check"
)

func TestZoneChainAndHelpers(t *testing.T) {
	t.Parallel()

	chain := zoneChain("www.example.com")
	want := []string{".", "com.", "example.com.", "www.example.com."}
	if len(chain) != len(want) {
		t.Fatalf("zoneChain length = %d, want %d (%#v)", len(chain), len(want), chain)
	}
	for i := range want {
		if chain[i] != want[i] {
			t.Fatalf("zoneChain[%d] = %q, want %q", i, chain[i], want[i])
		}
	}

	if got := zoneLabel("example.com."); got != "example.com" {
		t.Fatalf("zoneLabel() = %q, want %q", got, "example.com")
	}
	if got := zoneLabel("."); got != "." {
		t.Fatalf("zoneLabel(root) = %q, want %q", got, ".")
	}

	finding := failFinding("example.com", "failed to fetch DS", dns.ErrKey)
	if finding.Status != check.StatusFail || !strings.Contains(finding.Message, "failed to fetch DS") {
		t.Fatalf("failFinding() = %#v", finding)
	}
}

func TestSignatureWarningsAndDNSKEYWarnings(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()

	expired := &dns.RRSIG{
		Algorithm:  5,
		Expiration: uint32(now.Add(-time.Hour).Unix()),
	}
	expiredFindings := signatureWarnings([]*dns.RRSIG{expired}, "example.com DNSKEY", Options{
		ExpiryWarn: 24 * time.Hour,
		Now:        func() time.Time { return now },
	})
	if len(expiredFindings) != 1 || expiredFindings[0].Status != check.StatusFail || !strings.Contains(expiredFindings[0].Message, "expired at") {
		t.Fatalf("signatureWarnings(expired) = %#v", expiredFindings)
	}

	soon := &dns.RRSIG{
		Algorithm:  5,
		Expiration: uint32(now.Add(2 * time.Hour).Unix()),
	}
	soonFindings := signatureWarnings([]*dns.RRSIG{soon}, "example.com DNSKEY", Options{
		ExpiryWarn: 24 * time.Hour,
		Now:        func() time.Time { return now },
	})
	if len(soonFindings) != 2 {
		t.Fatalf("signatureWarnings(soon) len = %d, want 2 (%#v)", len(soonFindings), soonFindings)
	}
	if soonFindings[0].Status != check.StatusWarn || soonFindings[1].Status != check.StatusWarn {
		t.Fatalf("signatureWarnings(soon) statuses = %#v", soonFindings)
	}

	keys := []*dns.DNSKEY{
		{Algorithm: 5},
		{Algorithm: 5},
		{Algorithm: 8},
	}
	keyFindings := dnskeyWarnings(keys, "example.com")
	if len(keyFindings) != 1 || !strings.Contains(keyFindings[0].Message, "deprecated algorithm RSASHA1") {
		t.Fatalf("dnskeyWarnings() = %#v", keyFindings)
	}
}

func TestRRSAny(t *testing.T) {
	t.Parallel()

	keys := []*dns.DNSKEY{{}, {}}
	got := rrsAny(keys)
	if len(got) != 2 {
		t.Fatalf("rrsAny() len = %d, want 2", len(got))
	}
}
