package dnssec

import (
	"fmt"
	"strings"
	"time"

	"context"

	"github.com/miekg/dns"

	"github.com/chrj/diggity/internal/check"
	"github.com/chrj/diggity/internal/resolver"
)

// Name is the identifier used in reports.
const Name = "dnssec"

// Options controls DNSSEC validation behaviour.
type Options struct {
	ExpiryWarn time.Duration
}

// Algorithms whose use in new deployments is forbidden by RFC 8624.
var deprecatedAlgorithms = map[uint8]string{
	1:  "RSAMD5",
	3:  "DSASHA1",
	5:  "RSASHA1",
	6:  "DSA-NSEC3-SHA1",
	7:  "RSASHA1-NSEC3-SHA1",
	12: "ECC-GOST",
}

// Digest types whose use in new deployments is forbidden by RFC 8624.
var deprecatedDigestTypes = map[uint8]string{
	1: "SHA-1",
	3: "GOST R 34.11-94",
}

// Run validates the DNSSEC chain of trust for hostname's zone.
func Run(ctx context.Context, r *resolver.Resolver, hostname string, opts Options) check.Result {
	res := check.Result{Check: Name, Hostname: hostname}

	zone, err := findZone(ctx, r, hostname)
	if err != nil {
		return fail(res, fmt.Sprintf("could not find zone for %s: %v", hostname, err))
	}

	chain := zoneChain(zone)
	var findings []check.Finding
	var parentKeys []*dns.DNSKEY

	for _, z := range chain {
		levelFindings, levelKeys, signed, halt := validateLevel(ctx, r, z, parentKeys, opts)
		findings = append(findings, levelFindings...)
		if halt {
			break
		}
		if !signed {
			break
		}
		parentKeys = levelKeys
	}

	res.Findings = findings
	res.Status = aggregateStatus(findings)
	return res
}

// zoneChain returns the list of zones to validate, from root down to zone.
// For "example.com." → [".", "com.", "example.com."].
func zoneChain(zone string) []string {
	zone = dns.Fqdn(zone)
	var chain []string
	for {
		chain = append([]string{zone}, chain...)
		if zone == "." {
			break
		}
		next, ok := parentName(zone)
		if !ok {
			break
		}
		zone = next
	}
	return chain
}

// validateLevel runs the DNSSEC checks for one zone in the chain. It returns:
//   - findings: status messages emitted at this level
//   - keys:     the validated DNSKEY set, to be used as the parent keys at
//     the next level
//   - signed:   false if this zone is unsigned (chain stops here, pass)
//   - halt:     true on a fatal verification error (chain stops here, fail)
func validateLevel(ctx context.Context, r *resolver.Resolver, zone string, parentKeys []*dns.DNSKEY, opts Options) ([]check.Finding, []*dns.DNSKEY, bool, bool) {
	label := zoneLabel(zone)
	var findings []check.Finding

	var trustedKSKs []*dns.DNSKEY

	if zone == "." {
		// Fetch root DNSKEY and match against bundled trust anchors.
		keys, sigs, err := fetchDNSKEY(ctx, r, zone)
		if err != nil {
			findings = append(findings, failFinding(label, "failed to fetch root DNSKEY", err))
			return findings, nil, true, true
		}
		matched := matchAgainstAnchors(keys, bundledRootAnchors)
		if len(matched) == 0 {
			findings = append(findings, check.Finding{
				Status:  check.StatusFail,
				Message: label + " root DNSKEY does not match any bundled trust anchor",
			})
			return findings, nil, true, true
		}
		trustedKSKs = matched
		findings = append(findings, check.Finding{
			Status:  check.StatusPass,
			Message: fmt.Sprintf("%s root DNSKEY matches bundled trust anchor (key tag %d)", label, matched[0].KeyTag()),
		})

		// Verify the DNSKEY RRset is signed by a matched KSK.
		if err := verifySignatures(rrsAny(keys), sigs, trustedKSKs); err != nil {
			findings = append(findings, check.Finding{
				Status:  check.StatusFail,
				Message: fmt.Sprintf("%s DNSKEY RRSIG verification failed: %v", label, err),
			})
			return findings, nil, true, true
		}
		findings = append(findings, signatureWarnings(sigs, label+" DNSKEY", opts)...)
		findings = append(findings, dnskeyWarnings(keys, label)...)
		return findings, keys, true, false
	}

	// Non-root: fetch DS at parent and DNSKEY at zone, then link them.
	dsSet, dsSigs, err := fetchDS(ctx, r, zone)
	if err != nil {
		findings = append(findings, failFinding(label, "failed to fetch DS", err))
		return findings, nil, true, true
	}
	if len(dsSet) == 0 {
		findings = append(findings, check.Finding{
			Status:  check.StatusPass,
			Message: fmt.Sprintf("%s unsigned (no DS at parent)", label),
		})
		return findings, nil, false, false
	}

	if err := verifySignatures(rrsAny(dsSet), dsSigs, parentKeys); err != nil {
		findings = append(findings, check.Finding{
			Status:  check.StatusFail,
			Message: fmt.Sprintf("%s DS RRSIG verification failed: %v", label, err),
		})
		return findings, nil, true, true
	}
	findings = append(findings, signatureWarnings(dsSigs, label+" DS", opts)...)
	for _, ds := range dsSet {
		if name, ok := deprecatedAlgorithms[ds.Algorithm]; ok {
			findings = append(findings, check.Finding{
				Status:  check.StatusWarn,
				Message: fmt.Sprintf("%s DS uses deprecated algorithm %s (%d)", label, name, ds.Algorithm),
			})
		}
		if name, ok := deprecatedDigestTypes[ds.DigestType]; ok {
			findings = append(findings, check.Finding{
				Status:  check.StatusWarn,
				Message: fmt.Sprintf("%s DS uses deprecated digest type %s (%d)", label, name, ds.DigestType),
			})
		}
	}

	keys, keySigs, err := fetchDNSKEY(ctx, r, zone)
	if err != nil {
		findings = append(findings, failFinding(label, "failed to fetch DNSKEY", err))
		return findings, nil, true, true
	}

	trustedKSKs = matchAgainstDS(keys, dsSet)
	if len(trustedKSKs) == 0 {
		findings = append(findings, check.Finding{
			Status:  check.StatusFail,
			Message: fmt.Sprintf("%s no DNSKEY matches any DS digest at parent", label),
		})
		return findings, nil, true, true
	}
	findings = append(findings, check.Finding{
		Status:  check.StatusPass,
		Message: fmt.Sprintf("%s DS at parent matches DNSKEY (key tag %d)", label, trustedKSKs[0].KeyTag()),
	})

	if err := verifySignatures(rrsAny(keys), keySigs, trustedKSKs); err != nil {
		findings = append(findings, check.Finding{
			Status:  check.StatusFail,
			Message: fmt.Sprintf("%s DNSKEY RRSIG verification failed: %v", label, err),
		})
		return findings, nil, true, true
	}
	findings = append(findings, signatureWarnings(keySigs, label+" DNSKEY", opts)...)
	findings = append(findings, dnskeyWarnings(keys, label)...)

	// Bonus: verify the SOA RRset is signed by a ZSK from the validated set.
	if soaRR, soaSigs, err := fetchSOA(ctx, r, zone); err == nil && len(soaRR) > 0 {
		if err := verifySignatures(soaRR, soaSigs, keys); err != nil {
			findings = append(findings, check.Finding{
				Status:  check.StatusFail,
				Message: fmt.Sprintf("%s SOA RRSIG verification failed: %v", label, err),
			})
		} else {
			findings = append(findings, signatureWarnings(soaSigs, label+" SOA", opts)...)
		}
	}

	return findings, keys, true, false
}

func fetchDNSKEY(ctx context.Context, r *resolver.Resolver, zone string) ([]*dns.DNSKEY, []*dns.RRSIG, error) {
	rrs, sigs, err := fetchSet(ctx, r, zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, nil, err
	}
	var keys []*dns.DNSKEY
	for _, rr := range rrs {
		if k, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, k)
		}
	}
	return keys, sigs, nil
}

func fetchDS(ctx context.Context, r *resolver.Resolver, zone string) ([]*dns.DS, []*dns.RRSIG, error) {
	rrs, sigs, err := fetchSet(ctx, r, zone, dns.TypeDS)
	if err != nil {
		return nil, nil, err
	}
	var ds []*dns.DS
	for _, rr := range rrs {
		if d, ok := rr.(*dns.DS); ok {
			ds = append(ds, d)
		}
	}
	return ds, sigs, nil
}

func fetchSOA(ctx context.Context, r *resolver.Resolver, zone string) ([]dns.RR, []*dns.RRSIG, error) {
	return fetchSet(ctx, r, zone, dns.TypeSOA)
}

func fetchSet(ctx context.Context, r *resolver.Resolver, name string, qtype uint16) ([]dns.RR, []*dns.RRSIG, error) {
	msg, err := r.Resolve(ctx, name, qtype)
	if err != nil {
		return nil, nil, err
	}
	if msg.Rcode != dns.RcodeSuccess {
		return nil, nil, fmt.Errorf("rcode %s", dns.RcodeToString[msg.Rcode])
	}
	var rrs []dns.RR
	var sigs []*dns.RRSIG
	for _, rr := range msg.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok {
			if sig.TypeCovered == qtype {
				sigs = append(sigs, sig)
			}
			continue
		}
		if rr.Header().Rrtype == qtype {
			rrs = append(rrs, rr)
		}
	}
	return rrs, sigs, nil
}

func matchAgainstAnchors(keys []*dns.DNSKEY, anchors []*dns.DS) []*dns.DNSKEY {
	var out []*dns.DNSKEY
	for _, key := range keys {
		for _, ds := range anchors {
			if key.KeyTag() != ds.KeyTag || key.Algorithm != ds.Algorithm {
				continue
			}
			computed := key.ToDS(ds.DigestType)
			if computed == nil {
				continue
			}
			if strings.EqualFold(computed.Digest, ds.Digest) {
				out = append(out, key)
				break
			}
		}
	}
	return out
}

func matchAgainstDS(keys []*dns.DNSKEY, dsSet []*dns.DS) []*dns.DNSKEY {
	return matchAgainstAnchors(keys, dsSet)
}

func verifySignatures(rrset []dns.RR, sigs []*dns.RRSIG, candidates []*dns.DNSKEY) error {
	if len(rrset) == 0 {
		return fmt.Errorf("empty RRset")
	}
	if len(sigs) == 0 {
		return fmt.Errorf("no RRSIGs")
	}
	if len(candidates) == 0 {
		return fmt.Errorf("no candidate keys")
	}
	var lastErr error
	for _, sig := range sigs {
		for _, key := range candidates {
			if sig.KeyTag != key.KeyTag() || sig.Algorithm != key.Algorithm {
				continue
			}
			if err := sig.Verify(key, rrset); err == nil {
				return nil
			} else {
				lastErr = err
			}
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no RRSIG matched any candidate key")
	}
	return lastErr
}

func signatureWarnings(sigs []*dns.RRSIG, label string, opts Options) []check.Finding {
	var findings []check.Finding
	now := time.Now()
	for _, sig := range sigs {
		exp := time.Unix(int64(sig.Expiration), 0)
		if exp.Before(now) {
			findings = append(findings, check.Finding{
				Status:  check.StatusFail,
				Message: fmt.Sprintf("%s RRSIG expired at %s", label, exp.UTC().Format(time.RFC3339)),
			})
			continue
		}
		if opts.ExpiryWarn > 0 && exp.Sub(now) < opts.ExpiryWarn {
			findings = append(findings, check.Finding{
				Status:  check.StatusWarn,
				Message: fmt.Sprintf("%s RRSIG expires in %s (at %s)", label, exp.Sub(now).Round(time.Hour), exp.UTC().Format(time.RFC3339)),
			})
		}
		if name, ok := deprecatedAlgorithms[sig.Algorithm]; ok {
			findings = append(findings, check.Finding{
				Status:  check.StatusWarn,
				Message: fmt.Sprintf("%s RRSIG uses deprecated algorithm %s (%d)", label, name, sig.Algorithm),
			})
		}
	}
	return findings
}

func dnskeyWarnings(keys []*dns.DNSKEY, label string) []check.Finding {
	seen := map[uint8]bool{}
	var findings []check.Finding
	for _, k := range keys {
		if seen[k.Algorithm] {
			continue
		}
		seen[k.Algorithm] = true
		if name, ok := deprecatedAlgorithms[k.Algorithm]; ok {
			findings = append(findings, check.Finding{
				Status:  check.StatusWarn,
				Message: fmt.Sprintf("%s DNSKEY uses deprecated algorithm %s (%d)", label, name, k.Algorithm),
			})
		}
	}
	return findings
}

func rrsAny[T dns.RR](items []T) []dns.RR {
	out := make([]dns.RR, len(items))
	for i, x := range items {
		out[i] = x
	}
	return out
}

func findZone(ctx context.Context, r *resolver.Resolver, name string) (string, error) {
	msg, err := r.Resolve(ctx, dns.Fqdn(name), dns.TypeSOA)
	if err != nil {
		return "", err
	}
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return "", fmt.Errorf("rcode %s", dns.RcodeToString[msg.Rcode])
	}
	for _, rr := range msg.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Hdr.Name, nil
		}
	}
	for _, rr := range msg.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Hdr.Name, nil
		}
	}
	return "", fmt.Errorf("no SOA in response")
}

func parentName(name string) (string, bool) {
	name = dns.Fqdn(name)
	if name == "." {
		return "", false
	}
	i := strings.IndexByte(name, '.')
	if i < 0 {
		return "", false
	}
	if i+1 >= len(name) {
		return ".", true
	}
	return name[i+1:], true
}

func zoneLabel(zone string) string {
	if zone == "." {
		return "."
	}
	return strings.TrimSuffix(zone, ".")
}

func aggregateStatus(findings []check.Finding) check.Status {
	status := check.StatusPass
	for _, f := range findings {
		if f.Status == check.StatusSkip {
			continue
		}
		if f.Status > status && f.Status <= check.StatusFail {
			status = f.Status
		}
	}
	return status
}

func fail(res check.Result, msg string) check.Result {
	res.Status = check.StatusFail
	res.Findings = []check.Finding{{Status: check.StatusFail, Message: msg}}
	return res
}

func failFinding(label, what string, err error) check.Finding {
	return check.Finding{
		Status:  check.StatusFail,
		Message: fmt.Sprintf("%s %s: %v", label, what, err),
	}
}
