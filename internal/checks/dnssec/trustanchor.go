package dnssec

import "github.com/miekg/dns"

// bundledRootAnchors are the IANA root trust anchors compiled into the binary
// so diggity can validate the DNSSEC chain without reading
// /usr/share/dns/root.key from the host. Refreshed per release.
//
// Source: https://data.iana.org/root-anchors/root-anchors.xml
//
// As of 2024 IANA publishes two simultaneously valid root KSKs:
//   - KSK-2017: key tag 20326, algorithm 8 (RSASHA256), SHA-256 digest
//   - KSK-2024: key tag 38696, algorithm 8 (RSASHA256), SHA-256 digest
//
// At least one must match a published DNSKEY for the chain to validate.
var bundledRootAnchors = []*dns.DS{
	{
		Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
		KeyTag:     20326,
		Algorithm:  8,
		DigestType: 2,
		Digest:     "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d",
	},
	{
		Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
		KeyTag:     38696,
		Algorithm:  8,
		DigestType: 2,
		Digest:     "683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16",
	},
}
