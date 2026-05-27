package dnssec

// RootTrustAnchorXML is the IANA root trust anchor bundled at build time so
// diggity validates the DNSSEC chain without reading /usr/share/dns/root.key
// from the host. Refreshed per release.
//
// Source: https://data.iana.org/root-anchors/root-anchors.xml
//
// TODO: replace placeholder with the real anchor and add a build-time check
// that the file is non-empty and parses.
var RootTrustAnchorXML = ``
