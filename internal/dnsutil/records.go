package dnsutil

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

// FirstSOA returns the first SOA in the answer section, then the authority
// section. It is useful for zone discovery and negative-cache lookups.
func FirstSOA(msg *dns.Msg) *dns.SOA {
	for _, rr := range append(append([]dns.RR(nil), msg.Answer...), msg.Ns...) {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa
		}
	}
	return nil
}

// AnswerRecords returns answer-section records of qtype.
func AnswerRecords(msg *dns.Msg, qtype uint16) []dns.RR {
	return recordsByType(msg.Answer, qtype)
}

// AuthorityRecords returns authority-section records of qtype.
func AuthorityRecords(msg *dns.Msg, qtype uint16) []dns.RR {
	return recordsByType(msg.Ns, qtype)
}

// AnswerOrAuthorityRecords returns answer-section records of qtype, falling
// back to the authority section when the answer is empty.
func AnswerOrAuthorityRecords(msg *dns.Msg, qtype uint16) ([]dns.RR, bool) {
	rrs := AnswerRecords(msg, qtype)
	if len(rrs) > 0 {
		return rrs, false
	}
	rrs = AuthorityRecords(msg, qtype)
	return rrs, len(rrs) > 0
}

// NSHostnames returns the NS targets from the answer section, falling back to
// the authority section when needed.
func NSHostnames(msg *dns.Msg) []string {
	rrs, _ := AnswerOrAuthorityRecords(msg, dns.TypeNS)
	hosts := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		if ns, ok := rr.(*dns.NS); ok {
			hosts = append(hosts, ns.Ns)
		}
	}
	return hosts
}

// AnswerIPs returns A or AAAA addresses from the answer section.
func AnswerIPs(msg *dns.Msg, qtype uint16) []net.IP {
	rrs := AnswerRecords(msg, qtype)
	ips := make([]net.IP, 0, len(rrs))
	for _, rr := range rrs {
		switch x := rr.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				ips = append(ips, x.A)
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				ips = append(ips, x.AAAA)
			}
		}
	}
	return ips
}

// AdditionalIPs returns glue A and AAAA records from the additional section,
// keyed by lowercase owner name.
func AdditionalIPs(msg *dns.Msg) map[string][]net.IP {
	glue := map[string][]net.IP{}
	for _, rr := range msg.Extra {
		switch x := rr.(type) {
		case *dns.A:
			k := strings.ToLower(x.Hdr.Name)
			glue[k] = append(glue[k], x.A)
		case *dns.AAAA:
			k := strings.ToLower(x.Hdr.Name)
			glue[k] = append(glue[k], x.AAAA)
		}
	}
	return glue
}

// RecordTTLs returns the TTLs of the provided records in order.
func RecordTTLs(rrs []dns.RR) []uint32 {
	ttls := make([]uint32, 0, len(rrs))
	for _, rr := range rrs {
		ttls = append(ttls, rr.Header().Ttl)
	}
	return ttls
}

func recordsByType(rrs []dns.RR, qtype uint16) []dns.RR {
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr.Header().Rrtype == qtype {
			out = append(out, rr)
		}
	}
	return out
}
