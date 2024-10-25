//
// SPDX-License-Identifier: BSD-3-Clause
//
// Adapted from: https://github.com/ooni/probe-engine/blob/v0.23.0/netx/resolver/decoder.go
//
// Answers decoder
//

package dnscore

import "github.com/miekg/dns"

// DecodeLookupA decodes RRs from a lookup A response.
func DecodeLookupA(rrs []dns.RR) (addrs []string, cname string, err error) {
	for _, answer := range rrs {
		switch answer := answer.(type) {
		case *dns.A:
			addrs = append(addrs, answer.A.String())
		case *dns.CNAME:
			cname = answer.Target
		}
	}
	if len(addrs) <= 0 {
		return nil, "", ErrNoData
	}
	return
}

// DecodeLookupAAAA decodes RRs from a lookup AAAA response.
func DecodeLookupAAAA(rrs []dns.RR) (addrs []string, cname string, err error) {
	for _, answer := range rrs {
		switch answer := answer.(type) {
		case *dns.AAAA:
			addrs = append(addrs, answer.AAAA.String())
		case *dns.CNAME:
			cname = answer.Target
		}
	}
	if len(addrs) <= 0 {
		return nil, "", ErrNoData
	}
	return
}
