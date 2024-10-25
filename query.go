//
// SPDX-License-Identifier: BSD-3-Clause
//
// Adapted from: https://github.com/ooni/probe-engine/blob/v0.23.0/netx/resolver/encoder.go
//
// Query implementation
//

package dnscore

import (
	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

// QueryOption is a function that modifies a DNS query.
type QueryOption func(*dns.Msg) error

const (
	// EDNS0FlagDO enables DNSSEC by setting the DNSSSEC OK (DO) bit.
	EDNS0FlagDO = 1 << iota

	// EDNS0FlagBlockLengthPadding enables block-length padding as defined
	// by https://datatracker.ietf.org/doc/html/rfc8467#section-4.1.
	//
	// This helps protect against size-based traffic analysis by padding
	// DNS queries to a standard block size (128 bytes).
	//
	// This flag implies [QueryFlagEDNS0].
	EDNS0FlagBlockLengthPadding
)

// EDNS0SuggestedMaxResponseSizeUDP is the suggested max-response size
// to use for the DNS over UDP transport. This value is same as the one
// used by the [net] package in the standard library.
const EDNS0SuggestedMaxResponseSizeUDP = 1232

// END0SSuggestedMaxResponseSizeOtherwise is the suggested max-response size
// when not using the DNS over UDP transport.
const EDNS0SuggestedMaxResponseSizeOtherwise = 4096

// QueryOptionEDNS0 configures the EDNS(0) options.
//
// You can configure:
//
// 1. The maximum acceptable response size.
//
// 2. DNSSEC using [EDNS0FlagDO].
//
// 3. Block-length padding using [EDNS0FlagBlockLengthPadding].
func QueryOptionEDNS0(maxResponseSize uint16, flags int) QueryOption {
	return func(q *dns.Msg) error {
		// 1. DNSSEC OK (DO)
		q.SetEdns0(maxResponseSize, flags&EDNS0FlagDO != 0)

		// 2. padding
		//
		// Clients SHOULD pad queries to the closest multiple of
		// 128 octets RFC8467#section-4.1. We inflate the query
		// length by the size of the option (i.e. 4 octets). The
		// cast to uint is necessary to make the modulus operation
		// work as intended when the desiredBlockSize is smaller
		// than (query.Len()+4) ¯\_(ツ)_/¯.
		if flags&EDNS0FlagBlockLengthPadding != 0 {
			const desiredBlockSize = 128
			remainder := (desiredBlockSize - uint16(q.Len()+4)) % desiredBlockSize
			opt := new(dns.EDNS0_PADDING)
			opt.Padding = make([]byte, remainder)
			q.IsEdns0().Option = append(q.IsEdns0().Option, opt)
		}
		return nil
	}
}

// NewQuery constructs a [*dns.Message] containing a query.
//
// This function takes care of IDNA encoding the domain name and
// fails if the domain name is invalid.
//
// Additionally, [NewQuery] ensures the given name is fully qualified.
//
// Use constants such as [dns.TypeAAAA] to specify the query type.
//
// The [QueryOption] functions can be used to set additional options.
func NewQuery(name string, qtype uint16, options ...QueryOption) (*dns.Msg, error) {
	// IDNA encode the domain name.
	punyName, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return nil, err
	}

	// Ensure the domain name is fully qualified.
	if !dns.IsFqdn(punyName) {
		punyName = dns.Fqdn(punyName)
	}

	// Create the query message.
	question := dns.Question{
		Name:   punyName,
		Qtype:  qtype,
		Qclass: dns.ClassINET,
	}
	query := new(dns.Msg)
	query.Id = dns.Id()
	query.RecursionDesired = true
	query.Question = make([]dns.Question, 1)
	query.Question[0] = question

	// Apply the query options.
	for _, option := range options {
		if err := option(query); err != nil {
			return nil, err
		}
	}
	return query, nil
}
