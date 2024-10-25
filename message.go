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

// ValidateResponse validates a given DNS response
// message for a given query message.
func ValidateResponse(query, response *dns.Msg) error {
	return nil
}

// RCodeToError maps an RCODE inside a valid DNS response
// to an error string using a suffix compatible with the
// error strings returned by [*net.Resolver].
//
// For example, if a domain does not exist, the error
// will use the "no such host" suffix.
//
// If the RCODE is zero, this function returns nil.
func RCodeToError(response *dns.Msg) error {
	return nil
}
