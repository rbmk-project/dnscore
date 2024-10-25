// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import "github.com/miekg/dns"

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
	return nil, nil
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
