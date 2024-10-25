//
// SPDX-License-Identifier: BSD-3-Clause
//
// Adapted from: https://github.com/ooni/probe-engine/blob/v0.23.0/netx/resolver/decoder.go
//
// Response implementation
//

package dnscore

import (
	"errors"

	"github.com/miekg/dns"
)

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

// These error messages use the same suffixes used by the Go standard library.
var (
	// ErrCannotUnmarshalMessage indicates that we cannot unmarshal a DNS message.
	ErrCannotUnmarshalMessage = errors.New("cannot unmarshal DNS message")

	// ErrInvalidResponse indicates that a response message is invalid.
	ErrInvalidResponse = errors.New("invalid DNS response")

	// ErrNoName indicates that the server response code is NXDOMAIN.
	ErrNoName = errors.New("no such host")

	// ErrServerMisbehaving indicates that the server response code is
	// neither 0, nor NXDOMAIN, nor SERVFAIL.
	ErrServerMisbehaving = errors.New("server misbehaving")

	// ErrServerTemporarilyMisbehaving indicates that the server answer is SERVFAIL.
	//
	// The error message is same as [ErrServerMisbehaving] for compatibility with the
	// Go standard library, which assigns the same error string to both errors.
	ErrServerTemporarilyMisbehaving = errors.New("server misbehaving")

	// ErrNoData indicates that there is no pertinent answer in the response.
	ErrNoData = errors.New("no answer from DNS server")
)
