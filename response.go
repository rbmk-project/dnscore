//
// SPDX-License-Identifier: BSD-3-Clause
//
// Adapted from:
//
// - https://github.com/ooni/probe-engine/blob/v0.23.0/netx/resolver/decoder.go
//
// - https://github.com/golang/go/blob/go1.21.10/src/net/dnsclient_unix.go
//
// Response implementation
//

package dnscore

import (
	"errors"

	"github.com/miekg/dns"
)

// Additional errors emitted by [ValidateResponse].
var (
	// ErrInvalidQuery means that the query does not contain a single question.
	ErrInvalidQuery = errors.New("invalid query")
)

// ValidateResponse validates a given DNS response
// message for a given query message.
func ValidateResponse(query, resp *dns.Msg) error {
	// 1. make sure the message is actually a response
	if !resp.Response {
		return ErrInvalidResponse
	}

	// 2. make sure the response ID matches the query ID
	if resp.Id != query.Id {
		return ErrInvalidResponse
	}

	// 3. make sure the query and the response contains a question
	if len(resp.Question) != 1 {
		return ErrInvalidResponse
	}
	resp0 := resp.Question[0]
	if len(query.Question) != 1 {
		return ErrInvalidQuery
	}
	query0 := query.Question[0]

	// 4. make sure the question name is correct
	if !equalASCIIName(resp0.Name, query0.Name) {
		return ErrInvalidResponse
	}
	if resp0.Qclass != query0.Qclass {
		return ErrInvalidResponse
	}
	if resp0.Qtype != query0.Qtype {
		return ErrInvalidResponse
	}
	return nil
}

func equalASCIIName(x, y string) bool {
	if len(x) != len(y) {
		return false
	}
	for i := 0; i < len(x); i++ {
		a := x[i]
		b := y[i]
		if 'A' <= a && a <= 'Z' {
			a += 0x20
		}
		if 'A' <= b && b <= 'Z' {
			b += 0x20
		}
		if a != b {
			return false
		}
	}
	return true
}

// These error messages use the same suffixes used by the Go standard library.
var (
	// ErrCannotUnmarshalMessage indicates that we cannot unmarshal a DNS message.
	ErrCannotUnmarshalMessage = errors.New("cannot unmarshal DNS message")

	// ErrInvalidResponse means that the response is not a response message
	// or does not contain a single question matching the query.
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

// RCodeToError maps an RCODE inside a valid DNS response
// to an error string using a suffix compatible with the
// error strings returned by [*net.Resolver].
//
// For example, if a domain does not exist, the error
// will use the "no such host" suffix.
//
// If the RCODE is zero, this function returns nil.
func RCodeToError(resp *dns.Msg) error {
	// 1. handle NXDOMAIN case by mapping it to EAI_NONAME
	if resp.Rcode == dns.RcodeNameError {
		return ErrNoName
	}

	// 2. handle the case of lame referral by mapping it to EAI_NODATA
	if resp.Rcode == dns.RcodeSuccess &&
		!resp.Authoritative &&
		!resp.RecursionAvailable &&
		len(resp.Answer) == 0 {
		return ErrNoData
	}

	// 3. handle any other error by mapping to EAI_FAIL
	if resp.Rcode != dns.RcodeSuccess {
		if resp.Rcode == dns.RcodeServerFailure {
			return ErrServerTemporarilyMisbehaving
		}
		return ErrServerMisbehaving
	}
	return nil
}
