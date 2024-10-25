// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import (
	"context"

	"github.com/miekg/dns"
)

// transport returns the tranport to use for resolving queries, which is
// either the transport specified in the resolver or the default.
func (r *Resolver) transport() *Transport {
	if r.Transport != nil {
		return r.Transport
	}
	return DefaultTransport
}

// lookup is the internal implementation of the Lookup* functions.
func (r *Resolver) lookup(ctx context.Context, name string, qtype uint16) ([]dns.RR, error) {
	// TODO(bassosimone): see how the stdlib handles retries

	// TODO(bassosimone): we need to handle .onion domains

	// TODO(bassosimone): we probably want an operation timeout here

	// TODO(bassosimone): allow to configure the server address
	addr := &ServerAddr{Address: "8.8.8.8:53", Protocol: ProtocolUDP}

	// TODO(bassosimone): allow to configure options
	var options []QueryOption

	// Encode the query
	query, err := NewQuery(name, qtype, options...)
	if err != nil {
		return nil, err
	}
	q0 := query.Question[0] // we know it's present because we just created it

	// Obtain the transport and perform the query
	resp, err := r.transport().Query(ctx, addr, query)
	if err != nil {
		return nil, err
	}

	// Validate the response, check for errors and extract RRs
	if err := ValidateResponse(query, resp); err != nil {
		return nil, err
	}
	if err := RCodeToError(resp); err != nil {
		return nil, err
	}
	return ValidAnswers(q0, resp)
}
