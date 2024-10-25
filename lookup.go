//
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// SPDX-License-Identifier: BSD-3-Clause
//
// Adapted from: https://github.com/golang/go/blob/go1.21.10/src/net/dnsclient_unix.go
//
// Resolver code to send queries and receive responses
// along with BSD-licensed code from the stdlib.
//

package dnscore

import (
	"context"
	"errors"

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

// exchange implements [*Resolver.lookup] with a specific server.
func (r *Resolver) exchange(ctx context.Context,
	name string, qtype uint16, server resolverConfigServer) ([]dns.RR, error) {
	// Handle the case of domains that should not be resolved
	labels := dns.SplitDomainName(dns.CanonicalName(name))
	if len(labels) > 0 && labels[len(labels)-1] == "onion" {
		return nil, ErrNoData
	}

	// Enforce an operation timeout
	if server.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, server.timeout)
		defer cancel()
	}

	// Encode the query
	query, err := NewQuery(name, qtype, server.queryOptions...)
	if err != nil {
		return nil, err
	}
	q0 := query.Question[0] // we know it's present because we just created it

	// Obtain the transport and perform the query
	resp, err := r.transport().Query(ctx, server.address, query)
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

// lookup is the internal implementation of the Lookup* functions.
func (r *Resolver) lookup(ctx context.Context,
	name string, qtype uint16) ([]dns.RR, error) {
	// by default, on failure, we return the EAI_NODATA equivalent
	lastErr := ErrNoData

	// obtain the list of servers and prepare to walk it
	var (
		config   = r.config()
		attempts = config.Attempts()
		servers  = config.servers()
	)
	for idx := 0; len(servers) > 0 && idx < attempts; idx++ {
		// select a server and exchange the query
		server := servers[uint32(idx)%uint32(len(servers))]
		rrs, err := r.exchange(ctx, name, qtype, server)

		// immediately handle success and stop on NXDOMAIN
		//
		// note: it's not so common to use NXDOMAIN for censorship
		// so this is a trade off to privilege fast convergence
		if err == nil {
			return rrs, nil
		}
		if errors.Is(err, ErrNoName) {
			return nil, err
		}

		lastErr = err
	}

	return nil, lastErr
}
