// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import "context"

// Resolver is a DNS resolver. This struct is API compatible with
// the [*net.Resolver] struct from the [net] package.
//
// Construct using [NewResolver].
type Resolver struct {
	// Transport is the DNS transport to use for resolving queries.
	//
	// If nil, we use [DefaultTransport].
	Transport *Transport
}

// LookupHost looks up the given host named using the DNS resolver.
func (r *Resolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return nil, nil
}
