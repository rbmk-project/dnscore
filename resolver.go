// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import (
	"context"
	"errors"
	"net"

	"github.com/miekg/dns"
)

// Resolver is a DNS resolver. This struct is API compatible with
// the [*net.Resolver] struct from the [net] package.
//
// Construct using [NewResolver].
type Resolver struct {
	// Config is the optional resolver configuration.
	//
	// If nil, we use an empty [*ResolverConfig].
	Config *ResolverConfig

	// Transport is the optional DNS transport to use for resolving queries.
	//
	// If nil, we use [DefaultTransport].
	Transport *Transport
}

// NewResolver creates a new DNS resolver with default settings.
func NewResolver() *Resolver {
	return &Resolver{}
}

// config returns the resolver configuration or a default one.
func (r *Resolver) config() *ResolverConfig {
	if r.Config == nil {
		return NewConfig()
	}
	return r.Config
}

// LookupHost looks up the given host named using the DNS resolver.
func (r *Resolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	// TODO(bassosimone): this is a simplified implementation
	// that does not perform the queries in parallel.
	addrsA, errA := r.LookupA(ctx, host)
	addrsAAAA, errAAAA := r.LookupAAAA(ctx, host)
	addrs := append([]string{}, addrsA...)
	addrs = append(addrs, addrsAAAA...)
	if errA != nil && errAAAA != nil {
		return nil, errors.Join(errA, errAAAA)
	}
	if len(addrs) < 1 {
		return nil, ErrNoData
	}
	return addrs, nil
}

// LookupA resolves the IPv4 addresses of a given domain.
func (r *Resolver) LookupA(ctx context.Context, host string) ([]string, error) {
	// Behave like getaddrinfo when the host is an IP address.
	if net.ParseIP(host) != nil {
		return []string{host}, nil
	}

	// Obtain the RRs
	rrs, err := r.lookup(ctx, host, dns.TypeA)
	if err != nil {
		return nil, err
	}

	// Decode as IPv4 addresses and CNAME
	addrs, _, err := DecodeLookupA(rrs)
	return addrs, err
}

// LookupAAAA resolves the IPv6 addresses of a given domain.
func (r *Resolver) LookupAAAA(ctx context.Context, host string) ([]string, error) {
	// Behave like getaddrinfo when the host is an IP address.
	if net.ParseIP(host) != nil {
		return []string{host}, nil
	}

	// Obtain the RRs
	rrs, err := r.lookup(ctx, host, dns.TypeAAAA)
	if err != nil {
		return nil, err
	}

	// Decode as IPv6 addresses and CNAME
	addrs, _, err := DecodeLookupAAAA(rrs)
	return addrs, err
}
