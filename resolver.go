//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/ooni/probe-cli/blob/v3.20.1/internal/netxlite/resolverparallel.go
//

package dnscore

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// ResolverTransport is the interface defining the [*Transport]
// methods used by the [*Resolver] struct.
//
// The [*Transport] type implements this interface.
type ResolverTransport interface {
	Query(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error)
}

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
	Transport ResolverTransport
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

// resolverLookupResult is the result of a lookup operation.
type resolverLookupResult struct {
	addrs []string
	err   error
}

// LookupHost looks up the given host named using the DNS resolver.
func (r *Resolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	// start A and AAAA lookups in the background to speed up the process
	// then wait for both of them to terminate
	//
	// note: when the context is canceled, the lookup terminates immediately
	ach := make(chan *resolverLookupResult)
	go func() {
		var result resolverLookupResult
		result.addrs, result.err = r.LookupA(ctx, host)
		ach <- &result
	}()
	aaaach := make(chan *resolverLookupResult)
	go func() {
		var result resolverLookupResult
		result.addrs, result.err = r.LookupAAAA(ctx, host)
		aaaach <- &result
	}()
	ares, aaaares := <-ach, <-aaaach

	// merge addresses to return a single list to the caller
	addrs := append(append([]string{}, ares.addrs...), aaaares.addrs...)

	// handle the case of no addresses
	//
	// if there's an error, give priority to the A error because not all
	// domains have AAAA records; as a fallback, when there's no error just
	// say that the queries returned no data
	if len(addrs) < 1 {
		if ares.err != nil && !errors.Is(ares.err, ErrNoData) {
			return nil, ares.err
		}
		if aaaares.err != nil && !errors.Is(aaaares.err, ErrNoData) {
			return nil, aaaares.err
		}
		return nil, ErrNoData
	}

	// deduplicate addresses and sort IPv4 before IPv6
	addrs = resolverDedupAndSort(addrs)
	return addrs, nil
}

// resolverDedupAndSort deduplicates a list of addresses and sorts IPv4
// addresses before IPv6 addresses. In principle, DNS resolvers should not
// return duplicates, but, with censorship, it is possible that the AAAA
// query answer is actually a censored A answer. Additionally, since we
// don't implement RFC6724, we sort IPv4 addresses before IPv6 addresses,
// given that everyone supports IPv4 and not everyone supports IPv6.
func resolverDedupAndSort(addrs []string) []string {
	uniq := make(map[string]struct{})
	var dedupA, dedupAAAA []string
	for _, addr := range addrs {
		if _, ok := uniq[addr]; !ok {
			uniq[addr] = struct{}{}
			if strings.Contains(addr, ":") {
				dedupAAAA = append(dedupAAAA, addr)
				continue
			}
			dedupA = append(dedupA, addr)
		}
	}
	result := make([]string, 0, len(dedupA)+len(dedupAAAA))
	result = append(result, dedupA...)
	result = append(result, dedupAAAA...)
	return result
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
