// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import (
	"sync"
	"time"
)

// ResolverConfig contains configuration for the resolver.
//
// Construct using [NewConfig].
//
// This struct is safe for concurrent use by multiple goroutines.
//
// If the configuration is empty, it uses the "8.8.8.8:53/udp"
// and "8.8.4.4:53/udp" servers as the default servers.
type ResolverConfig struct {
	// attempts is the number of attempts to make for each query.
	attempts int

	// list contains the list of configured servers.
	list []resolverConfigServer

	// mu is the mutex for the config.
	mu sync.RWMutex
}

// DefaultAttempts is the default number of attempts to make for each query.
const DefaultAttempts = 2

// NewConfig creates a new resolver configuration.
func NewConfig() *ResolverConfig {
	return &ResolverConfig{
		attempts: DefaultAttempts,
		list:     []resolverConfigServer{},
		mu:       sync.RWMutex{},
	}
}

// SetAttempts sets the number of attempts to make for each query.
func (c *ResolverConfig) SetAttempts(attempts int) {
	c.mu.Lock()
	c.attempts = attempts
	c.mu.Unlock()
}

// Attempts returns the number of attempts to make for each query.
func (c *ResolverConfig) Attempts() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.attempts
}

// resolverConfigServer contains configuration for a single resolver server.
//
// Construct a new instance using [newResolverConfigServer].
type resolverConfigServer struct {
	// address is the address of the server.
	address *ServerAddr

	// queryOptions is the list of query options to use
	// for constructing queries to this server.
	queryOptions []QueryOption

	// timeout is the timeout for each query.
	timeout time.Duration
}

// AddServerOption is an option for adding a server to the resolver configuration.
type AddServerOption func(*resolverConfigServer)

// ServerOptionQueryOptions sets the query options to use for constructing queries
// to this specific server.If this option is not used, we use the default query options
// suitable for the protocol used by the server. Specifically, we enable DNSSEC
// validation and block-length padding for DNS-over-HTTPS and DNS-over-TLS servers.
func ServerOptionQueryOptions(queryOptions ...QueryOption) AddServerOption {
	return func(s *resolverConfigServer) {
		s.queryOptions = queryOptions
	}
}

// DefaultQueryTimeout is the default timeout for each query.
const DefaultQueryTimeout = 2 * time.Second

// ServerOptionQueryTimeout sets the timeout for each query.
//
// If this option is not used, we use the [DefaultQueryTimeout] default.
func ServerOptionQueryTimeout(timeout time.Duration) AddServerOption {
	return func(s *resolverConfigServer) {
		s.timeout = timeout
	}
}

// newResolverConfigServer creates a new resolver server configuration.
func newResolverConfigServer(address *ServerAddr, options ...AddServerOption) resolverConfigServer {
	server := resolverConfigServer{
		address:      address,
		queryOptions: []QueryOption{},
		timeout:      DefaultQueryTimeout,
	}

	// apply the default query options suitable for the protocol used by the server
	switch address.Protocol {
	case ProtocolDoH, ProtocolDoT:
		server.queryOptions = append(server.queryOptions, QueryOptionEDNS0(
			EDNS0SuggestedMaxResponseSizeOtherwise,
			EDNS0FlagDO|EDNS0FlagBlockLengthPadding))

	case ProtocolTCP:
		server.queryOptions = append(server.queryOptions, QueryOptionEDNS0(
			EDNS0SuggestedMaxResponseSizeOtherwise, 0))

	case ProtocolUDP:
		server.queryOptions = append(server.queryOptions, QueryOptionEDNS0(
			EDNS0SuggestedMaxResponseSizeUDP, 0))
	}

	// apply the user-provided resolver config options
	for _, option := range options {
		option(&server)
	}

	return server
}

// AddServer adds a new server to the resolver configuration.
func (c *ResolverConfig) AddServer(address *ServerAddr, options ...AddServerOption) {
	c.mu.Lock()
	c.list = append(c.list, newResolverConfigServer(address, options...))
	c.mu.Unlock()
}

// servers returns the list of configured servers.
func (c *ResolverConfig) servers() []resolverConfigServer {
	// copy the list of servers
	c.mu.RLock()
	list := append([]resolverConfigServer(nil), c.list...)
	c.mu.RUnlock()

	// if empty, create the default servers
	if len(list) == 0 {
		defaultAddrs := []string{"8.8.8.8", "8.8.4.4"}
		for _, addr := range defaultAddrs {
			list = append(list, newResolverConfigServer(
				NewServerAddr(ProtocolUDP, addr+":53"),
				ServerOptionQueryOptions(QueryOptionEDNS0(
					EDNS0SuggestedMaxResponseSizeUDP, 0))))
		}
	}
	return list
}
