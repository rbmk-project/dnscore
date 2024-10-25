// SPDX-License-Identifier: GPL-3.0-or-later

/*
Package dnscore provides a DNS resolver, a DNS transport, a query builder,
and a DNS response parser.

This package is designed to facilitate DNS measurements and queries
by providing both high-level and low-level APIs. It aims to be flexible,
extensible, and easy to integrate with existing Go code.

The high-level API provides a DNS resolver that is compatible with the
net.Resolver struct from the net package. The low-level transport API
allows users to send and receive DNS messages using different protocols
and dialers. The package also includes utilities for creating and validating
DNS messages.

# Features

- High-level API compatible with *dns.Resolver for easy integration.
- Low-level transport API for granular control over DNS requests and responses.
- Support for multiple DNS protocols, including UDP, TCP, DoT, and DoH.
- Utilities for creating and validating DNS messages.
- Optional logging for structured diagnostic events.
- Handling of duplicate responses for DNS over UDP to measure censorship.

The package is structured to allow users to compose their own workflows
by providing building blocks for DNS queries and responses. It leverages
the well-tested miekg/dns library for DNS message parsing and serialization.

# High-Level API

	resolver := dnscore.NewResolver()
	addrs, err := resolver.LookupHost(context.Background(), "www.example.com")
	if err != nil {
		log.Fatalf("resolver.LookupHost: %s", err.Error())
	}
	fmt.Printf("addrs: %s\n", addrs)

# Low-Level Transport

	logger := slog.New(slog.NewTextHandler(os.Stdout))
	transport := dnscore.NewTransport(logger)
	serverAddr := dnscore.NewServerAddr(dnscore.ProtocolUDP, "8.8.8.8:53")

	query, err := dnscore.CreateQuery("www.example.com", dns.TypeA)
	if err != nil {
		log.Fatalf("dnscore.CreateQuery: %s", err.Error())
	}
	fmt.Printf("%s\n\n", query.String())

	response, err := transport.Query(context.Background(), serverAddr, query)
	if err != nil {
		log.Fatalf("transport.Query: %s", err.Error())
	}
	fmt.Printf("%s\n\n", response.String())

	if err = dnscore.ValidateResponse(query, response); err != nil {
		log.Fatalf("dnscore.ValidateResponse: %s", err.Error())
	}

	if err := dnscore.RCodeToError(response); err != nil {
		log.Fatalf("dnscore.RCodeToError: %s", err.Error())
	}
*/
package dnscore
