// SPDX-License-Identifier: GPL-3.0-or-later

// Command transport shows how to use the transport to perform a DNS lookup.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/miekg/dns"
	"github.com/rbmk-project/common/runtimex"
	"github.com/rbmk-project/dnscore"
)

// Define command-line flags
var (
	serverAddr = flag.String("server", "8.8.8.8:53", "DNS server address")
	domain     = flag.String("domain", "www.example.com", "Domain to query")
	qtype      = flag.String("type", "A", "Query type (A, AAAA, CNAME, etc.)")
	protocol   = flag.String("protocol", "udp", "DNS protocol (udp, tcp, dot, doh)")
)

func main() {
	// Parse command-line flags
	flag.Parse()

	// Set up the JSON logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{}))
	transport := &dnscore.Transport{}
	transport.Logger = logger

	// Determine the DNS query type
	var dnsType uint16
	switch *qtype {
	case "A":
		dnsType = dns.TypeA
	case "AAAA":
		dnsType = dns.TypeAAAA
	case "CNAME":
		dnsType = dns.TypeCNAME
	case "HTTPS":
		dnsType = dns.TypeHTTPS
	default:
		panic(fmt.Errorf("transport: unsupported query type: %s", *qtype))
	}

	// Create the server address
	server := dnscore.NewServerAddr(dnscore.Protocol(*protocol), *serverAddr)
	flags := 0
	maxlength := uint16(dnscore.EDNS0SuggestedMaxResponseSizeUDP)
	if *protocol == string(dnscore.ProtocolDoT) || *protocol == string(dnscore.ProtocolDoH) {
		flags |= dnscore.EDNS0FlagDO | dnscore.EDNS0FlagBlockLengthPadding
	}
	if *protocol != string(dnscore.ProtocolUDP) {
		maxlength = dnscore.EDNS0SuggestedMaxResponseSizeOtherwise
	}

	// Create the DNS query
	optEDNS0 := dnscore.QueryOptionEDNS0(maxlength, flags)
	query := runtimex.Try1(dnscore.NewQueryWithServerAddr(server, *domain, dnsType, optEDNS0))
	fmt.Printf(";; Query:\n%s\n", query.String())

	// Perform the DNS query
	response := runtimex.Try1(transport.Query(context.Background(), server, query))
	fmt.Printf("\n;; Response:\n%s\n\n", response.String())

	// Validate the DNS response
	runtimex.Try0(dnscore.ValidateResponse(query, response))

	// Map the RCODE to an error, if any
	runtimex.Try0(dnscore.RCodeToError(response))
}
