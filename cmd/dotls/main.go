// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/miekg/dns"
	"github.com/rbmk-project/dnscore"
)

func main() {
	// Define command-line flags
	serverAddr := flag.String("server", "8.8.8.8:853", "DNS server address")
	domain := flag.String("domain", "www.example.com", "Domain to query")
	qtype := flag.String("qtype", "A", "Query type (A, AAAA, CNAME, etc.)")

	// Parse command-line flags
	flag.Parse()

	// Set up the JSON logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{}))
	transport := dnscore.NewTransport()
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
		log.Fatalf("Unsupported query type: %s", *qtype)
	}

	// Create the server address
	server := dnscore.NewServerAddr(dnscore.ProtocolDoT, *serverAddr)

	// Create the DNS query
	optEDNS0 := dnscore.QueryOptionEDNS0(4096,
		dnscore.EDNS0FlagDO|dnscore.EDNS0FlagBlockLengthPadding)
	query, err := dnscore.NewQuery(*domain, dnsType, optEDNS0)
	if err != nil {
		log.Fatalf("dnscore.NewQuery: %s", err.Error())
	}
	fmt.Printf("Query:\n%s\n", query.String())

	// Perform the DNS query
	response, err := transport.Query(context.Background(), server, query)
	if err != nil {
		log.Fatalf("transport.Query: %s", err.Error())
	}
	fmt.Printf("\nResponse:\n%s\n\n", response.String())

	// Validate the DNS response
	if err = dnscore.ValidateResponse(query, response); err != nil {
		log.Fatalf("dnscore.ValidateResponse: %s", err.Error())
	}

	// Map the RCODE to an error, if any
	if err := dnscore.RCodeToError(response); err != nil {
		log.Fatalf("dnscore.RCodeToError: %s", err.Error())
	}
}
