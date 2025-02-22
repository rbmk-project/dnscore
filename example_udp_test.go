// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore_test

import (
	"context"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rbmk-project/common/runtimex"
	"github.com/rbmk-project/dnscore"
)

func ExampleTransport_dnsOverUDP() {
	// create transport, server addr, and query
	txp := &dnscore.Transport{}
	serverAddr := &dnscore.ServerAddr{
		Protocol: dnscore.ProtocolUDP,
		Address:  "8.8.8.8:53",
	}
	options := []dnscore.QueryOption{
		dnscore.QueryOptionEDNS0(
			dnscore.EDNS0SuggestedMaxResponseSizeUDP,
			0,
		),
	}
	query, err := dnscore.NewQueryWithServerAddr(serverAddr, "dns.google", dns.TypeA, options...)
	if err != nil {
		log.Fatal(err)
	}

	// issue the query and get the response
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := txp.Query(ctx, serverAddr, query)
	if err != nil {
		log.Fatal(err)
	}

	// validate the response
	if err := dnscore.ValidateResponse(query, resp); err != nil {
		log.Fatal(err)
	}
	runtimex.Assert(len(query.Question) > 0, "expected at least one question")
	rrs, err := dnscore.ValidAnswers(query.Question[0], resp)
	if err != nil {
		log.Fatal(err)
	}

	// print the results
	var addrs []string
	for _, rr := range rrs {
		switch rr := rr.(type) {
		case *dns.A:
			addrs = append(addrs, rr.A.String())
		}
	}
	slices.Sort(addrs)
	fmt.Printf("%s\n", strings.Join(addrs, "\n"))

	// Output:
	// 8.8.4.4
	// 8.8.8.8
}
