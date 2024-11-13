// SPDX-License-Identifier: GPL-3.0-or-later

package dnscoretest_test

import (
	"fmt"
	"log"
	"slices"
	"strings"

	"github.com/miekg/dns"
	"github.com/rbmk-project/dnscore/dnscoretest"
)

func ExampleServer_udp() {
	// Create a fake UDP server using the example.com handler
	server := &dnscoretest.Server{}
	handler := dnscoretest.NewExampleComHandler()
	<-server.StartUDP(handler)
	defer server.Close()

	// Create a DNS client
	client := &dns.Client{Net: "udp"}
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	// Send the query to the fake server
	resp, _, err := client.Exchange(query, server.Addr)
	if err != nil {
		log.Fatal(err)
	}

	// print the results
	var addrs []string
	for _, rr := range resp.Answer {
		switch rr := rr.(type) {
		case *dns.A:
			addrs = append(addrs, rr.A.String())
		}
	}
	slices.Sort(addrs)
	fmt.Printf("%s\n", strings.Join(addrs, "\n"))

	// Output:
	// 93.184.215.14
}
