// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore_test

import (
	"context"
	"fmt"
	"log"
	"slices"
	"strings"

	"github.com/rbmk-project/dnscore"
)

func ExampleResolver() {
	// create resolver config and resolver
	config := dnscore.NewConfig()
	serverAddr := dnscore.NewServerAddr(dnscore.ProtocolDoT, "8.8.8.8:853")
	config.AddServer(serverAddr)
	reso := dnscore.NewResolver()
	reso.Config = config

	// issue the queries and merge the responses
	addrs, err := reso.LookupHost(context.Background(), "dns.google")
	if err != nil {
		log.Fatal(err)
	}

	// print the results
	slices.Sort(addrs)
	fmt.Printf("%s\n", strings.Join(addrs, "\n"))

	// Output:
	// 2001:4860:4860::8844
	// 2001:4860:4860::8888
	// 8.8.4.4
	// 8.8.8.8
}
