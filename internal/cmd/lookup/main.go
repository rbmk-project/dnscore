// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/rbmk-project/common/runtimex"
	"github.com/rbmk-project/dnscore"
)

func main() {
	// Define command-line flags
	domain := flag.String("domain", "www.example.com", "Domain to query")

	// Parse command-line flags
	flag.Parse()

	// Set up the JSON logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{}))
	transport := dnscore.NewTransport()
	transport.Logger = logger

	// Create the resolver
	reso := dnscore.NewResolver()
	reso.Transport = transport

	// Resolve the domain
	addrs := runtimex.Try1(reso.LookupHost(context.Background(), *domain))
	fmt.Printf("%s\n", addrs)
}
