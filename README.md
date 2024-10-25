# dnscore - DNS Measurement Library

`dnscore` is a Go library designed for performing DNS measurements. It
provides both high-level and low-level APIs to cater to different use
cases, from simple DNS lookups to detailed analysis of DNS responses.

## Features

- High-level API compatible with `*dns.Resolver`
- Low-level transport for granular control over DNS requests and
  responses
- Support for DNS over UDP (Do53), DNS over TLS (DoT), and DNS over
  HTTPS (DoH)
- Extensible with custom function pointers for advanced use cases
- Optional logging for measurement purposes
- Handling of duplicate responses for DNS over UDP

## Installation

```sh
go get github.com/rbmk-project/dnscore
```

## Usage

### High-Level API

The high-level API is designed to be compatible with Go's `*dns.Resolver`,
making it easy to integrate with existing code.

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/rbmk-project/dnscore"
)

func main() {
    resolver := dnscore.NewResolver()
    addrs, err := resolver.LookupHost(context.Background(), "www.example.com")
    if err != nil {
      log.Fatalf("resolver.LookupHost: %s", err.Error())
    }
    fmt.Printf("addrs: %s\n", addrs)
}
```

### Low-Level Transport

The low-level transport API provides more granular control, allowing you
to handle specific cases like DNS over UDP.

```go
package main

import (
    "context"
    "fmt"
    "os"
    "log/slog"

    "github.com/rbmk-project/dnscore"
    "github.com/miekg/dns"
)

func main() {
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
}
```

## Customization

You can customize the behavior of the resolver and transport by providing
custom function pointers. If these pointers are `nil`, the standard
library functions will be used.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request
on GitHub.

## License

```
SPDX-License-Identifier: GPL-3.0-or-later
```
