# dnscore - DNS Measurement Library

[![GoDoc](https://pkg.go.dev/badge/github.com/rbmk-project/dnscore)](https://pkg.go.dev/github.com/rbmk-project/dnscore)

`dnscore` is a Go library designed for performing DNS measurements.  Its high-level
API, `*dnscore.Resolver`, is compatible with `*net.Resolver`. Its low-level API,
`*dnscore.Transport`, provides granular control over performing DNS queries using
specific protocols (including UDP, TCP, TLS, and HTTPS).

## Features

- High-level `*Resolver` API compatible with `*net.Resolver` for easy integration.
- Low-level `*Transport` API allowing granular control over DNS requests and responses.
- Support for multiple DNS protocols, including UDP, TCP, DoT, and DoH.
- Utilities for creating and validating DNS messages.
- Optional logging for structured diagnostic events through `log/slog`.
- Handling of duplicate responses for DNS over UDP to measure censorship.

The package is structured to allow users to compose their own workflows
by providing building blocks for DNS queries and responses. It uses
the widely-used [miekg/dns](https://github.com/miekg/dns) library for
DNS message parsing and serialization.

## Installation

```sh
go get github.com/rbmk-project/dnscore
```

## Usage

### High-Level API

The `*dnscore.Resolver` API is compatible with `*net.Resolver`.

See [example_resolver_test.go](example_resolver_test.go) for a complete example.

### Low-Level Transport

The `*dnscore.Transport` API provides granular control over DNS queries and responses.

See

- [example_https_test.go](example_https_test.go)
- [example_tcp_test.go](example_tcp_test.go)
- [example_tls_test.go](example_tls_test.go)
- [example_udp_test.go](example_udp_test.go)

for complete examples using DNS over HTTPS, TCP, TLS, and UDP respectively.

## Design

See [DESIGN.md](DESIGN.md) for an overview of the design.

## Contributing

Contributions are welcome! Please submit a pull requests
using GitHub. Use [rbmk-project/issues](https://github.com/rbmk-project/issues)
to create issues and discuss features related to this package.

## License

```
SPDX-License-Identifier: GPL-3.0-or-later
```
