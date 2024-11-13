# DESIGN.md - dnscore

## Introduction

`dnscore` is a Go library designed for performing DNS measurements. Its high-level
API, `*dnscore.Resolver`, is compatible with `*net.Resolver`. Its low-level API,
`*dnscore.Transport`, provides granular control over performing DNS queries using
specific protocols (including UDP, TCP, TLS, and HTTPS).

## Architecture

### High-Level API

The high-level `*Resolver` API is designed to be compatible with Go's `*net.Resolver`. This
makes it easy for users to integrate `dnscore` with existing code or to perform
A/B testing with the standard library. Users of this API can customize the transport
used by a `*Resolver` to perform actual DNS lookups.

### Low-Level Transport

The low-level `*Transport` API allows its users to send individual DNS
queries and receive responses using specific protocols (e.g., DNS-over-HTTPS).

The `*ServerAddr` struct contains the server address and protocol.

Users can *customize* the `*Transport` behaviour by overriding function
pointers. For example, overriding `DialContext` allows to change the way
in which `*Transport` creates network connections.

Optionally, `*Transport` uses the `log/slog` package to emit structured logs,
whose JSON representation can be used for measurement purposes.

Optionally, `*Transport` can handle duplicate responses for DNS over UDP, which
are a typical signature of censorship in China and other countries.

The `*Transport` is low level in that it does not handle retries and does not
validate responses. However, `dnscore` includes utility functions for validating
DNS responses, mapping RCODEs to error messages, and extracting IP addresses
from DNS responses.

## Dependencies

We use [miekg/dns](https://github.com/miekg/dns) for parsing
and serializing DNS messages.

## Design Decisions

### Separation Between DNS and other layers

This package does not specify how to create and measure TCP and UDP
connections, which is handled by separate packages. We did this to make
separate measurement libraries very orthogonal to each other.

### Function Pointers for Customization

To keep the library simple and avoid excessive abstraction, we use function
pointers for customization. This allows users to override specific behaviors
without the need for agreeing on interfaces with other packages.

### Compatibility with `*dns.Resolver`

Providing an API compatible with `*dns.Resolver` ensures that `dnscore` can be
easily integrated with existing Go code. It also facilitates A/B testing with
the standard library, which may be useful for troubleshooting.

### Granular Control with Low-Level Transport

Exposing a low-level transport API provides users of this library with
maximum control over DNS queries and their processing.

### Decoupling Transport from Destination Server

The transport is immutable and designed to be decoupled from the destination
server, allowing it to handle multiple requests towards distinct servers concurrently. This
is achieved by putting the server address inside the separate `*ServerAddr` struct.
