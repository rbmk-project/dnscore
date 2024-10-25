# DESIGN.md - dnscore

## Introduction

`dnscore` is a Go library designed for performing DNS measurements. It aims to
provide both high-level and low-level APIs to cater to different use cases, from
simple DNS lookups to detailed analysis of DNS responses.

## Architecture

### High-Level API

The high-level API is designed to be compatible with Go's `*dns.Resolver`. This
makes it easy for users to integrate `dnscore` with existing code and perform
A/B testing with the standard library.

- **Resolver**: The `Resolver` type provides methods for performing DNS lookups,
  such as `LookupHost`, `LookupIP`, etc.
- **Customization**: Users can provide a custom `Transport` for DNS resolution.

### Low-Level Transport

The low-level transport API provides more granular control over DNS requests and
responses. This is useful for handling specific cases like DNS over UDP, where
duplicate responses might be received.

- **Transport**: The `Transport` type provides methods for sending DNS queries
  and receiving responses.
- **ServerAddr**: The `ServerAddr` struct encapsulates the server address and
  protocol.
- **Customization**: Users can provide custom function pointers for creating
  network connections, etc. If these pointers are `nil`, the standard library
  functions will be used.
- **Logging**: Optional structured logging for measurement purposes.
- **Duplicate Response Handling**: Optional handling of duplicate responses for
  DNS over UDP, to address censorship measurement needs.

## Dependencies

`dnscore` leverages existing libraries for DNS parsing and serialization to
avoid reinventing the wheel. The primary dependency is the `miekg/dns` library,
which is well-tested and widely used in the Go community.

## Design Decisions

### Function Pointers for Customization

To keep the library simple and avoid excessive abstraction, we use function
pointers for customization. This allows users to override specific behaviors
without the need for complex interfaces.

### Compatibility with `*dns.Resolver`

Providing an API compatible with `*dns.Resolver` ensures that `dnscore` can be
easily integrated with existing Go code. It also facilitates A/B testing with
the standard library.

### Granular Control with Low-Level Transport

Exposing a low-level transport API allows users to handle specific cases like
DNS over UDP more effectively. This is particularly useful for measuring DNS
censorship and analyzing duplicate responses.

### Decoupling Transport from Destination Server

The transport is designed to be decoupled from the destination server, allowing
it to handle multiple requests concurrently. This is achieved by encapsulating
the server address within the `ServerAddr` structure.

## Future Work

- **Support for Additional Protocols**: Extend support to other DNS protocols
  like DNS over HTTP/3 (DoH3) and DNS over QUIC (DoQ).
- **Enhanced Metrics**: Provide more detailed metrics and logging for DNS
  measurements.
- **Improved Customization**: Explore additional customization options, such as
  middleware for DNS requests and responses.

## Conclusion

`dnscore` is designed to be a flexible and extensible library for DNS
measurements. By providing both high-level and low-level APIs, it caters to a
wide range of use cases while keeping the design simple and maintainable.
