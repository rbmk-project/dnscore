// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

// Protocol is a transport protocol.
type Protocol string

// All the implemented DNS protocols.
const (
	// ProtocolUDP is DNS over UDP.
	ProtocolUDP = Protocol("udp")

	// ProtocolTCP is DNS over TCP.
	ProtocolTCP = Protocol("tcp")

	// ProtocolDoT is DNS over TLS.
	ProtocolDoT = Protocol("dot")

	// ProtocolDoH is DNS over HTTPS.
	ProtocolDoH = Protocol("doh")
)

// Name aliases for DNS protocols.
const (
	// ProtocolTLS is an alias for ProtocolDoT.
	ProtocolTLS = ProtocolDoT

	// ProtocolHTTPS is an alias for ProtocolDoH.
	ProtocolHTTPS = ProtocolDoH
)

// ServerAddr is a DNS server address.
//
// While currently minimal, ServerAddr is designed as a pointer type to
// allow for future extensions of server-specific properties (e.g., custom
// headers for DoH) without requiring breaking API changes.
//
// Construct using [NewServerAddr].
type ServerAddr struct {
	// Protocol is the transport protocol to use.
	//
	// Use one of:
	//
	// - [ProtocolUDP]
	// - [ProtocolTCP]
	// - [ProtocolDoT]
	// - [ProtocolDoH]
	Protocol Protocol

	// Address is the network address of the server.
	//
	// For [ProtocolUDP], [ProtocolTCP], and [ProtocolDoT] this is
	// a string in the form returned by [net.JoinHostPort].
	//
	// For [ProtocolDoH] this is a URL.
	Address string
}

// NewServerAddr constructs a new [*ServerAddr] with the given protocol and address.
func NewServerAddr(protocol Protocol, address string) *ServerAddr {
	return &ServerAddr{
		Protocol: protocol,
		Address:  address,
	}
}
