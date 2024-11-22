// SPDX-License-Identifier: GPL-3.0-or-later

package dnscoretest

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
)

// Server is a fake DNS server.
//
// The zero value is a valid server.
type Server struct {
	// Addr is the address of the server for DNS-over-UDP,
	// DNS-over-TCP, and DNS-over-TLS.
	Addr string

	// Listen is an optional func to override the default
	// function used to create a [net.Listener].
	Listen func(network, address string) (net.Listener, error)

	// ListenPacket is an optional func to override the default
	// function used to create a listening [net.PacketConn].
	ListenPacket func(network, address string) (net.PacketConn, error)

	// ListenTLS is an optional func to override the default
	// function used to listen using TLS.
	ListenTLS func(network, address string, config *tls.Config) (net.Listener, error)

	// RootCAs contains the cert pool the client should use
	// for DNS-over-TLS and DNS-over-HTTPS.
	RootCAs *x509.CertPool

	// URL is the URL for DNS-over-HTTPS.
	URL string

	// ioclosers is a list of ioclosers to close when the server is closed.
	ioclosers []io.Closer

	// started indicates that the server has started.
	started bool
}

// Close closes the server.
func (s *Server) Close() error {
	var err error
	for _, c := range s.ioclosers {
		if cerr := c.Close(); cerr != nil {
			err = cerr
		}
	}
	return err
}
