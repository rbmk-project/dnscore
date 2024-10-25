//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// DNS-over-TLS implementation
//

package dnscore

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/miekg/dns"
)

// dialTLSContext is a helper function that dials a network address using the
// given dialer or the default dialer if the given dialer is nil.
func (t *Transport) dialTLSContext(ctx context.Context, network, address string) (net.Conn, error) {
	if t.DialTLSContext != nil {
		return t.DialTLSContext(ctx, network, address)
	}

	// Fill in a default TLS config
	hostname, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		InsecureSkipVerify: false,
		NextProtos:         []string{"dot"},
		RootCAs:            nil, // use the stdlib default
		ServerName:         hostname,
	}

	// Defer to the stdlib TLS dialer
	dialer := &tls.Dialer{Config: config}
	return dialer.DialContext(ctx, network, address)
}

// queryTLS implements [*Transport.Query] for DNS over TLS.
func (t *Transport) queryTLS(ctx context.Context,
	addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
	// 1. Dial the TLS connection
	conn, err := t.dialTLSContext(ctx, "tcp", addr.Address)

	// 2. Handle dialing failure
	if err != nil {
		return nil, err
	}

	// 3. Transfer conn ownership and perform the round trip
	return t.queryStream(ctx, addr, query, conn)
}
