//
// SPDX-License-Identifier: BSD-3-Clause
//
// Adapted from: https://github.com/ooni/probe-engine/blob/v0.23.0/netx/resolver/dnsovertcp.go
//
// DNS-over-TCP implementation
//

package dnscore

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"

	"github.com/miekg/dns"
)

// queryTCP implements [*Transport.Query] for DNS over TCP.
func (t *Transport) queryTCP(ctx context.Context,
	addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
	// 0. immediately fail if the context is already done, which
	// is useful to write unit tests
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// 1. Dial the connection
	conn, err := t.dialContext(ctx, "tcp", addr.Address)

	// 2. Handle dialing failure
	if err != nil {
		return nil, err
	}

	// 3. Transfer conn ownership and perform the round trip
	return t.queryStream(ctx, addr, query, conn)
}

// ErrQueryTooLargeForTransport indicates that a query is too large for the transport.
var ErrQueryTooLargeForTransport = errors.New("query too large for transport")

// queryMsg is an interface modeling [*dns.Msg] to allow for
// testing [*Transport.queryStream] more easily.
type queryMsg interface {
	Pack() ([]byte, error)
}

// queryStream performs the round trip over the given TCP/TLS stream.
//
// This method TAKES OWNERSHIP of the provided connection and is
// responsible for closing it when done.
func (t *Transport) queryStream(ctx context.Context,
	addr *ServerAddr, query queryMsg, conn net.Conn) (*dns.Msg, error) {

	// 1. Use a single connection for request, which is what the standard library
	// does as well for TCP and is more robust in terms of residual censorship.
	//
	// In the future, we may want to reuse a TLS connection for multiple queries
	//
	// Make sure we react to context being canceled early.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		defer conn.Close()
		<-ctx.Done()
	}()

	// 2. Use the context deadline to limit the query lifetime
	// as documented in the [*Transport.Query] function.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	// 3. Serialize the query and possibly log that we're sending it.
	rawQuery, err := query.Pack()
	if err != nil {
		return nil, err
	}
	t0 := t.maybeLogQuery(ctx, addr, rawQuery)

	// 4. Wrap the query into a frame
	rawQueryFrame, err := newRawMsgFrame(addr, rawQuery)
	if err != nil {
		return nil, err
	}

	// 5. Send the query. Do not bother with logging the write call
	// since that should be done by a custom dialer that wraps the
	// returned connection and implements the desired logging.
	if _, err := conn.Write(rawQueryFrame); err != nil {
		return nil, err
	}

	// 6. Wrap the conn to avoid issuing too many reads
	// then read the response header and query
	br := bufio.NewReader(conn)
	header := make([]byte, 2)
	if _, err := io.ReadFull(br, header); err != nil {
		return nil, err
	}
	length := int(header[0])<<8 | int(header[1])
	rawResp := make([]byte, length)
	if _, err := io.ReadFull(br, rawResp); err != nil {
		return nil, err
	}

	// 7. Parse the response and possibly log that we received it.
	resp := new(dns.Msg)
	if err := resp.Unpack(rawResp); err != nil {
		return nil, err
	}
	t.maybeLogResponseConn(ctx, addr, t0, rawQuery, rawResp, conn)
	return resp, nil
}

// newRawMsgFrame creates a new raw frame for sending a message over TCP or TLS.
func newRawMsgFrame(addr *ServerAddr, rawMsg []byte) ([]byte, error) {
	if len(rawMsg) > math.MaxUint16 {
		return nil, fmt.Errorf("%w: %s", ErrQueryTooLargeForTransport, addr.Protocol)
	}
	rawMsgFrame := []byte{byte(len(rawMsg) >> 8)}
	rawMsgFrame = append(rawMsgFrame, byte(len(rawMsg)))
	rawMsgFrame = append(rawMsgFrame, rawMsg...)
	return rawMsgFrame, nil
}
