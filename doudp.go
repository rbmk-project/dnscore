//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// DNS over UDP protocol.
//
// Adapted from: https://github.com/ooni/probe-engine/blob/v0.23.0/netx/resolver/dnsoverudp.go
//

package dnscore

import (
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/miekg/dns"
)

// dialContext is a helper function that dials a network address using the
// given dialer or the default dialer if the given dialer is nil.
func (t *Transport) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if t.DialContext != nil {
		return t.DialContext(ctx, network, address)
	}
	dialer := &net.Dialer{}
	return dialer.DialContext(ctx, network, address)
}

// timeNow is a helper function that returns the current time using the
// given function or the stdlib if the given function is nil.
func (t *Transport) timeNow() time.Time {
	if t.TimeNow != nil {
		return t.TimeNow()
	}
	return time.Now()
}

// maybeLogQuery is a helper function that logs the query if the logger is set
// and returns the current time for subsequent logging.
func (t *Transport) maybeLogQuery(addr *ServerAddr, rawQuery []byte) time.Time {
	t0 := t.timeNow()
	if t.Logger != nil {
		t.Logger.Info(
			"dnsQuery",
			slog.Any("query", rawQuery),
			slog.String("serverAddr", addr.Address),
			slog.String("serverProtocol", string(addr.Protocol)),
			slog.Time("t", t0),
		)
	}
	return t0
}

// maybeLogResponse is a helper function that logs the response if the logger is set.
func (t *Transport) maybeLogResponse(addr *ServerAddr, t0 time.Time, rawQuery, rawResp []byte) {
	if t.Logger != nil {
		t.Logger.Info(
			"dnsResponse",
			slog.Any("rawQuery", rawQuery),
			slog.Any("rawResponse", rawResp),
			slog.String("serverAddr", addr.Address),
			slog.String("serverProtocol", string(addr.Protocol)),
			slog.Time("t0", t0),
			slog.Time("t", t.timeNow()),
		)
	}
}

// sendQueryUDP dials a connection, sends and logs the query and
// returns the following values:
//
// - conn: the connection to the server.
//
// - t0: the time when the query was sent.
//
// - rawQuery: the raw query bytes sent to the server.
//
// - err: any error that occurred during the process.
//
// On success, the caller TAKES OWNERSHIP of the returned connection
// and is responsible for closing it when done.
func (t *Transport) sendQueryUDP(ctx context.Context, addr *ServerAddr,
	query *dns.Msg) (conn net.Conn, t0 time.Time, rawQuery []byte, err error) {
	// 1. Dial the connection and handle failure. We do not handle retries at this
	// level and instead rely on the caller to retry the query if needed. This allows
	// the [*Resolver] to cycle through multiple servers in case of failure.
	conn, err = t.dialContext(ctx, "udp", addr.Address)
	if err != nil {
		return
	}

	// 2. Use the context deadline to limit the query lifetime
	// as documented in the [*Transport.Query] function.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	// 3. Serialize the query and possibly log that we're sending it.
	rawQuery, err = query.Pack()
	if err != nil {
		return
	}
	t0 = t.maybeLogQuery(addr, rawQuery)

	// 4. Send the query. Do not bother with logging the write call
	// since that should be done by a custom dialer that wraps the
	// returned connection and implements the desired logging.
	_, err = conn.Write(rawQuery)
	return
}

// edns0MaxResponseSize returns the maximum response size that the client
// did configure using EDNS(0) or the default size of 512 bytes.
func edns0MaxResponseSize(query *dns.Msg) (maxSize uint16) {
	for _, rr := range query.Extra {
		if opt, ok := rr.(*dns.OPT); ok {
			maxSize = opt.UDPSize()
			break
		}
	}
	if maxSize <= 0 {
		maxSize = 512
	}
	return
}

// recvResponseUDP reads and parses the response from the server and
// possibly logs the response. It returns the parsed response or an error.
func (t *Transport) recvResponseUDP(addr *ServerAddr, conn net.Conn,
	t0 time.Time, query *dns.Msg, rawQuery []byte) (*dns.Msg, error) {
	// 1. Read the corresponding raw response
	buffer := make([]byte, edns0MaxResponseSize(query))
	count, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}
	rawResp := buffer[:count]

	// 2. Parse the raw response and possibly log that we received it.
	resp := &dns.Msg{}
	if err := resp.Unpack(rawResp); err != nil {
		return nil, err
	}
	t.maybeLogResponse(addr, t0, rawQuery, rawResp)
	return resp, nil
}

// queryUDP implements [*Transport.Query] for DNS over UDP.
func (t *Transport) queryUDP(ctx context.Context,
	addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
	// Send the query and log the query if needed.
	conn, t0, rawQuery, err := t.sendQueryUDP(ctx, addr, query)
	if err != nil {
		return nil, err
	}

	// Use a single connection for request, which is what the standard library
	// does as well and is more robust in terms of residual censorship.
	//
	// Make sure we react to context being canceled early.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		defer conn.Close()
		<-ctx.Done()
	}()

	// Read and parse the response and log it if needed.
	return t.recvResponseUDP(addr, conn, t0, query, rawQuery)
}

// emitMessageOrError sends a message or error to the output channel
// or drops the message if the context is done.
func (t *Transport) emitMessageOrError(ctx context.Context,
	msg *dns.Msg, err error, out chan *MessageOrError) {
	var messageOrError *MessageOrError
	if err != nil {
		messageOrError = &MessageOrError{Err: err}
	} else {
		messageOrError = &MessageOrError{Msg: msg}
	}

	select {
	case out <- messageOrError:
	case <-ctx.Done():
	}
}

// queryUDPWithDuplicates implements [*Transport.Query] for DNS over UDP with
func (t *Transport) queryUDPWithDuplicates(ctx context.Context,
	addr *ServerAddr, query *dns.Msg) <-chan *MessageOrError {
	out := make(chan *MessageOrError, 4)
	go func() {
		// Ensure the channel is closed when we're done
		defer close(out)

		// Send the query and log the query if needed.
		conn, t0, rawQuery, err := t.sendQueryUDP(ctx, addr, query)
		if err != nil {
			t.emitMessageOrError(ctx, nil, err, out)
			return
		}

		// Use a single connection for request, which is what the standard library
		// does as well and is more robust in terms of residual censorship.
		//
		// Make sure we react to context being canceled early.
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		go func() {
			defer conn.Close()
			<-ctx.Done()
		}()

		// Loop collecting responses and emitting them until the context is done.
		for {
			resp, err := t.recvResponseUDP(addr, conn, t0, query, rawQuery)
			if err != nil {
				t.emitMessageOrError(ctx, nil, err, out)
				return
			}

			t.emitMessageOrError(ctx, resp, nil, out)
		}
	}()
	return out
}
