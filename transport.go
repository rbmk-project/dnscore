// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/miekg/dns"
)

// Transport allows sending and receiving DNS messages.
//
// Construct using [NewTransport].
//
// A [*Transport] is safe for concurrent use by multiple goroutines
// as long as you don't modify its fields after construction and the
// underlying fields you may set (e.g., DialContext) are also safe.
type Transport struct {
	// DialContext is the optional dialer for creating new
	// TCP and UDP connections. If this field is nil, the default
	// dialer from the [net] package will be used.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)

	// Logger is the optional structured logger for emitting
	// structured diagnostic events. If this field is nil, we
	// will not be emitting structured logs.
	Logger *slog.Logger

	// TimeNow is an optional function that returns the current time.
	// If this field is nil, the [time.Now] function will be used.
	TimeNow func() time.Time
}

// DefaultTransport is the default transport used by the package.
var DefaultTransport = NewTransport()

// NewTransport constructs a new [*Transport] with default settings.
func NewTransport() *Transport {
	return &Transport{}
}

// ErrNoSuchTransportProtocol is returned when the given protocol is not supported.
var ErrNoSuchTransportProtocol = errors.New("no such transport protocol")

// Query sends a DNS query to the given server address and returns the response.
//
// The context is used to control the query lifetime. If the context is
// cancelled or times out, the query will be aborted and an error will
// be immediately returned to the caller.
//
// The returned DNS message is the first message received from the server and
// it is not guaranteed to be valid for the query. You will still need to
// validate the response using the [ValidateResponse] function.
func (t *Transport) Query(ctx context.Context,
	addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
	switch addr.Protocol {
	case ProtocolUDP:
		return t.queryUDP(ctx, addr, query)
	case ProtocolTCP:
		return t.queryTCP(ctx, addr, query)
	default:
		return nil, fmt.Errorf("%w: %s", ErrNoSuchTransportProtocol, addr.Protocol)
	}
}

// MessageOrError contains either a DNS message or an error.
type MessageOrError struct {
	Err error
	Msg *dns.Msg
}

// ErrTransportCannotReceiveDuplicates is returned when the transport cannot receive duplicates.
var ErrTransportCannotReceiveDuplicates = errors.New("transport cannot receive duplicates")

// QueryWithDuplicates sends a DNS query to the given server address
// and returns the received responses. Use this method when you expect
// duplicate responses possibly caused by censorship. For example,
// the GFW (Great Firewall of China) typically causes duplicate responses
// with different addresses when a given domain is censored.
//
// This method only works with [ProtocolUDP].
//
// As for [*Transport.Query], the context is used to control the query
// lifetime. If the context is cancelled or times out, the query will be
// aborted and the returned channel will be then closed.
//
// The returned DNS messages are the responses received from the server and
// they are not guaranteed to be valid for the query. You will still need to
// validate the responses using the [ValidateResponse] function.
func (t *Transport) QueryWithDuplicates(ctx context.Context,
	addr *ServerAddr, query *dns.Msg) <-chan *MessageOrError {
	if addr.Protocol != ProtocolUDP {
		ch := make(chan *MessageOrError, 1)
		ch <- &MessageOrError{Err: fmt.Errorf("%w: %s", ErrTransportCannotReceiveDuplicates, addr.Protocol)}
		close(ch)
		return ch
	}
	return t.queryUDPWithDuplicates(ctx, addr, query)
}
