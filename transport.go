// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

// Transport allows sending and receiving DNS messages.
//
// The zero value is ready to use.
//
// A [*Transport] is safe for concurrent use by multiple goroutines
// as long as you don't modify its fields after construction and the
// underlying fields you may set (e.g., DialContext) are also safe.
type Transport struct {
	// DialContext is the optional dialer for creating new
	// TCP and UDP connections. If this field is nil, the default
	// dialer from the [net] package will be used.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)

	// DialTLSContext is like DialContext but for creating new
	// TLS connections. If this field is nil, we will configure
	// a suitable [*tls.Config] and use [*tls.Dialer].
	DialTLSContext func(ctx context.Context, network, address string) (net.Conn, error)

	// HTTPClient is the optional HTTP client to use for DNS-over-HTTPS.
	// If this field is nil, we use the  default HTTP client from [net/http].
	//
	// When HTTPClientDo is nil and this field is not nil, we use this client to
	// perform queries and http/httptrace to obtain connection information.
	HTTPClient *http.Client

	// HTTPClientDo optionally allows full control over how HTTP requests
	// are performed and how to obtain connection information. When this
	// field is non-nil, it takes precedence over HTTPClient.
	//
	// This field is mainly useful for measurement scenarios where you need
	// precise control over connection handling and addressing information.
	HTTPClientDo func(req *http.Request) (*http.Response, netip.AddrPort, netip.AddrPort, error)

	// Logger is the optional structured logger for emitting
	// structured diagnostic events. If this field is nil, we
	// will not be emitting structured logs.
	Logger *slog.Logger

	// NewHTTPRequestWithContext is an optional function that creates a new
	// HTTP request with the given context. If this field is nil, the
	// [http.NewRequestWithContext] function will be used.
	NewHTTPRequestWithContext func(ctx context.Context, method, url string, body io.Reader) (*http.Request, error)

	// ReadAllContext is the optional function to read the whole HTTP response
	// body in DNS-over-HTTPS. If this field is nil, we use the [io.ReadAll] function
	// instead. Compared to [io.ReadAll], this function has a context argument
	// and an [io.Closer] argument, which SHOULD be used to close the connection
	// when the context is cancelled. In general, this is not useful, but in censored
	// places censorship may desync the TCP connection, making context-based
	// interruption useful to avoid being blocked ~forever.
	ReadAllContext func(ctx context.Context, r io.Reader, c io.Closer) ([]byte, error)

	// RootCAs contains the [*x509.CertPool] used by DNS-over-TLS
	// when the DialTLSContext function pointer is nil. Leaving this
	// field nil implies using the system's root CAs.
	RootCAs *x509.CertPool

	// TimeNow is an optional function that returns the current time.
	// If this field is nil, the [time.Now] function will be used.
	TimeNow func() time.Time
}

// DefaultTransport is the default transport used by the package.
var DefaultTransport = &Transport{}

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

	case ProtocolDoT:
		return t.queryTLS(ctx, addr, query)

	case ProtocolDoH:
		return t.queryHTTPS(ctx, addr, query)

	case ProtocolDoQ:
		return t.queryQUIC(ctx, addr, query)

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
		ch <- &MessageOrError{Err: fmt.Errorf(
			"%w: %s", ErrTransportCannotReceiveDuplicates, addr.Protocol)}
		close(ch)
		return ch
	}

	return t.queryUDPWithDuplicates(ctx, addr, query)
}

type dnsStream interface {
	io.Reader
	io.Writer
	io.Closer
	SetDeadline(t time.Time) error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}
