//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// DNS-over-QUIC implementation
//

// DNS over Dedicated QUIC Connections
// RFC 9250
// https://datatracker.ietf.org/doc/rfc9250/

package dnscore

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

func (t *Transport) createQUICStream(ctx context.Context, addr *ServerAddr,
	query *dns.Msg) (stream *quicStreamWrapper, err error) {

	udpAddr, err := net.ResolveUDPAddr("udp", addr.Address)
	if err != nil {
		return
	}

	// udpConn, err := net.ListenPacket("udp", addr.Address)

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return
	}

	tr := &quic.Transport{
		Conn: udpConn,
	}

	// 1. Fill in a default TLS config and QUIC config
	hostname, _, err := net.SplitHostPort(addr.Address)
	if err != nil {
		return
	}
	tlsConfig := &tls.Config{
		NextProtos: []string{"doq"},
		ServerName: hostname,
	}
	quicConfig := &quic.Config{}

	// 2. Use the context deadline to limit the query lifetime
	// as documented in the [*Transport.Query] function.
	if deadline, ok := ctx.Deadline(); ok {
		_ = udpConn.SetDeadline(deadline)
	}

	// RFC 9250
	// 4.2.1.  DNS Message IDs
	// When sending queries over a QUIC connection, the DNS Message ID MUST
	// be set to 0.
	query.Id = 0

	quicConn, err := tr.Dial(ctx, udpAddr, tlsConfig, quicConfig)
	if err != nil {
		return
	}

	quicStream, err := quicConn.OpenStream()
	if err != nil {
		return
	}

	stream = &quicStreamWrapper{
		Stream:     quicStream,
		localAddr:  quicConn.LocalAddr(),
		remoteAddr: quicConn.RemoteAddr(),
	}

	return
}

func (t *Transport) queryQUIC(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
	// 0. immediately fail if the context is already done, which
	// is useful to write unit tests
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Send the query and log the query if needed.
	stream, err := t.createQUICStream(ctx, addr, query)
	if err != nil {
		return nil, err
	}

	return t.queryStream(ctx, addr, query, stream)
}

type quicStreamWrapper struct {
	Stream     quic.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (qsw *quicStreamWrapper) Read(p []byte) (int, error)    { return qsw.Stream.Read(p) }
func (qsw *quicStreamWrapper) Write(p []byte) (int, error)   { return qsw.Stream.Write(p) }
func (qsw *quicStreamWrapper) Close() error                  { return qsw.Stream.Close() }
func (qsw *quicStreamWrapper) SetDeadline(t time.Time) error { return nil }
func (qsw *quicStreamWrapper) LocalAddr() net.Addr           { return qsw.localAddr }
func (qsw *quicStreamWrapper) RemoteAddr() net.Addr          { return qsw.remoteAddr }
