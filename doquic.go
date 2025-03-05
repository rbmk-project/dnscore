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
	"github.com/rbmk-project/common/closepool"
)

func (t *Transport) queryQUIC(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
	// 0. immediately fail if the context is already done, which
	// is useful to write unit tests
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	connPool := &closepool.Pool{}

	// Send the query and log the query if needed.
	// 1. Fill in a default TLS config and QUIC config
	hostname, _, err := net.SplitHostPort(addr.Address)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		NextProtos: []string{"doq"},
		ServerName: hostname,
		RootCAs:    t.RootCAs,
	}

	listenConfig := &net.ListenConfig{}
	udpConn, err := listenConfig.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		return nil, err
	}
	connPool.Add(udpConn)

	udpAddr, err := net.ResolveUDPAddr("udp", addr.Address)
	if err != nil {
		return nil, err
	}

	tr := &quic.Transport{
		Conn: udpConn,
	}
	quicConfig := &quic.Config{}
	quicConn, err := tr.Dial(ctx, udpAddr, tlsConfig, quicConfig)
	if err != nil {
		return nil, err
	}

	quicStream, err := quicConn.OpenStream()
	if err != nil {
		return nil, err
	}

	stream := &quicStreamWrapper{
		Stream:     quicStream,
		localAddr:  quicConn.LocalAddr(),
		remoteAddr: quicConn.RemoteAddr(),
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		defer connPool.Close()
		<-ctx.Done()
	}()

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
func (qsw *quicStreamWrapper) SetDeadline(t time.Time) error { return qsw.Stream.SetDeadline(t) }
func (qsw *quicStreamWrapper) LocalAddr() net.Addr           { return qsw.localAddr }
func (qsw *quicStreamWrapper) RemoteAddr() net.Addr          { return qsw.remoteAddr }
