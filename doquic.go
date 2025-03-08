//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// DNS-over-QUIC implementation
//
// See // https://datatracker.ietf.org/doc/rfc9250/
//

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

	// 1. Fill the TLS configuration
	hostname, _, err := net.SplitHostPort(addr.Address)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		NextProtos: []string{"doq"},
		ServerName: hostname,
		RootCAs:    t.RootCAs,
	}

	// 2. Create a connection pool to close all opened connections
	// and ensure we don't leak resources by using defer.
	connPool := &closepool.Pool{}
	defer connPool.Close()

	// TODO(bassosimone,roopeshsn): for TCP connections, we abstract
	// this process of combining the DNS lookup and dialing a connection,
	// which, in turn, allows for better unit testing and also allows
	// rbmk-project/rbmk to use rbmk-project/x/netcore for dialing.
	//
	// We should probably see to create a similar dialing interface in
	// rbmk-project/x/netcore for QUIC connections. We started discussing
	// this in https://github.com/rbmk-project/dnscore/pull/18.

	// 3. Open the UDP connection for supporting QUIC
	listenConfig := &net.ListenConfig{}
	udpConn, err := listenConfig.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		return nil, err
	}
	connPool.Add(udpConn)

	// 4. Map the UDP address, which may possibly contain a domain
	// name, to an actual UDP address structure to dial with
	udpAddr, err := net.ResolveUDPAddr("udp", addr.Address)
	if err != nil {
		return nil, err
	}

	// 5. Establish a QUIC connection. Note that the default
	// configuration implies a 5s timeout for handshaking and
	// a 30s idle connection timeout.
	tr := &quic.Transport{
		Conn: udpConn,
	}
	connPool.Add(tr)
	quicConfig := &quic.Config{}
	quicConn, err := tr.Dial(ctx, udpAddr, tlsConfig, quicConfig)
	if err != nil {
		return nil, err
	}
	connPool.Add(closepool.CloserFunc(func() error {
		// Closing w/o specific error -- RFC 9250 Sect. 4.3
		const doq_no_error = 0x00
		return quicConn.CloseWithError(doq_no_error, "")
	}))

	// 6. Open a stream for sending the DoQ query and wrap it into
	// an adapter that makes it usable by DNS-over-stream code
	quicStream, err := quicConn.OpenStream()
	if err != nil {
		return nil, err
	}
	stream := &quicStreamAdapter{
		Stream:     quicStream,
		localAddr:  quicConn.LocalAddr(),
		remoteAddr: quicConn.RemoteAddr(),
	}
	connPool.Add(stream)

	// 7. Ensure that we tear down everything which we have set up
	// in the case in which the context is canceled
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		defer connPool.Close()
		<-ctx.Done()
	}()

	// 8. defer to queryStream. Note that this method TAKES OWNERSHIP of
	// the stream and closes it after we've sent the query, honouring the
	// expectations for DoQ queries -- see RFC 9250 Sect. 4.2.
	return t.queryStream(ctx, addr, query, stream)
}

// quicStreamAdapter ensures a QUIC stream implements [dnsStream].
type quicStreamAdapter struct {
	Stream     quic.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

// Make sure we actually implement [dnsStream].
var _ dnsStream = &quicStreamAdapter{}

func (qsw *quicStreamAdapter) Read(p []byte) (int, error) {
	return qsw.Stream.Read(p)
}

func (qsw *quicStreamAdapter) Write(p []byte) (int, error) {
	return qsw.Stream.Write(p)
}

func (qsw *quicStreamAdapter) Close() error {
	return qsw.Stream.Close()
}

func (qsw *quicStreamAdapter) SetDeadline(t time.Time) error {
	return qsw.Stream.SetDeadline(t)
}

func (qsw *quicStreamAdapter) LocalAddr() net.Addr {
	return qsw.localAddr
}

func (qsw *quicStreamAdapter) RemoteAddr() net.Addr {
	return qsw.remoteAddr
}
