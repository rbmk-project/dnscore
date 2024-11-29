// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"time"
)

// addrToAddrPort converts a net.Addr to a netip.AddrPort.
func addrToAddrPort(addr net.Addr) netip.AddrPort {
	if addr == nil {
		return netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
	}
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.AddrPort()
	}
	if udp, ok := addr.(*net.UDPAddr); ok {
		return udp.AddrPort()
	}
	return netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
}

// maybeLogQuery is a helper function that logs the query if the logger is set
// and returns the current time for subsequent logging.
func (t *Transport) maybeLogQuery(
	ctx context.Context, addr *ServerAddr, rawQuery []byte) time.Time {
	t0 := t.timeNow()
	if t.Logger != nil {
		t.Logger.InfoContext(
			ctx,
			"dnsQuery",
			slog.Any("dnsRawQuery", rawQuery),
			slog.String("serverAddr", addr.Address),
			slog.String("serverProtocol", string(addr.Protocol)),
			slog.Time("t", t0),
		)
	}
	return t0
}

// maybeLogResponseAddrPort is a helper function that logs the response if the logger is set.
func (t *Transport) maybeLogResponseAddrPort(ctx context.Context,
	addr *ServerAddr, t0 time.Time, rawQuery, rawResp []byte,
	laddr, raddr netip.AddrPort) {
	if t.Logger != nil {
		// Convert zero values to unspecified
		if !laddr.IsValid() {
			laddr = netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
		}
		if !raddr.IsValid() {
			raddr = netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
		}

		t.Logger.InfoContext(
			ctx,
			"dnsResponse",
			slog.String("localAddr", laddr.String()),
			slog.Any("dnsRawQuery", rawQuery),
			slog.Any("dnsRawResponse", rawResp),
			slog.String("remoteAddr", raddr.String()),
			slog.String("serverAddr", addr.Address),
			slog.String("serverProtocol", string(addr.Protocol)),
			slog.Time("t0", t0),
			slog.Time("t", t.timeNow()),
		)
	}
}

// maybeLogResponseConn is a helper function that logs the response if the logger is set.
func (t *Transport) maybeLogResponseConn(ctx context.Context,
	addr *ServerAddr, t0 time.Time, rawQuery, rawResp []byte,
	conn net.Conn) {
	if t.Logger != nil {
		t.maybeLogResponseAddrPort(
			ctx,
			addr,
			t0,
			rawQuery,
			rawResp,
			addrToAddrPort(conn.LocalAddr()),
			addrToAddrPort(conn.RemoteAddr()),
		)
	}
}
