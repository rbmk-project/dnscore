// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/rbmk-project/common/netipx"
)

// addrToAddrPort is an alias for [common.AddrToAddrPort].
var addrToAddrPort = netipx.AddrToAddrPort

// protocolMap maps the DNS protocol to the corresponding network protocol.
var protocolMap = map[Protocol]string{
	ProtocolDoH: "tcp",
	ProtocolTCP: "tcp",
	ProtocolDoT: "tcp",
	ProtocolUDP: "udp",
	ProtocolDoQ: "udp",
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
			slog.String("protocol", protocolMap[addr.Protocol]),
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
			slog.String("protocol", protocolMap[addr.Protocol]),
		)
	}
}

// maybeLogResponseConn is a helper function that logs the response if the logger is set.
func (t *Transport) maybeLogResponseConn(ctx context.Context,
	addr *ServerAddr, t0 time.Time, rawQuery, rawResp []byte,
	conn dnsStream) {
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
