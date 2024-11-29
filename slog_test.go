// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/rbmk-project/common/mocks"
	"github.com/stretchr/testify/assert"
)

func Test_addrToAddrPort(t *testing.T) {
	tests := []struct {
		name string
		addr net.Addr
		want netip.AddrPort
	}{
		{
			name: "nil address",
			addr: nil,
			want: netip.AddrPortFrom(netip.IPv6Unspecified(), 0),
		},

		{
			name: "TCP address",
			addr: &net.TCPAddr{
				IP:   net.ParseIP("2001:db8::1"),
				Port: 1234,
			},
			want: netip.MustParseAddrPort("[2001:db8::1]:1234"),
		},

		{
			name: "UDP address",
			addr: &net.UDPAddr{
				IP:   net.ParseIP("2001:db8::2"),
				Port: 5678,
			},
			want: netip.MustParseAddrPort("[2001:db8::2]:5678"),
		},

		{
			name: "other address type",
			addr: &net.UnixAddr{},
			want: netip.AddrPortFrom(netip.IPv6Unspecified(), 0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := addrToAddrPort(tt.addr)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTransport_maybeLogQuery(t *testing.T) {
	tests := []struct {
		name       string
		newLogger  func(w io.Writer) *slog.Logger
		expectTime time.Time
		expectLog  string
	}{
		{
			name: "Logger set",
			newLogger: func(w io.Writer) *slog.Logger {
				return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
					Level: slog.LevelDebug,
					ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
						if attr.Key == slog.TimeKey {
							return slog.Attr{}
						}
						return attr
					},
				}))
			},
			expectTime: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			expectLog:  "{\"level\":\"INFO\",\"msg\":\"dnsQuery\",\"dnsRawQuery\":\"AAAAAA==\",\"serverAddr\":\"8.8.8.8:53\",\"serverProtocol\":\"udp\",\"t\":\"2020-01-01T00:00:00Z\"}\n",
		},

		{
			name:       "Logger not set",
			newLogger:  func(w io.Writer) *slog.Logger { return nil },
			expectTime: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			expectLog:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			transport := &Transport{
				Logger: tt.newLogger(&out),
				TimeNow: func() time.Time {
					return tt.expectTime
				},
			}

			addr := &ServerAddr{Address: "8.8.8.8:53", Protocol: ProtocolUDP}
			rawQuery := []byte{0, 0, 0, 0}

			ctx := context.Background()
			actualTime := transport.maybeLogQuery(ctx, addr, rawQuery)

			assert.Equal(t, tt.expectTime, actualTime)

			actualLog := out.String()
			assert.Equal(t, tt.expectLog, actualLog)
		})
	}
}

func TestTransport_maybeLogResponseAddrPort(t *testing.T) {
	tests := []struct {
		name      string
		newLogger func(w io.Writer) *slog.Logger
		laddr     netip.AddrPort
		raddr     netip.AddrPort
		expectLog string
	}{
		{
			name: "Logger set with valid addresses",
			newLogger: func(w io.Writer) *slog.Logger {
				return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
					Level: slog.LevelDebug,
					ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
						if attr.Key == slog.TimeKey {
							return slog.Attr{}
						}
						return attr
					},
				}))
			},
			laddr:     netip.MustParseAddrPort("[2001:db8::1]:1234"),
			raddr:     netip.MustParseAddrPort("[2001:db8::2]:443"),
			expectLog: "{\"level\":\"INFO\",\"msg\":\"dnsResponse\",\"localAddr\":\"[2001:db8::1]:1234\",\"dnsRawQuery\":\"AAAAAA==\",\"dnsRawResponse\":\"AQEBAQ==\",\"remoteAddr\":\"[2001:db8::2]:443\",\"serverAddr\":\"8.8.8.8:53\",\"serverProtocol\":\"udp\",\"t0\":\"2020-01-01T00:00:00Z\",\"t\":\"2020-01-01T00:00:11Z\"}\n",
		},

		{
			name: "Logger set with invalid addresses",
			newLogger: func(w io.Writer) *slog.Logger {
				return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
					Level: slog.LevelDebug,
					ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
						if attr.Key == slog.TimeKey {
							return slog.Attr{}
						}
						return attr
					},
				}))
			},
			laddr:     netip.AddrPort{}, // invalid
			raddr:     netip.AddrPort{}, // invalid
			expectLog: "{\"level\":\"INFO\",\"msg\":\"dnsResponse\",\"localAddr\":\"[::]:0\",\"dnsRawQuery\":\"AAAAAA==\",\"dnsRawResponse\":\"AQEBAQ==\",\"remoteAddr\":\"[::]:0\",\"serverAddr\":\"8.8.8.8:53\",\"serverProtocol\":\"udp\",\"t0\":\"2020-01-01T00:00:00Z\",\"t\":\"2020-01-01T00:00:11Z\"}\n",
		},

		{
			name:      "Logger not set",
			newLogger: func(w io.Writer) *slog.Logger { return nil },
			expectLog: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			transport := &Transport{
				Logger: tt.newLogger(&out),
				TimeNow: func() time.Time {
					return time.Date(2020, 1, 1, 0, 0, 11, 0, time.UTC)
				},
			}

			addr := &ServerAddr{Address: "8.8.8.8:53", Protocol: ProtocolUDP}
			rawQuery := []byte{0, 0, 0, 0}
			rawResponse := []byte{1, 1, 1, 1}

			ctx := context.Background()
			transport.maybeLogResponseAddrPort(
				ctx,
				addr,
				time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
				rawQuery,
				rawResponse,
				tt.laddr,
				tt.raddr,
			)

			actualLog := out.String()
			assert.Equal(t, tt.expectLog, actualLog)
		})
	}
}

func TestTransport_maybeLogResponseConn(t *testing.T) {
	tests := []struct {
		name      string
		newLogger func(w io.Writer) *slog.Logger
		conn      net.Conn
		expectLog string
	}{
		{
			name: "Logger set with TCP addresses",
			newLogger: func(w io.Writer) *slog.Logger {
				return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
					Level: slog.LevelDebug,
					ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
						if attr.Key == slog.TimeKey {
							return slog.Attr{}
						}
						return attr
					},
				}))
			},
			conn: &mocks.Conn{
				MockLocalAddr: func() net.Addr {
					return &net.TCPAddr{
						IP:   net.ParseIP("2001:db8::1"),
						Port: 1234,
					}
				},
				MockRemoteAddr: func() net.Addr {
					return &net.TCPAddr{
						IP:   net.ParseIP("2001:db8::2"),
						Port: 443,
					}
				},
			},
			expectLog: "{\"level\":\"INFO\",\"msg\":\"dnsResponse\",\"localAddr\":\"[2001:db8::1]:1234\",\"dnsRawQuery\":\"AAAAAA==\",\"dnsRawResponse\":\"AQEBAQ==\",\"remoteAddr\":\"[2001:db8::2]:443\",\"serverAddr\":\"8.8.8.8:53\",\"serverProtocol\":\"udp\",\"t0\":\"2020-01-01T00:00:00Z\",\"t\":\"2020-01-01T00:00:11Z\"}\n",
		},

		{
			name: "Logger set with non-TCP addresses",
			newLogger: func(w io.Writer) *slog.Logger {
				return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
					Level: slog.LevelDebug,
					ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
						if attr.Key == slog.TimeKey {
							return slog.Attr{}
						}
						return attr
					},
				}))
			},
			conn: &mocks.Conn{
				MockLocalAddr: func() net.Addr {
					return &net.UnixAddr{Name: "/tmp/local.sock", Net: "unix"}
				},
				MockRemoteAddr: func() net.Addr {
					return &net.UnixAddr{Name: "/tmp/remote.sock", Net: "unix"}
				},
			},
			expectLog: "{\"level\":\"INFO\",\"msg\":\"dnsResponse\",\"localAddr\":\"[::]:0\",\"dnsRawQuery\":\"AAAAAA==\",\"dnsRawResponse\":\"AQEBAQ==\",\"remoteAddr\":\"[::]:0\",\"serverAddr\":\"8.8.8.8:53\",\"serverProtocol\":\"udp\",\"t0\":\"2020-01-01T00:00:00Z\",\"t\":\"2020-01-01T00:00:11Z\"}\n",
		},

		{
			name:      "Logger not set",
			newLogger: func(w io.Writer) *slog.Logger { return nil },
			conn:      &mocks.Conn{},
			expectLog: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			transport := &Transport{
				Logger: tt.newLogger(&out),
				TimeNow: func() time.Time {
					return time.Date(2020, 1, 1, 0, 0, 11, 0, time.UTC)
				},
			}

			addr := &ServerAddr{Address: "8.8.8.8:53", Protocol: ProtocolUDP}
			rawQuery := []byte{0, 0, 0, 0}
			rawResponse := []byte{1, 1, 1, 1}

			ctx := context.Background()
			transport.maybeLogResponseConn(
				ctx,
				addr,
				time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
				rawQuery,
				rawResponse,
				tt.conn,
			)

			actualLog := out.String()
			assert.Equal(t, tt.expectLog, actualLog)
		})
	}
}
