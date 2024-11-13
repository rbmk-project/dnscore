// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rbmk-project/common/mocks"
	"github.com/stretchr/testify/assert"
)

// MockDNSMsg is a mock implementation of the dns.Msg interface.
type MockDNSMsg struct {
	MockPack func() ([]byte, error)
}

func (m *MockDNSMsg) Pack() ([]byte, error) {
	return m.MockPack()
}

func newValidRawRespFrame() []byte {
	resp := &dns.Msg{}
	rawResp, err := resp.Pack()
	if err != nil {
		panic(err)
	}
	rawRespFrame, err := newRawMsgFrame(&ServerAddr{}, rawResp)
	if err != nil {
		panic(err)
	}
	return rawRespFrame
}

func newGarbageRawRespFrame() []byte {
	rawRespFrame, err := newRawMsgFrame(&ServerAddr{}, []byte{0xFF})
	if err != nil {
		panic(err)
	}
	return rawRespFrame
}

func TestTransport_queryTCP(t *testing.T) {
	tests := []struct {
		name           string
		setupTransport func() *Transport
		expectedError  error
	}{
		{
			name: "Successful query",
			setupTransport: func() *Transport {
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return &mocks.Conn{
							MockWrite: func(b []byte) (int, error) {
								return len(b), nil
							},
							MockRead: (bytes.NewReader(newValidRawRespFrame())).Read,
							MockClose: func() error {
								return nil
							},
						}, nil
					},
				}
			},
			expectedError: nil,
		},

		{
			name: "Dial failure",
			setupTransport: func() *Transport {
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return nil, errors.New("dial failed")
					},
				}
			},
			expectedError: errors.New("dial failed"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := tt.setupTransport()
			addr := NewServerAddr(ProtocolTCP, "8.8.8.8:53")
			query := new(dns.Msg)
			query.SetQuestion("example.com.", dns.TypeA)

			_, err := transport.queryTCP(context.Background(), addr, query)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTransport_queryStream(t *testing.T) {
	tests := []struct {
		name           string
		query          queryMsg
		setupTransport func() *Transport
		setupConn      func(deadlineset *bool) net.Conn
		expectedError  error
		expectDeadline bool
	}{
		{
			name: "Successful query",
			query: &dns.Msg{
				Question: []dns.Question{
					{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				},
			},
			setupTransport: func() *Transport {
				return &Transport{}
			},
			setupConn: func(_ *bool) net.Conn {
				return &mocks.Conn{
					MockWrite: func(b []byte) (int, error) {
						return len(b), nil
					},
					MockRead: bytes.NewReader(newValidRawRespFrame()).Read,
					MockClose: func() error {
						return nil
					},
				}
			},
			expectedError: nil,
		},

		{
			name: "Write failure",
			query: &dns.Msg{
				Question: []dns.Question{
					{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				},
			},
			setupTransport: func() *Transport {
				return &Transport{}
			},
			setupConn: func(_ *bool) net.Conn {
				return &mocks.Conn{
					MockWrite: func(b []byte) (int, error) {
						return 0, errors.New("write failed")
					},
					MockClose: func() error {
						return nil
					},
				}
			},
			expectedError: errors.New("write failed"),
		},

		{
			name: "Read header failure",
			query: &dns.Msg{
				Question: []dns.Question{
					{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				},
			},
			setupTransport: func() *Transport {
				return &Transport{}
			},
			setupConn: func(_ *bool) net.Conn {
				return &mocks.Conn{
					MockWrite: func(b []byte) (int, error) {
						return len(b), nil
					},
					MockRead: func(b []byte) (int, error) {
						return 0, errors.New("read header failed")
					},
					MockClose: func() error {
						return nil
					},
				}
			},
			expectedError: errors.New("read header failed"),
		},

		{
			name: "Read body failure",
			query: &dns.Msg{
				Question: []dns.Question{
					{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				},
			},
			setupTransport: func() *Transport {
				return &Transport{}
			},
			setupConn: func(_ *bool) net.Conn {
				return &mocks.Conn{
					MockWrite: func(b []byte) (int, error) {
						return len(b), nil
					},
					MockRead: bytes.NewReader([]byte{0, 4}).Read,
					MockClose: func() error {
						return nil
					},
				}
			},
			expectedError: io.EOF,
		},

		{
			name: "Unpack failure",
			query: &dns.Msg{
				Question: []dns.Question{
					{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				},
			},
			setupTransport: func() *Transport {
				return &Transport{}
			},
			setupConn: func(_ *bool) net.Conn {
				return &mocks.Conn{
					MockWrite: func(b []byte) (int, error) {
						return len(b), nil
					},
					MockRead: bytes.NewReader(newGarbageRawRespFrame()).Read,
					MockClose: func() error {
						return nil
					},
				}
			},
			expectedError: errors.New("dns: overflow unpacking uint16"),
		},

		{
			name: "Context deadline set",
			query: &dns.Msg{
				Question: []dns.Question{
					{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				},
			},
			setupTransport: func() *Transport {
				return &Transport{}
			},
			setupConn: func(deadlineset *bool) net.Conn {
				return &mocks.Conn{
					MockWrite: func(b []byte) (int, error) {
						return len(b), nil
					},
					MockRead: bytes.NewReader(newValidRawRespFrame()).Read,
					MockClose: func() error {
						return nil
					},
					MockSetDeadline: func(t time.Time) error {
						*deadlineset = true
						return nil
					},
				}
			},
			expectedError:  nil,
			expectDeadline: true,
		},

		{
			name: "Non-FQDN query",
			query: &dns.Msg{
				Question: []dns.Question{
					{Name: "invalid-domain", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				},
			},
			setupTransport: func() *Transport {
				return &Transport{}
			},
			setupConn: func(_ *bool) net.Conn {
				return &mocks.Conn{
					MockWrite: func(b []byte) (int, error) {
						return len(b), nil
					},
					MockClose: func() error {
						return nil
					},
				}
			},
			expectedError: errors.New("dns: domain must be fully qualified"),
		},

		{
			name: "Query too large for transport",
			query: &MockDNSMsg{
				MockPack: func() ([]byte, error) {
					return make([]byte, math.MaxUint16+1), nil
				},
			},
			setupTransport: func() *Transport {
				return &Transport{}
			},
			setupConn: func(_ *bool) net.Conn {
				return &mocks.Conn{
					MockWrite: func(b []byte) (int, error) {
						return len(b), nil
					},
					MockRead: bytes.NewReader(newValidRawRespFrame()).Read,
					MockClose: func() error {
						return nil
					},
				}
			},
			expectedError: fmt.Errorf("%w: %s", ErrQueryTooLargeForTransport, ProtocolTCP),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := tt.setupTransport()
			addr := NewServerAddr(ProtocolTCP, "8.8.8.8:53")

			var deadlineset bool
			conn := tt.setupConn(&deadlineset)

			ctx := context.Background()
			if tt.expectDeadline {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(1*time.Hour))
				defer cancel()
			}

			_, err := transport.queryStream(ctx, addr, tt.query, conn)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
			if tt.expectDeadline {
				assert.True(t, deadlineset)
			}
		})
	}
}

func Test_newRawMsgFrame(t *testing.T) {
	tests := []struct {
		name          string
		rawMsg        []byte
		expectedFrame []byte
		expectedError error
	}{
		{
			name:          "Valid message frame",
			rawMsg:        []byte{0, 1, 2, 3},
			expectedFrame: []byte{0, 4, 0, 1, 2, 3},
			expectedError: nil,
		},
		{
			name:          "Message too large",
			rawMsg:        make([]byte, math.MaxUint16+1),
			expectedFrame: nil,
			expectedError: ErrQueryTooLargeForTransport,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := &ServerAddr{Protocol: ProtocolTCP}
			frame, err := newRawMsgFrame(addr, tt.rawMsg)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, errors.Unwrap(err))
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedFrame, frame)
			}
		})
	}
}
