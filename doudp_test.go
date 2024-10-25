// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import (
	"context"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/rbmk-project/dnscore/internal/mocks"
	"github.com/stretchr/testify/assert"
)

func TestQueryUDP(t *testing.T) {
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
							MockRead: func(b []byte) (int, error) {
								copy(b, []byte{0, 0, 0, 0})
								return len(b), nil
							},
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

		{
			name: "Write failure",
			setupTransport: func() *Transport {
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return &mocks.Conn{
							MockWrite: func(b []byte) (int, error) {
								return 0, errors.New("write failed")
							},
							MockClose: func() error {
								return nil
							},
						}, nil
					},
				}
			},
			expectedError: errors.New("write failed"),
		},

		{
			name: "Read failure",
			setupTransport: func() *Transport {
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return &mocks.Conn{
							MockWrite: func(b []byte) (int, error) {
								return len(b), nil
							},
							MockRead: func(b []byte) (int, error) {
								return 0, errors.New("read failed")
							},
							MockClose: func() error {
								return nil
							},
						}, nil
					},
				}
			},
			expectedError: errors.New("read failed"),
		},

		{
			name: "Send query failure",
			setupTransport: func() *Transport {
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return &mocks.Conn{
							MockWrite: func(b []byte) (int, error) {
								return 0, errors.New("send query failed")
							},
							MockClose: func() error {
								return nil
							},
						}, nil
					},
				}
			},
			expectedError: errors.New("send query failed"),
		},

		{
			name: "Garbage response",
			setupTransport: func() *Transport {
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return &mocks.Conn{
							MockWrite: func(b []byte) (int, error) {
								return len(b), nil
							},
							MockRead: func(b []byte) (int, error) {
								copy(b, []byte{0xFF})
								return 1, nil
							},
							MockClose: func() error {
								return nil
							},
						}, nil
					},
				}
			},
			expectedError: errors.New("dns: overflow unpacking uint16"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := tt.setupTransport()
			addr := NewServerAddr(ProtocolUDP, "8.8.8.8:53")
			query := new(dns.Msg)
			query.SetQuestion("example.com.", dns.TypeA)

			_, err := transport.queryUDP(context.Background(), addr, query)
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestQueryUDPWithDuplicates(t *testing.T) {
	tests := []struct {
		name           string
		setupTransport func() *Transport
		expectedError  error
	}{
		{
			name: "Successful query with duplicates",
			setupTransport: func() *Transport {
				count := &atomic.Int64{}
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return &mocks.Conn{
							MockWrite: func(b []byte) (int, error) {
								return len(b), nil
							},
							MockRead: func(b []byte) (int, error) {
								if count.Add(1) > 3 {
									return 0, os.ErrDeadlineExceeded
								}
								copy(b, []byte{0, 0, 0, 0})
								return len(b), nil
							},
							MockClose: func() error {
								return nil
							},
						}, nil
					},
				}
			},
			expectedError: os.ErrDeadlineExceeded,
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

		{
			name: "Write failure",
			setupTransport: func() *Transport {
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return &mocks.Conn{
							MockWrite: func(b []byte) (int, error) {
								return 0, errors.New("write failed")
							},
							MockClose: func() error {
								return nil
							},
						}, nil
					},
				}
			},
			expectedError: errors.New("write failed"),
		},

		{
			name: "Read failure",
			setupTransport: func() *Transport {
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return &mocks.Conn{
							MockWrite: func(b []byte) (int, error) {
								return len(b), nil
							},
							MockRead: func(b []byte) (int, error) {
								return 0, errors.New("read failed")
							},
							MockClose: func() error {
								return nil
							},
						}, nil
					},
				}
			},
			expectedError: errors.New("read failed"),
		},

		{
			name: "Garbage response",
			setupTransport: func() *Transport {
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return &mocks.Conn{
							MockWrite: func(b []byte) (int, error) {
								return len(b), nil
							},
							MockRead: func(b []byte) (int, error) {
								copy(b, []byte{0xFF})
								return 1, nil
							},
							MockClose: func() error {
								return nil
							},
						}, nil
					},
				}
			},
			expectedError: errors.New("dns: overflow unpacking uint16"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := tt.setupTransport()
			addr := NewServerAddr(ProtocolUDP, "8.8.8.8:53")
			query := new(dns.Msg)
			query.SetQuestion("example.com.", dns.TypeA)

			ch := transport.queryUDPWithDuplicates(context.Background(), addr, query)
			messages := []*MessageOrError{}
			for msgOrErr := range ch {
				messages = append(messages, msgOrErr)
			}
			if len(messages) <= 0 {
				t.Fatal("No messages received")
			}
			last := messages[len(messages)-1]
			if tt.expectedError != nil {
				assert.Error(t, last.Err)
				assert.Equal(t, tt.expectedError.Error(), last.Err.Error())
			} else {
				assert.NoError(t, last.Err)
			}
		})
	}
}
