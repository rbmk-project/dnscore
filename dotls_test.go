// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/rbmk-project/dnscore/internal/mocks"
	"github.com/stretchr/testify/assert"
)

func TestTransport_dialTLSContext(t *testing.T) {
	tests := []struct {
		name           string
		setupTransport func() *Transport
		address        string
		expectedError  error
	}{
		{
			name: "Invalid address",
			setupTransport: func() *Transport {
				return &Transport{}
			},
			address:       "invalid-address",
			expectedError: errors.New("address invalid-address: missing port in address"),
		},

		{
			name: "Override DialTLSContext",
			setupTransport: func() *Transport {
				return &Transport{
					DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return &mocks.Conn{}, nil
					},
				}
			},
			address:       "example.com:853",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := tt.setupTransport()
			ctx := context.Background()

			_, err := transport.dialTLSContext(ctx, "tcp", tt.address)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTransport_queryTLS(t *testing.T) {
	tests := []struct {
		name           string
		setupTransport func() *Transport
		expectedError  error
	}{
		{
			name: "Successful query",
			setupTransport: func() *Transport {
				return &Transport{
					DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
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
					DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
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
			addr := NewServerAddr(ProtocolDoT, "8.8.8.8:853")
			query := new(dns.Msg)
			query.SetQuestion("example.com.", dns.TypeA)

			_, err := transport.queryTLS(context.Background(), addr, query)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
