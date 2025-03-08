package dnscore

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestTransport_queryQUIC(t *testing.T) {
	// TODO(bassosimone,roopeshsn): currently this is an integration test
	// using the network w/ real servers but we should instead have:
	//
	// 1. an integration test using the network but using a QUIC server running
	// locally (a test which should live inside integration_test.go)
	//
	// 2. unit tests using mocking like we do for, e.g.m dohttps_test.go

	tests := []struct {
		name           string
		setupTransport func() *Transport
		expectedError  error
	}{
		{
			name: "Successful query",
			setupTransport: func() *Transport {
				return &Transport{}
			},
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := tt.setupTransport()
			addr := NewServerAddr(ProtocolDoQ, "dns.adguard.com:853")
			query := new(dns.Msg)
			query.SetQuestion("example.com.", dns.TypeA)

			_, err := transport.queryQUIC(context.Background(), addr, query)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
