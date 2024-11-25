// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import (
	"context"
	"errors"
	"testing"

	"github.com/miekg/dns"
)

func TestTransportQuery(t *testing.T) {
	// create a canceled context so that we do not actually perform the query
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		protocol  Protocol
		expectErr error
	}{
		{protocol: ProtocolUDP, expectErr: context.Canceled},
		{protocol: ProtocolTCP, expectErr: context.Canceled},
		{protocol: ProtocolDoT, expectErr: context.Canceled},
		{protocol: ProtocolDoH, expectErr: context.Canceled},
		{protocol: "", expectErr: ErrNoSuchTransportProtocol},
	}

	for _, tt := range tests {
		t.Run(string(tt.protocol), func(t *testing.T) {
			txp := &Transport{}
			query := &dns.Msg{}
			addr := NewServerAddr(tt.protocol, "")

			resp, err := txp.Query(ctx, addr, query)

			if !errors.Is(err, tt.expectErr) {
				t.Errorf("expected %v error, got %v", tt.expectErr, err)
			}
			if resp != nil {
				t.Errorf("expected nil response, got %v", resp)
			}
		})
	}
}

func TestTransportQueryWithDuplicates(t *testing.T) {
	// create a canceled context so that we do not actually perform the query
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		protocol  Protocol
		expectErr error
	}{
		{protocol: ProtocolUDP, expectErr: context.Canceled},
		{protocol: ProtocolTCP, expectErr: ErrTransportCannotReceiveDuplicates},
		{protocol: ProtocolDoT, expectErr: ErrTransportCannotReceiveDuplicates},
		{protocol: ProtocolDoH, expectErr: ErrTransportCannotReceiveDuplicates},
	}

	for _, tt := range tests {
		t.Run(string(tt.protocol), func(t *testing.T) {
			txp := &Transport{}
			query := &dns.Msg{}
			addr := NewServerAddr(tt.protocol, "")

			out := txp.QueryWithDuplicates(ctx, addr, query)

			var results []*MessageOrError
			for result := range out {
				results = append(results, result)
			}

			if len(results) != 1 {
				t.Errorf("expected 1 result, got %d", len(results))
			}

			r0 := results[0]
			if !errors.Is(r0.Err, tt.expectErr) {
				t.Errorf("expected %v error, got %v", tt.expectErr, r0.Err)
			}
			if r0.Msg != nil {
				t.Errorf("expected nil response, got %v", r0.Msg)
			}
		})
	}
}
