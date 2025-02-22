// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import (
	"errors"
	"testing"

	"github.com/miekg/dns"
)

func TestNewQueryWithServerAddr(t *testing.T) {
	// Override the `dns.Id` factory for testing purposes
	const expectedNonZeroQueryID = 4
	savedId := dns.Id
	dns.Id = func() uint16 { return expectedNonZeroQueryID }
	defer func() { dns.Id = savedId }()

	// TODO(bassosimone,roopeshsn): ensure we also test for DoQ
	// once we merge the corresponding PR.

	tests := []struct {
		name       string
		serverAddr *ServerAddr
		qname      string
		qtype      uint16
		options    []QueryOption
		wantName   string
		wantId     uint16
		wantErr    bool
	}{
		{
			name:       "standard UDP query",
			serverAddr: NewServerAddr(ProtocolUDP, "8.8.8.8:53"),
			qname:      "www.example.com",
			qtype:      dns.TypeA,
			wantName:   "www.example.com.",
			wantId:     expectedNonZeroQueryID,
		},
		{
			name:       "standard TCP query",
			serverAddr: NewServerAddr(ProtocolTCP, "8.8.8.8:53"),
			qname:      "www.example.com",
			qtype:      dns.TypeA,
			wantName:   "www.example.com.",
			wantId:     expectedNonZeroQueryID,
		},
		{
			name:       "standard TLS query",
			serverAddr: NewServerAddr(ProtocolTLS, "8.8.8.8:53"),
			qname:      "www.example.com",
			qtype:      dns.TypeA,
			wantName:   "www.example.com.",
			wantId:     expectedNonZeroQueryID,
		},
		{
			name:       "DoH query should have zero ID",
			serverAddr: NewServerAddr(ProtocolHTTPS, "https://dns.google/dns-query"),
			qname:      "example.com",
			qtype:      dns.TypeAAAA,
			wantName:   "example.com.",
			wantId:     0,
		},
		{
			name:       "invalid domain",
			serverAddr: NewServerAddr(ProtocolUDP, "8.8.8.8:53"),
			qname:      "invalid domain",
			qtype:      dns.TypeA,
			wantErr:    true,
		},
		{
			name:       "with failing option",
			serverAddr: NewServerAddr(ProtocolUDP, "8.8.8.8:53"),
			qname:      "www.example.com",
			qtype:      dns.TypeA,
			options:    []QueryOption{mockedFailingOption},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewQueryWithServerAddr(tt.serverAddr, tt.qname, tt.qtype, tt.options...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewQueryWithServerAddr() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if got.Question[0].Name != tt.wantName {
				t.Errorf("NewQueryWithServerAddr() name = %v, want %v", got.Question[0].Name, tt.wantName)
			}
			if tt.wantId == 0 && got.Id != 0 {
				t.Errorf("NewQueryWithServerAddr() id = %v, want 0", got.Id)
			}
			if tt.wantId != 0 && got.Id == 0 {
				t.Errorf("NewQueryWithServerAddr() id = 0, want non-zero")
			}
		})
	}
}

func TestNewQuery(t *testing.T) {
	// Note: NewQuery has been deprecated on 2025-02-20
	tests := []struct {
		name     string
		qtype    uint16
		options  []QueryOption
		wantName string
		wantErr  bool
	}{
		{"www.example.com", dns.TypeA, nil, "www.example.com.", false},
		{"example.com", dns.TypeAAAA, nil, "example.com.", false},
		{"invalid domain", dns.TypeA, nil, "", true},
		{"www.mocked-failure.com", dns.TypeA, []QueryOption{mockedFailingOption}, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewQuery(tt.name, tt.qtype, tt.options...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewQuery() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && got.Question[0].Name != tt.wantName {
				t.Errorf("NewQuery() = %v, want %v", got.Question[0].Name, tt.wantName)
			}
		})
	}
}

func mockedFailingOption(q *dns.Msg) error {
	return errors.New("mocked option failure")
}

func TestQueryOptionEDNS0(t *testing.T) {
	query := new(dns.Msg)
	option := QueryOptionEDNS0(4096, EDNS0FlagDO|EDNS0FlagBlockLengthPadding)
	if err := option(query); err != nil {
		t.Errorf("QueryOptionEDNS0() error = %v", err)
	}
	if query.IsEdns0() == nil {
		t.Errorf("QueryOptionEDNS0() did not set EDNS0 options")
	}
	if len(query.IsEdns0().Option) == 0 {
		t.Errorf("QueryOptionEDNS0() did not set padding option")
	}
}

func TestQueryOptionID(t *testing.T) {
	query := new(dns.Msg)
	option := QueryOptionID(42)
	if err := option(query); err != nil {
		t.Errorf("QueryOptionID() error = %v", err)
	}
	if query.Id != 42 {
		t.Errorf("QueryOptionID() did not set ID")
	}
}
