// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import (
	"errors"
	"testing"

	"github.com/miekg/dns"
)

func TestNewQuery(t *testing.T) {
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
