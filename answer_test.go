// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestDecodeLookupA(t *testing.T) {
	tests := []struct {
		name     string
		rrs      []dns.RR
		expected []string
		cname    string
		err      error
	}{
		{
			name: "Single A record",
			rrs: []dns.RR{
				&dns.A{A: net.ParseIP("192.0.2.1")},
			},
			expected: []string{"192.0.2.1"},
			cname:    "",
			err:      nil,
		},
		{
			name: "Single CNAME record",
			rrs: []dns.RR{
				&dns.CNAME{Target: "example.com."},
			},
			expected: nil,
			cname:    "",
			err:      ErrNoData,
		},
		{
			name: "Multiple A records",
			rrs: []dns.RR{
				&dns.A{A: net.ParseIP("192.0.2.1")},
				&dns.A{A: net.ParseIP("192.0.2.2")},
			},
			expected: []string{"192.0.2.1", "192.0.2.2"},
			cname:    "",
			err:      nil,
		},
		{
			name:     "No A records",
			rrs:      []dns.RR{},
			expected: nil,
			cname:    "",
			err:      ErrNoData,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addrs, cname, err := DecodeLookupA(tt.rrs)
			assert.Equal(t, tt.expected, addrs)
			assert.Equal(t, tt.cname, cname)
			assert.Equal(t, tt.err, err)
		})
	}
}

func TestDecodeLookupAAAA(t *testing.T) {
	tests := []struct {
		name     string
		rrs      []dns.RR
		expected []string
		cname    string
		err      error
	}{
		{
			name: "Single AAAA record",
			rrs: []dns.RR{
				&dns.AAAA{AAAA: net.ParseIP("2001:db8::1")},
			},
			expected: []string{"2001:db8::1"},
			cname:    "",
			err:      nil,
		},
		{
			name: "Single CNAME record",
			rrs: []dns.RR{
				&dns.CNAME{Target: "example.com."},
			},
			expected: nil,
			cname:    "",
			err:      ErrNoData,
		},
		{
			name: "Multiple AAAA records",
			rrs: []dns.RR{
				&dns.AAAA{AAAA: net.ParseIP("2001:db8::1")},
				&dns.AAAA{AAAA: net.ParseIP("2001:db8::2")},
			},
			expected: []string{"2001:db8::1", "2001:db8::2"},
			cname:    "",
			err:      nil,
		},
		{
			name:     "No AAAA records",
			rrs:      []dns.RR{},
			expected: nil,
			cname:    "",
			err:      ErrNoData,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addrs, cname, err := DecodeLookupAAAA(tt.rrs)
			assert.Equal(t, tt.expected, addrs)
			assert.Equal(t, tt.cname, cname)
			assert.Equal(t, tt.err, err)
		})
	}
}
