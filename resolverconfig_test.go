// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNewConfig(t *testing.T) {
	config := NewConfig()
	if config == nil {
		t.Fatal("Expected non-nil config")
	}
	if config.Attempts() != DefaultAttempts {
		t.Fatalf("Expected %d attempts, got %d", DefaultAttempts, config.Attempts())
	}
	if len(config.servers()) != 2 {
		t.Fatalf("Expected 2 default servers, got %d", len(config.servers()))
	}
}

func TestSetAttempts(t *testing.T) {
	config := NewConfig()
	config.SetAttempts(3)
	if config.Attempts() != 3 {
		t.Fatalf("Expected 3 attempts, got %d", config.Attempts())
	}
}

func TestAddServer(t *testing.T) {
	config := NewConfig()
	addr := NewServerAddr(ProtocolUDP, "1.1.1.1:53")
	config.AddServer(addr)
	servers := config.servers()
	if len(servers) != 1 {
		t.Fatalf("Expected 1 server, got %d", len(servers))
	}
	if servers[0].address.Address != "1.1.1.1:53" {
		t.Fatalf("Expected server address 1.1.1.1:53, got %s", servers[0].address.Address)
	}
}

func TestServerOptionQueryTimeout(t *testing.T) {
	addr := NewServerAddr(ProtocolUDP, "1.1.1.1:53")
	server := newResolverConfigServer(addr, ServerOptionQueryTimeout(5*time.Second))
	if server.timeout != 5*time.Second {
		t.Fatalf("Expected timeout 5s, got %s", server.timeout)
	}
}

func TestServerOptionQueryOptions(t *testing.T) {
	tests := []struct {
		protocol       Protocol
		expectedLength int
		expectedFlags  int
	}{
		{ProtocolUDP, 1, 0},
		{ProtocolTCP, 1, 0},
		{ProtocolDoT, 1, EDNS0FlagDO | EDNS0FlagBlockLengthPadding},
		{ProtocolDoH, 1, EDNS0FlagDO | EDNS0FlagBlockLengthPadding},
	}

	for _, test := range tests {
		addr := NewServerAddr(test.protocol, "1.1.1.1:53")
		server := newResolverConfigServer(addr)
		if len(server.queryOptions) != test.expectedLength {
			t.Fatalf("Expected %d query option(s) for protocol %s, got %d", test.expectedLength, test.protocol, len(server.queryOptions))
		}
		if test.expectedLength > 0 {
			option := server.queryOptions[0]
			msg := &dns.Msg{}
			if err := option(msg); err != nil {
				t.Fatalf("Failed to apply query option for protocol %s: %s", test.protocol, err)
			}
			if msg.IsEdns0() == nil {
				t.Fatalf("Expected EDNS0 option for protocol %s", test.protocol)
			}
			if msg.IsEdns0().Do() != (test.expectedFlags&EDNS0FlagDO != 0) {
				t.Fatalf("Expected DO flag %v for protocol %s, got %v", test.expectedFlags&EDNS0FlagDO != 0, test.protocol, msg.IsEdns0().Do())
			}
			if len(msg.IsEdns0().Option) > 0 {
				if _, ok := msg.IsEdns0().Option[0].(*dns.EDNS0_PADDING); !ok && (test.expectedFlags&EDNS0FlagBlockLengthPadding != 0) {
					t.Fatalf("Expected block length padding for protocol %s", test.protocol)
				}
			}
		}
	}
}
