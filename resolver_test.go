// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// MockResolverTransport allows mocking a [ResolverTransport].
type MockResolverTransport struct {
	MockQuery func(ctx context.Context,
		addr *ServerAddr, query *dns.Msg) (*dns.Msg, error)
}

func (rtm *MockResolverTransport) Query(ctx context.Context,
	addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
	return rtm.MockQuery(ctx, addr, query)
}

func TestResolverTransportMock(t *testing.T) {
	t.Run("Query", func(t *testing.T) {
		expected := errors.New("mocked error")
		rtm := &MockResolverTransport{
			MockQuery: func(ctx context.Context,
				addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
				return nil, expected
			},
		}
		resp, err := rtm.Query(context.Background(), nil, nil)
		if !errors.Is(err, expected) {
			t.Fatal("unexpected error")
		}
		if resp != nil {
			t.Fatal("unexpected response")
		}
	})
}

func TestResolver_config(t *testing.T) {
	tests := []struct {
		name     string
		config   *ResolverConfig
		attempts int
	}{
		{
			name:     "Nil config returns default",
			config:   nil,
			attempts: DefaultAttempts,
		},
		{
			name:     "Non-nil config returns the same config",
			config:   &ResolverConfig{attempts: 128},
			attempts: 128,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &Resolver{Config: tt.config}
			result := resolver.config()
			if result.attempts != tt.attempts {
				t.Fatalf("expected attempts %d, got %d", tt.attempts, result.attempts)
			}
		})
	}
}

func TestResolverDedupAndSort(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "No duplicates, mixed IPv4 and IPv6",
			input:    []string{"192.0.2.1", "2001:db8::1"},
			expected: []string{"192.0.2.1", "2001:db8::1"},
		},

		{
			name:     "With duplicates, mixed IPv4 and IPv6",
			input:    []string{"192.0.2.1", "2001:db8::1", "192.0.2.1", "2001:db8::1"},
			expected: []string{"192.0.2.1", "2001:db8::1"},
		},

		{
			name:     "Only IPv4 addresses",
			input:    []string{"192.0.2.1", "192.0.2.2"},
			expected: []string{"192.0.2.1", "192.0.2.2"},
		},

		{
			name:     "Only IPv6 addresses",
			input:    []string{"2001:db8::1", "2001:db8::2"},
			expected: []string{"2001:db8::1", "2001:db8::2"},
		},

		{
			name:     "Mixed IPv4 and IPv6 with duplicates",
			input:    []string{"192.0.2.1", "2001:db8::1", "192.0.2.1", "2001:db8::1", "192.0.2.2"},
			expected: []string{"192.0.2.1", "192.0.2.2", "2001:db8::1"},
		},

		{
			name:     "Empty input",
			input:    []string{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolverDedupAndSort(tt.input)
			if len(result) != len(tt.expected) {
				t.Fatalf("expected %d addresses, got %d", len(tt.expected), len(result))
			}
			for i, addr := range result {
				if addr != tt.expected[i] {
					t.Fatalf("expected address %s, got %s", tt.expected[i], addr)
				}
			}
		})
	}
}

func TestResolver_LookupA(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		mockQuery   func(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error)
		expected    []string
		expectedErr error
	}{
		{
			name: "Valid IPv4 address",
			host: "192.0.2.1",
			mockQuery: func(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
				return nil, nil
			},
			expected:    []string{"192.0.2.1"},
			expectedErr: nil,
		},

		{
			name: "Valid A record",
			host: "example.com",
			mockQuery: func(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
				msg := &dns.Msg{}
				msg.SetReply(query)
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("192.0.2.1"),
				})
				return msg, nil
			},
			expected:    []string{"192.0.2.1"},
			expectedErr: nil,
		},

		{
			name: "No A record",
			host: "example.com",
			mockQuery: func(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
				msg := &dns.Msg{}
				msg.SetReply(query)
				return msg, nil
			},
			expected:    nil,
			expectedErr: ErrNoData,
		},

		{
			name: "DNS query error",
			host: "example.com",
			mockQuery: func(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
				return nil, io.EOF
			},
			expected:    nil,
			expectedErr: io.EOF,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rtm := &MockResolverTransport{
				MockQuery: tt.mockQuery,
			}
			resolver := NewResolver()
			resolver.Transport = rtm

			addrs, err := resolver.LookupA(context.Background(), tt.host)

			if !errors.Is(err, tt.expectedErr) {
				t.Fatalf("expected error %v, got %v", tt.expectedErr, err)
			}
			if len(addrs) != len(tt.expected) {
				t.Fatalf("expected %d addresses, got %d", len(tt.expected), len(addrs))
			}
			for i, addr := range addrs {
				if addr != tt.expected[i] {
					t.Fatalf("expected address %s, got %s", tt.expected[i], addr)
				}
			}
		})
	}
}

func TestResolver_LookupAAAA(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		mockQuery   func(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error)
		expected    []string
		expectedErr error
	}{
		{
			name: "Valid IPv6 address",
			host: "2001:db8::1",
			mockQuery: func(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
				return nil, nil
			},
			expected:    []string{"2001:db8::1"},
			expectedErr: nil,
		},

		{
			name: "Valid AAAA record",
			host: "example.com",
			mockQuery: func(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
				msg := &dns.Msg{}
				msg.SetReply(query)
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
					AAAA: net.ParseIP("2001:db8::1"),
				})
				return msg, nil
			},
			expected:    []string{"2001:db8::1"},
			expectedErr: nil,
		},

		{
			name: "No AAAA record",
			host: "example.com",
			mockQuery: func(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
				msg := &dns.Msg{}
				msg.SetReply(query)
				return msg, nil
			},
			expected:    nil,
			expectedErr: ErrNoData,
		},

		{
			name: "DNS query error",
			host: "example.com",
			mockQuery: func(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
				return nil, io.EOF
			},
			expected:    nil,
			expectedErr: io.EOF,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rtm := &MockResolverTransport{
				MockQuery: tt.mockQuery,
			}
			resolver := NewResolver()
			resolver.Transport = rtm

			addrs, err := resolver.LookupAAAA(context.Background(), tt.host)

			if !errors.Is(err, tt.expectedErr) {
				t.Fatalf("expected error %v, got %v", tt.expectedErr, err)
			}
			if len(addrs) != len(tt.expected) {
				t.Fatalf("expected %d addresses, got %d", len(tt.expected), len(addrs))
			}
			for i, addr := range addrs {
				if addr != tt.expected[i] {
					t.Fatalf("expected address %s, got %s", tt.expected[i], addr)
				}
			}
		})
	}
}

func TestResolver_LookupHost(t *testing.T) {
	skipAll := false // Set this to true to skip all tests except those with dontSkip set to true

	tests := []struct {
		name        string
		host        string
		mockQuery   func(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error)
		expected    []string
		expectedErr error
		dontSkip    bool
	}{
		{
			name: "Valid A and AAAA records",
			host: "example.com",
			mockQuery: func(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
				msg := &dns.Msg{}
				msg.SetReply(query)
				if query.Question[0].Qtype == dns.TypeA {
					msg.Answer = append(msg.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
						A:   net.ParseIP("192.0.2.1"),
					})
				} else if query.Question[0].Qtype == dns.TypeAAAA {
					msg.Answer = append(msg.Answer, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
						AAAA: net.ParseIP("2001:db8::1"),
					})
				}
				return msg, nil
			},
			expected:    []string{"192.0.2.1", "2001:db8::1"},
			expectedErr: nil,
			dontSkip:    false,
		},

		{
			name: "No A and AAAA records",
			host: "example.com",
			mockQuery: func(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
				msg := &dns.Msg{}
				msg.SetReply(query)
				return msg, nil
			},
			expected:    nil,
			expectedErr: ErrNoData,
			dontSkip:    false,
		},

		{
			name: "DNS query error for A record",
			host: "example.com",
			mockQuery: func(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
				if query.Question[0].Qtype == dns.TypeA {
					return nil, io.EOF
				}
				msg := &dns.Msg{}
				msg.SetReply(query)
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
					AAAA: net.ParseIP("2001:db8::1"),
				})
				return msg, nil
			},
			expected:    []string{"2001:db8::1"},
			expectedErr: nil,
			dontSkip:    false,
		},

		{
			name: "DNS query error for AAAA record",
			host: "example.com",
			mockQuery: func(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
				if query.Question[0].Qtype == dns.TypeAAAA {
					return nil, io.EOF
				}
				msg := &dns.Msg{}
				msg.SetReply(query)
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("192.0.2.1"),
				})
				return msg, nil
			},
			expected:    []string{"192.0.2.1"},
			expectedErr: nil,
			dontSkip:    false,
		},

		{
			name: "A returns error, AAAA returns no error and no addresses",
			host: "example.com",
			mockQuery: func(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
				msg := &dns.Msg{}
				if query.Question[0].Qtype == dns.TypeA {
					msg.SetRcode(query, dns.RcodeNameError)
				} else {
					msg.SetReply(query)
				}
				return msg, nil
			},
			expected:    nil,
			expectedErr: ErrNoName,
			dontSkip:    false,
		},

		{
			name: "A returns no error and no addresses, AAAA returns error",
			host: "example.com",
			mockQuery: func(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
				msg := &dns.Msg{}
				if query.Question[0].Qtype == dns.TypeAAAA {
					msg.SetRcode(query, dns.RcodeNameError)
				} else {
					msg.SetReply(query)
				}
				return msg, nil
			},
			expected:    nil,
			expectedErr: ErrNoName,
			dontSkip:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if skipAll && !tt.dontSkip {
				t.Skip("Skipping test as skipAll is true and dontSkip is false")
			}

			rtm := &MockResolverTransport{
				MockQuery: tt.mockQuery,
			}
			resolver := NewResolver()
			resolver.Transport = rtm

			addrs, err := resolver.LookupHost(context.Background(), tt.host)

			if !errors.Is(err, tt.expectedErr) {
				t.Fatalf("expected error %v, got %v", tt.expectedErr, err)
			}
			if len(addrs) != len(tt.expected) {
				t.Fatalf("expected %d addresses, got %d", len(tt.expected), len(addrs))
			}
			for i, addr := range addrs {
				if addr != tt.expected[i] {
					t.Fatalf("expected address %s, got %s", tt.expected[i], addr)
				}
			}
		})
	}
}
