// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestResolver_transport(t *testing.T) {
	t.Run("default transport", func(t *testing.T) {
		resolver := &Resolver{}
		if resolver.transport() != DefaultTransport {
			t.Fatal("unexpected transport: got non-default transport, want DefaultTransport")
		}
	})

	t.Run("custom transport", func(t *testing.T) {
		expectedTransport := &MockResolverTransport{}
		resolver := &Resolver{Transport: expectedTransport}
		if resolver.transport() != expectedTransport {
			t.Fatal("unexpected transport: got different transport, want expectedTransport")
		}
	})
}

func TestResolver_exchange(t *testing.T) {
	t.Run("successful query", func(t *testing.T) {
		expectedRR := &dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("192.0.2.1"),
		}
		mockTransport := &MockResolverTransport{
			MockQuery: func(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
				resp := &dns.Msg{}
				resp.SetReply(query)
				resp.Answer = append(resp.Answer, expectedRR)
				return resp, nil
			},
		}
		resolver := &Resolver{Transport: mockTransport}
		server := resolverConfigServer{
			address: &ServerAddr{Address: "8.8.8.8:53"},
		}
		rrs, err := resolver.exchange(context.Background(), "example.com", dns.TypeA, server)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}
		if len(rrs) != 1 || rrs[0].String() != expectedRR.String() {
			t.Fatalf("unexpected result: got %v, want %v", rrs, expectedRR)
		}
	})

	t.Run("query timeout", func(t *testing.T) {
		mockTransport := &MockResolverTransport{
			MockQuery: func(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
				time.Sleep(100 * time.Millisecond)
				return nil, context.DeadlineExceeded
			},
		}
		resolver := &Resolver{Transport: mockTransport}
		server := resolverConfigServer{
			address: &ServerAddr{Address: "8.8.8.8:53"},
			timeout: 10 * time.Millisecond,
		}
		_, err := resolver.exchange(context.Background(), "example.com", dns.TypeA, server)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("unexpected error: got %v, want %v", err, context.DeadlineExceeded)
		}
	})

	t.Run("onion domain", func(t *testing.T) {
		resolver := &Resolver{}
		server := resolverConfigServer{
			address: &ServerAddr{Address: "8.8.8.8:53"},
		}
		_, err := resolver.exchange(context.Background(), "example.onion", dns.TypeA, server)
		if !errors.Is(err, ErrNoData) {
			t.Fatalf("unexpected error: got %v, want %v", err, ErrNoData)
		}
	})

	t.Run("cannot encode query", func(t *testing.T) {
		resolver := &Resolver{}
		server := resolverConfigServer{
			address: &ServerAddr{Address: "8.8.8.8:53"},
		}
		_, err := resolver.exchange(context.Background(), "\t\t\t", dns.TypeA, server)
		if err == nil || err.Error() != "idna: disallowed rune U+0009" {
			t.Fatalf("unexpected error: %s", err)
		}
	})

	t.Run("invalid response", func(t *testing.T) {
		mockTransport := &MockResolverTransport{
			MockQuery: func(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
				return &dns.Msg{}, nil
			},
		}
		resolver := &Resolver{Transport: mockTransport}
		server := resolverConfigServer{
			address: &ServerAddr{Address: "8.8.8.8:53"},
		}
		_, err := resolver.exchange(context.Background(), "example.com", dns.TypeA, server)
		if !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("unexpected error: got %v, want %v", err, ErrInvalidResponse)
		}
	})
}

func TestResolver_lookup(t *testing.T) {
	t.Run("successful lookup", func(t *testing.T) {
		expectedRR := &dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("192.0.2.1"),
		}
		mockTransport := &MockResolverTransport{
			MockQuery: func(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
				resp := &dns.Msg{}
				resp.SetReply(query)
				resp.Answer = append(resp.Answer, expectedRR)
				return resp, nil
			},
		}
		resolver := &Resolver{Transport: mockTransport}
		config := &ResolverConfig{
			attempts: DefaultAttempts,
			list: []resolverConfigServer{
				{address: &ServerAddr{Address: "8.8.8.8:53"}},
			},
		}
		resolver.Config = config
		rrs, err := resolver.lookup(context.Background(), "example.com", dns.TypeA)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}
		if len(rrs) != 1 || rrs[0].String() != expectedRR.String() {
			t.Fatalf("unexpected result: got %v, want %v", rrs, expectedRR)
		}
	})

	t.Run("lookup with no data", func(t *testing.T) {
		mockTransport := &MockResolverTransport{
			MockQuery: func(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
				resp := &dns.Msg{}
				resp.SetReply(query)
				return resp, nil
			},
		}
		resolver := &Resolver{Transport: mockTransport}
		config := &ResolverConfig{
			attempts: DefaultAttempts,
			list: []resolverConfigServer{
				{address: &ServerAddr{Address: "8.8.8.8:53"}},
			},
		}
		resolver.Config = config
		_, err := resolver.lookup(context.Background(), "example.com", dns.TypeA)
		if !errors.Is(err, ErrNoData) {
			t.Fatalf("unexpected error: got %v, want %v", err, ErrNoData)
		}
	})

	t.Run("lookup with NXDOMAIN", func(t *testing.T) {
		mockTransport := &MockResolverTransport{
			MockQuery: func(ctx context.Context, addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
				resp := &dns.Msg{}
				resp.SetReply(query)
				resp.Rcode = dns.RcodeNameError
				return resp, nil
			},
		}
		resolver := &Resolver{Transport: mockTransport}
		config := &ResolverConfig{
			attempts: DefaultAttempts,
			list: []resolverConfigServer{
				{address: &ServerAddr{Address: "8.8.8.8:53"}},
			},
		}
		resolver.Config = config
		_, err := resolver.lookup(context.Background(), "example.com", dns.TypeA)
		if !errors.Is(err, ErrNoName) {
			t.Fatalf("unexpected error: got %v, want %v", err, ErrNoName)
		}
	})
}
