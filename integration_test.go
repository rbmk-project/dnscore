// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rbmk-project/dnscore"
	"github.com/rbmk-project/dnscore/dnscoretest"
	"github.com/stretchr/testify/assert"
)

func checkResult(t *testing.T, resp *dns.Msg, err error) {
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, 1, len(resp.Answer))
	assert.Equal(t, "example.com.", resp.Answer[0].Header().Name)
	assert.Equal(t, dns.TypeA, resp.Answer[0].Header().Rrtype)
	assert.Equal(
		t, dnscoretest.ExampleComAddrA.String(),
		resp.Answer[0].(*dns.A).A.String(),
	)
}

func TestTransport_RoundTrip_UDP(t *testing.T) {
	// create and start a testing server
	server := &dnscoretest.Server{}
	handler := dnscoretest.NewExampleComHandler()
	<-server.StartUDP(handler)
	defer server.Close()

	// create transport, server addr, and query
	txp := &dnscore.Transport{}
	serverAddr := &dnscore.ServerAddr{
		Protocol: dnscore.ProtocolUDP,
		Address:  server.Addr,
	}
	options := []dnscore.QueryOption{
		dnscore.QueryOptionEDNS0(
			dnscore.EDNS0SuggestedMaxResponseSizeUDP,
			0,
		),
	}
	query, err := dnscore.NewQuery("example.com", dns.TypeA, options...)
	if err != nil {
		t.Fatal(err)
	}

	// issue the query and get the response
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := txp.Query(ctx, serverAddr, query)

	// verify the results
	checkResult(t, resp, err)
}

func TestTransport_RoundTrip_TCP(t *testing.T) {
	// create and start a testing server
	server := &dnscoretest.Server{}
	handler := dnscoretest.NewExampleComHandler()
	<-server.StartTCP(handler)
	defer server.Close()

	// create transport, server addr, and query
	txp := &dnscore.Transport{}
	serverAddr := &dnscore.ServerAddr{
		Protocol: dnscore.ProtocolTCP,
		Address:  server.Addr,
	}
	options := []dnscore.QueryOption{
		dnscore.QueryOptionEDNS0(
			dnscore.EDNS0SuggestedMaxResponseSizeOtherwise,
			0,
		),
	}
	query, err := dnscore.NewQuery("example.com", dns.TypeA, options...)
	if err != nil {
		t.Fatal(err)
	}

	// issue the query and get the response
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := txp.Query(ctx, serverAddr, query)

	// verify the results
	checkResult(t, resp, err)
}

func TestTransport_RoundTrip_TLS(t *testing.T) {
	// create and start a testing server
	server := &dnscoretest.Server{}
	handler := dnscoretest.NewExampleComHandler()
	<-server.StartTLS(handler)
	defer server.Close()

	// create transport, server addr, and query
	txp := &dnscore.Transport{RootCAs: server.RootCAs}
	serverAddr := &dnscore.ServerAddr{
		Protocol: dnscore.ProtocolDoT,
		Address:  server.Addr,
	}
	options := []dnscore.QueryOption{
		dnscore.QueryOptionEDNS0(
			dnscore.EDNS0SuggestedMaxResponseSizeOtherwise,
			dnscore.EDNS0FlagDO|dnscore.EDNS0FlagBlockLengthPadding,
		),
	}
	query, err := dnscore.NewQuery("example.com", dns.TypeA, options...)
	if err != nil {
		t.Fatal(err)
	}

	// issue the query and get the response
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := txp.Query(ctx, serverAddr, query)

	// verify the results
	checkResult(t, resp, err)
}

func TestTransport_RoundTrip_HTTPS(t *testing.T) {
	// create and start a testing server
	server := &dnscoretest.Server{}
	handler := dnscoretest.NewExampleComHandler()
	<-server.StartHTTPS(handler)
	defer server.Close()

	// create transport, server addr, and query
	txp := &dnscore.Transport{
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: server.RootCAs,
				},
			},
		},
	}
	serverAddr := &dnscore.ServerAddr{
		Protocol: dnscore.ProtocolDoH,
		Address:  server.URL,
	}
	options := []dnscore.QueryOption{
		dnscore.QueryOptionEDNS0(
			dnscore.EDNS0SuggestedMaxResponseSizeOtherwise,
			dnscore.EDNS0FlagDO|dnscore.EDNS0FlagBlockLengthPadding,
		),
	}
	query, err := dnscore.NewQuery("example.com", dns.TypeA, options...)
	if err != nil {
		t.Fatal(err)
	}

	// issue the query and get the response
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := txp.Query(ctx, serverAddr, query)

	// verify the results
	checkResult(t, resp, err)
}
