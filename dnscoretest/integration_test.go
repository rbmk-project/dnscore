// SPDX-License-Identifier: GPL-3.0-or-later

package dnscoretest_test

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"testing"

	"github.com/miekg/dns"
	"github.com/rbmk-project/common/runtimex"
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

func TestFakeDNSServer_UDP(t *testing.T) {
	// Create a fake UDP server using the example.com handler
	server := &dnscoretest.Server{}
	handler := dnscoretest.NewExampleComHandler()
	<-server.StartUDP(handler)
	defer server.Close()

	// Create a DNS client
	client := &dns.Client{Net: "udp"}
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	// Send the query to the fake server
	resp, _, err := client.Exchange(query, server.Addr)

	// Validate the results
	checkResult(t, resp, err)
}

func TestFakeDNSServer_TCP(t *testing.T) {
	// Create a fake TCP server using the example.com handler
	server := &dnscoretest.Server{}
	handler := dnscoretest.NewExampleComHandler()
	<-server.StartTCP(handler)
	defer server.Close()

	// Create a DNS client
	client := &dns.Client{Net: "tcp"}
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	// Send the query to the fake server
	resp, _, err := client.Exchange(query, server.Addr)

	// Validate the results
	checkResult(t, resp, err)
}

func TestFakeDNSServer_TLS(t *testing.T) {
	// Create a fake TLS server using the example.com handler
	server := &dnscoretest.Server{}
	handler := dnscoretest.NewExampleComHandler()
	<-server.StartTLS(handler)
	defer server.Close()

	// Create a DNS client with TLS configuration
	tlsConfig := &tls.Config{
		RootCAs: server.RootCAs,
	}
	client := &dns.Client{
		Net:       "tcp-tls",
		TLSConfig: tlsConfig,
	}
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	// Send the query to the fake server
	resp, _, err := client.Exchange(query, server.Addr)

	// Validate the results
	checkResult(t, resp, err)
}

func TestFakeDNSServer_HTTPS(t *testing.T) {
	// Create a fake HTTPS server using the example.com handler
	server := &dnscoretest.Server{}
	handler := dnscoretest.NewExampleComHandler()
	<-server.StartHTTPS(handler)
	defer server.Close()

	// Create an HTTP client with TLS configuration
	tlsConfig := &tls.Config{
		RootCAs: server.RootCAs,
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	// Create the HTTP request
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	rawQuery := runtimex.Try1(query.Pack())
	httpReq := runtimex.Try1(http.NewRequest(
		"POST", server.URL, bytes.NewReader(rawQuery)))

	// Send the query to the fake server
	httpResp, err := client.Do(httpReq)

	// Validate the HTTPS response
	if err != nil {
		t.Fatal(err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		t.Fatal("expected 200, got", httpResp.StatusCode)
	}
	rawResp := runtimex.Try1(io.ReadAll(httpResp.Body))
	resp := &dns.Msg{}
	if err := resp.Unpack(rawResp); err != nil {
		t.Fatal(err)
	}

	// Validate the results
	checkResult(t, resp, err)
}
