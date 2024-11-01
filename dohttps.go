//
// SPDX-License-Identifier: BSD-3-Clause
//
// Adapted from: https://github.com/ooni/probe-engine/blob/v0.23.0/netx/resolver/dnsoverhttps.go
//
// DNS-over-HTTPS implementation
//

package dnscore

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"github.com/miekg/dns"
)

// newHTTPRequestWithContext is a helper function that creates a new HTTP request
// using the namesake transport function or the stdlib if the such a function is nil.
func (t *Transport) newHTTPRequestWithContext(ctx context.Context, method, URL string, body io.Reader) (*http.Request, error) {
	if t.NewHTTPRequestWithContext != nil {
		return t.NewHTTPRequestWithContext(ctx, method, URL, body)
	}
	return http.NewRequestWithContext(ctx, method, URL, body)
}

// httpClient is a helper function that returns the HTTP client using the
// specific transport field or the stdlib if the given field is nil.
func (t *Transport) httpClient() *http.Client {
	if t.HTTPClient != nil {
		return t.HTTPClient
	}
	return http.DefaultClient
}

// readAllContext is a helper function that reads all from the reader using the
// namesake transport function or the stdlib if the given function is nil.
func (t *Transport) readAllContext(ctx context.Context, r io.Reader, c io.Closer) ([]byte, error) {
	if t.ReadAllContext != nil {
		return t.ReadAllContext(ctx, r, c)
	}
	return io.ReadAll(r)
}

// queryHTTPS implements [*Transport.Query] for DNS over HTTPS.
func (t *Transport) queryHTTPS(ctx context.Context,
	addr *ServerAddr, query *dns.Msg) (*dns.Msg, error) {
	// 0. immediately fail if the context is already done, which
	// is useful to write unit tests
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// 1. Serialize the query and possibly log that we're sending it.
	rawQuery, err := query.Pack()
	if err != nil {
		return nil, err
	}
	t0 := t.maybeLogQuery(addr, rawQuery)

	// 2. The query is sent as the body of a POST request. The content-type
	// header must be set. Otherwise servers may respond with 400.
	req, err := t.newHTTPRequestWithContext(ctx, "POST", addr.Address, bytes.NewReader(rawQuery))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/dns-message")

	// 3. Receive the response headers making sure we close
	// the body, the response code is 200, and the content type
	// is the expected one. Since servers always include the
	// content type, we don't need to be flexible here.
	httpResp, err := t.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != 200 {
		return nil, ErrServerMisbehaving
	}
	if httpResp.Header.Get("content-type") != "application/dns-message" {
		return nil, ErrServerMisbehaving
	}

	// 4. Now that headers are OK, we read the whole raw response
	// body, decode it, and possibly log it.
	reader := io.LimitReader(httpResp.Body, int64(edns0MaxResponseSize(query)))
	rawResp, err := t.readAllContext(ctx, reader, httpResp.Body)
	if err != nil {
		return nil, err
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(rawResp); err != nil {
		return nil, err
	}
	t.maybeLogResponse(addr, t0, rawQuery, rawResp)
	return resp, nil
}
