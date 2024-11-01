//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/ooni/probe-cli/blob/v3.20.1/internal/mocks/http.go
//

package mocks

import "net/http"

// HTTPTransport mocks netxlite.HTTPTransport.
type HTTPTransport struct {
	// MockRoundTrip is the function to call when RoundTrip is called.
	MockRoundTrip func(req *http.Request) (*http.Response, error)
}

// RoundTrip calls MockRoundTrip.
func (txp *HTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return txp.MockRoundTrip(req)
}
