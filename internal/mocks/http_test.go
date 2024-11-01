//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/ooni/probe-cli/blob/v3.20.1/internal/mocks/http_test.go
//

package mocks

import (
	"errors"
	"net/http"
	"testing"
)

func TestHTTPTransport(t *testing.T) {
	t.Run("RoundTrip", func(t *testing.T) {
		expected := errors.New("mocked error")
		txp := &HTTPTransport{
			MockRoundTrip: func(req *http.Request) (*http.Response, error) {
				return nil, expected
			},
		}
		resp, err := txp.RoundTrip(&http.Request{})
		if !errors.Is(err, expected) {
			t.Fatal("not the error we expected", err)
		}
		if resp != nil {
			t.Fatal("expected nil response here")
		}
	})
}
