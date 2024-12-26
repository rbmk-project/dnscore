// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_main(t *testing.T) {
	t.Run("without changing options", func(t *testing.T) {
		main()
	})

	t.Run("DNS-over-UDP", func(t *testing.T) {
		*serverAddr = "8.8.8.8:53"
		*protocol = "udp"
		main()
	})

	t.Run("DNS-over-TCP", func(t *testing.T) {
		*serverAddr = "8.8.8.8:53"
		*protocol = "tcp"
		main()
	})

	t.Run("DNS-over-TLS", func(t *testing.T) {
		*serverAddr = "8.8.8.8:853"
		*protocol = "dot"
		main()
	})

	t.Run("DNS-over-HTTPS", func(t *testing.T) {
		*serverAddr = "https://8.8.8.8/dns-query"
		*protocol = "doh"
		main()
	})

	t.Run("DNS-over-QUIC", func(t *testing.T) {
		*serverAddr = "1.1.1.1:853"
		*protocol = "doq"
		main()
	})

	t.Run("AAAA query", func(t *testing.T) {
		*serverAddr = "8.8.8.8:53"
		*protocol = "udp"
		*qtype = "AAAA"
		main()
	})

	t.Run("CNAME query", func(t *testing.T) {
		*serverAddr = "8.8.8.8:53"
		*protocol = "udp"
		*qtype = "CNAME"
		main()
	})

	t.Run("HTTPS query", func(t *testing.T) {
		*serverAddr = "8.8.8.8:53"
		*protocol = "udp"
		*qtype = "HTTPS"
		main()
	})

	t.Run("unsupported query type", func(t *testing.T) {
		*serverAddr = "8.8.8.8:53"
		*protocol = "udp"
		*qtype = "Nothing"

		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					err = r.(error)
				}
			}()
			main()
		}()

		assert.Equal(t, err, errors.New("transport: unsupported query type: Nothing"))
	})
}
