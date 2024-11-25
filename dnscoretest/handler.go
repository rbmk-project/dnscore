// SPDX-License-Identifier: GPL-3.0-or-later

package dnscoretest

import (
	"io"
	"net"

	"github.com/miekg/dns"
	"github.com/rbmk-project/common/runtimex"
)

// ResponseWriter allows writing raw DNS responses.
type ResponseWriter interface {
	io.Writer
}

// Handler is a function that handles a DNS query.
type Handler interface {
	Handle(rw ResponseWriter, rawQuery []byte)
}

// HandlerFunc is an adapter to allow the use of ordinary functions as DNS handlers.
type HandlerFunc func(rw ResponseWriter, rawQuery []byte)

// Ensure HandlerFunc implements Handler.
var _ Handler = HandlerFunc(nil)

// Handle implements Handler.
func (hf HandlerFunc) Handle(rw ResponseWriter, rawQuery []byte) {
	hf(rw, rawQuery)
}

// ExampleComAddrA is the A address of example.com.
var ExampleComAddrA = net.IPv4(93, 184, 215, 14)

// NewExampleComHandler returns a handler that responds with a valid DNS response for example.com.
func NewExampleComHandler() Handler {
	return HandlerFunc(func(rw ResponseWriter, rawQuery []byte) {
		query := &dns.Msg{}
		runtimex.Try0(query.Unpack(rawQuery))
		resp := &dns.Msg{}
		resp.SetReply(query)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:     "example.com.",
				Rrtype:   dns.TypeA,
				Class:    dns.ClassINET,
				Ttl:      3600,
				Rdlength: 0,
			},
			A: ExampleComAddrA,
		})
		rawResp := runtimex.Try1(resp.Pack())
		_ = runtimex.Try1(rw.Write(rawResp))
	})
}
