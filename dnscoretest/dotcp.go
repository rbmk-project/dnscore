// SPDX-License-Identifier: GPL-3.0-or-later

package dnscoretest

import (
	"bufio"
	"io"
	"math"
	"net"

	"github.com/rbmk-project/common/runtimex"
)

// StartTCP starts a TCP listener and listens for incoming DNS queries.
//
// This method panics in case of failure.
func (s *Server) StartTCP(handler Handler) <-chan struct{} {
	runtimex.Assert(!s.started, "already started")
	ready := make(chan struct{})
	go func() {
		listener := runtimex.Try1(net.Listen("tcp", "127.0.0.1:0"))
		s.Addr = listener.Addr().String()
		s.ioclosers = append(s.ioclosers, listener)
		s.started = true
		close(ready)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			s.serveConn(handler, conn)
		}
	}()
	return ready
}

// serveConn serves a single DNS query over TCP or TLS.
func (s *Server) serveConn(handler Handler, conn net.Conn) {
	// Close the connection when done serving
	defer conn.Close()

	// Wrap the conn into a bufio.Reader and read the whole message
	br := bufio.NewReader(conn)
	header := make([]byte, 2)
	_ = runtimex.Try1(io.ReadFull(br, header))
	length := int(header[0])<<8 | int(header[1])
	rawQuery := make([]byte, length)
	_ = runtimex.Try1(io.ReadFull(br, rawQuery))

	// Wrap into a response writer and serve
	rw := &responseWriterStream{conn: conn}
	handler.Handle(rw, rawQuery)
}

// responseWriterStream is a response writer for TCP or TLS.
type responseWriterStream struct {
	conn net.Conn
}

// Ensure responseWriterStream implements ResponseWriter.
var _ ResponseWriter = (*responseWriterStream)(nil)

// Write implements ResponseWriter.
func (r *responseWriterStream) Write(rawMsg []byte) (int, error) {
	runtimex.Assert(len(rawMsg) <= math.MaxUint16, "message too large")
	rawMsgFrame := []byte{byte(len(rawMsg) >> 8)}
	rawMsgFrame = append(rawMsgFrame, byte(len(rawMsg)))
	rawMsgFrame = append(rawMsgFrame, rawMsg...)
	return r.conn.Write(rawMsgFrame)
}
