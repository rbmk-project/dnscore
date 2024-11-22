// SPDX-License-Identifier: GPL-3.0-or-later

package dnscoretest

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/url"

	"github.com/rbmk-project/common/runtimex"
)

// StartHTTPS starts an HTTPS server and handles incoming DNS queries.
//
// This method panics in case of failure.
func (s *Server) StartHTTPS(handler Handler) <-chan struct{} {
	runtimex.Assert(!s.started, "already started")
	ready := make(chan struct{})
	go func() {
		cert := runtimex.Try1(tls.X509KeyPair(certPEM, keyPEM))
		config := &tls.Config{Certificates: []tls.Certificate{cert}}
		listener := runtimex.Try1(s.listenTLS("tcp", "127.0.0.1:0", config))
		s.Addr = listener.Addr().String()
		s.RootCAs = x509.NewCertPool()
		runtimex.Assert(s.RootCAs.AppendCertsFromPEM(certPEM), "cannot append PEM cert")
		s.URL = (&url.URL{Scheme: "https", Host: s.Addr, Path: "/dns-query"}).String()
		s.ioclosers = append(s.ioclosers, listener)
		s.started = true
		srv := &http.Server{
			Handler: newHTTPHandler(handler),
		}
		close(ready)
		_ = srv.Serve(listener)
	}()
	return ready
}

func newHTTPHandler(handler Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawQuery := runtimex.Try1(io.ReadAll(r.Body))
		rw := &responseWriterHTTPS{w}
		handler.Handle(rw, rawQuery)
	})
}

// responseWriterHTTPS is a response writer for HTTPS.
type responseWriterHTTPS struct {
	w http.ResponseWriter
}

// Ensure responseWriterHTTPS implements ResponseWriter.
var _ ResponseWriter = (*responseWriterHTTPS)(nil)

// Write implements ResponseWriter.
func (r *responseWriterHTTPS) Write(rawResp []byte) (int, error) {
	r.w.Header().Add("Content-Type", "application/dns-message")
	return r.w.Write(rawResp)
}
