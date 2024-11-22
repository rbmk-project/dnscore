// SPDX-License-Identifier: GPL-3.0-or-later

package dnscoretest

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"net"

	"github.com/rbmk-project/common/runtimex"
)

var (
	//go:embed cert.pem
	certPEM []byte

	//go:embed key.pem
	keyPEM []byte
)

// StartTLS starts a TLS listener and listens for incoming DNS queries.
//
// This method panics in case of failure.
func (s *Server) StartTLS(handler Handler) <-chan struct{} {
	runtimex.Assert(!s.started, "already started")
	ready := make(chan struct{})
	go func() {
		cert := runtimex.Try1(tls.X509KeyPair(certPEM, keyPEM))
		config := &tls.Config{Certificates: []tls.Certificate{cert}}
		listener := runtimex.Try1(s.listenTLS("tcp", "127.0.0.1:0", config))
		s.Addr = listener.Addr().String()
		s.RootCAs = x509.NewCertPool()
		runtimex.Assert(s.RootCAs.AppendCertsFromPEM(certPEM), "cannot append PEM cert")
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

// listenTLS either uses the stdlib or the custom ListenTLS func.
func (s *Server) listenTLS(network, address string, config *tls.Config) (net.Listener, error) {
	if s.ListenTLS != nil {
		return s.ListenTLS(network, address, config)
	}
	return tls.Listen(network, address, config)
}
