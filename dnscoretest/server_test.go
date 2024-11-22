// SPDX-License-Identifier: GPL-3.0-or-later

package dnscoretest

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"

	"github.com/rbmk-project/common/mocks"
	"github.com/stretchr/testify/assert"
)

func TestServer_listen(t *testing.T) {
	expectedErr := errors.New("mocked error")
	srv := &Server{
		Listen: func(network, address string) (net.Listener, error) {
			return nil, expectedErr
		},
	}
	_, err := srv.listen("tcp", "127.0.0.1:0")
	assert.ErrorIs(t, err, expectedErr)
}

func TestServer_listenPacket(t *testing.T) {
	expectedErr := errors.New("mocked error")
	srv := &Server{
		ListenPacket: func(network, address string) (net.PacketConn, error) {
			return nil, expectedErr
		},
	}
	_, err := srv.listenPacket("udp", "127.0.0.1:0")
	assert.ErrorIs(t, err, expectedErr)
}

func TestServer_listenTLS(t *testing.T) {
	expectedErr := errors.New("mocked error")
	srv := &Server{
		ListenTLS: func(network, address string, config *tls.Config) (net.Listener, error) {
			return nil, expectedErr
		},
	}
	_, err := srv.listenTLS("tcp", "127.0.0.1:0", nil)
	assert.ErrorIs(t, err, expectedErr)
}

func TestServer_Close(t *testing.T) {
	expected := errors.New("mocked error")
	srv := &Server{}

	srv.ioclosers = append(srv.ioclosers, &mocks.Conn{
		MockClose: func() error {
			return nil
		},
	})

	srv.ioclosers = append(srv.ioclosers, &mocks.Conn{
		MockClose: func() error {
			return expected
		},
	})

	srv.ioclosers = append(srv.ioclosers, &mocks.Conn{
		MockClose: func() error {
			return nil
		},
	})

	if err := srv.Close(); !errors.Is(err, expected) {
		t.Fatal("expected", expected, ", got", err)
	}
}
