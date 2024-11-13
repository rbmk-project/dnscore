// SPDX-License-Identifier: GPL-3.0-or-later

package dnscoretest

import (
	"errors"
	"testing"

	"github.com/rbmk-project/common/mocks"
)

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
