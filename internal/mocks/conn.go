//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/ooni/probe-cli/blob/v3.20.1/internal/mocks/dialer.go
//

package mocks

import (
	"net"
	"time"
)

// Conn is a mockable net.Conn.
type Conn struct {
	// MockRead is the function to call when Read is called.
	MockRead func(b []byte) (int, error)

	// MockWrite is the function to call when Write is called.
	MockWrite func(b []byte) (int, error)

	// MockClose is the function to call when Close is called.
	MockClose func() error

	// MockLocalAddr is the function to call when LocalAddr is called.
	MockLocalAddr func() net.Addr

	// MockRemoteAddr is the function to call when RemoteAddr is called.
	MockRemoteAddr func() net.Addr

	// MockSetDeadline is the function to call when SetDeadline is called.
	MockSetDeadline func(t time.Time) error

	// MockSetReadDeadline is the function to call when SetReadDeadline is called.
	MockSetReadDeadline func(t time.Time) error

	// MockSetWriteDeadline is the function to call when SetWriteDeadline is called.
	MockSetWriteDeadline func(t time.Time) error
}

var _ net.Conn = &Conn{}

// Read calls MockRead.
func (c *Conn) Read(b []byte) (int, error) {
	return c.MockRead(b)
}

// Write calls MockWrite.
func (c *Conn) Write(b []byte) (int, error) {
	return c.MockWrite(b)
}

// Close calls MockClose.
func (c *Conn) Close() error {
	return c.MockClose()
}

// LocalAddr calls MockLocalAddr.
func (c *Conn) LocalAddr() net.Addr {
	return c.MockLocalAddr()
}

// RemoteAddr calls MockRemoteAddr.
func (c *Conn) RemoteAddr() net.Addr {
	return c.MockRemoteAddr()
}

// SetDeadline calls MockSetDeadline.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.MockSetDeadline(t)
}

// SetReadDeadline calls MockSetReadDeadline.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.MockSetReadDeadline(t)
}

// SetWriteDeadline calls MockSetWriteDeadline.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.MockSetWriteDeadline(t)
}
