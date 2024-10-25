// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import "testing"

func TestNewServerAddr(t *testing.T) {
	protocol := ProtocolUDP
	address := "8.8.8.8:53"
	serverAddr := NewServerAddr(protocol, address)

	if serverAddr.Protocol != protocol {
		t.Errorf("Expected protocol %s, got %s", protocol, serverAddr.Protocol)
	}

	if serverAddr.Address != address {
		t.Errorf("Expected address %s, got %s", address, serverAddr.Address)
	}
}
