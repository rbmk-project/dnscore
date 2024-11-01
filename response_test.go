// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestValidateResponse(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	resp := new(dns.Msg)
	resp.SetReply(query)

	if err := ValidateResponse(query, resp); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	resp.Id = query.Id + 1
	if err := ValidateResponse(query, resp); err != ErrInvalidResponse {
		t.Fatalf("expected ErrInvalidResponse, got %v", err)
	}
}

func Test_equalASCIIName(t *testing.T) {
	tests := []struct {
		name     string
		x        string
		y        string
		expected bool
	}{
		{"EqualNames", "example.com.", "example.com.", true},
		{"EqualNamesDifferentCase", "Example.COM.", "exaMple.com.", true},
		{"DifferentNames", "example.com.", "example.org.", false},
		{"DifferentLengths", "example.com.", "example.co.uk.", false},
		{"EmptyStrings", "", "", true},
		{"OneEmptyString", "example.com.", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if result := equalASCIIName(tt.x, tt.y); result != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestRCodeToError(t *testing.T) {
	tests := []struct {
		name     string
		rcode    int
		expected error
	}{
		{"NameError", dns.RcodeNameError, ErrNoName},
		{"ServerFailure", dns.RcodeServerFailure, ErrServerTemporarilyMisbehaving},
		{"LameReferral", dns.RcodeSuccess, ErrNoData},
		{"Success", dns.RcodeSuccess, nil},
		{"Refused", dns.RcodeRefused, ErrServerMisbehaving},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := new(dns.Msg)
			resp.Rcode = tt.rcode

			if tt.name == "LameReferral" {
				resp.Authoritative = false
				resp.RecursionAvailable = false
				resp.Answer = nil
			} else if tt.name == "Success" {
				resp.Authoritative = true
				resp.RecursionAvailable = true
				resp.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
					},
					A: net.IPv4(127, 0, 0, 1),
				}}
			}

			if err := RCodeToError(resp); err != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, err)
			}
		})
	}
}

func TestValidAnswers(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
		},
		A: net.IPv4(127, 0, 0, 1),
	})

	answers, err := ValidAnswers(query.Question[0], resp)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(answers))
	}
}
