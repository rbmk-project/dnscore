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
	tests := []struct {
		name     string
		query    *dns.Msg
		resp     *dns.Msg
		expected int
		err      error
	}{
		{
			name: "ValidAnswerWithoutCNAME",
			query: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				return m
			}(),
			resp: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetReply(new(dns.Msg))
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
					},
					A: net.IPv4(127, 0, 0, 1),
				})
				return m
			}(),
			expected: 1,
			err:      nil,
		},

		{
			name: "ValidAnswerWithCNAME",
			query: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.co.uk.", dns.TypeA)
				return m
			}(),
			resp: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetReply(new(dns.Msg))
				m.Answer = append(m.Answer, &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   "example.co.uk.",
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
					},
					Target: "example.com.",
				})
				m.Answer = append(m.Answer, &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
					},
					Target: "example.org.",
				})
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.org.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
					},
					A: net.IPv4(127, 0, 0, 1),
				})
				return m
			}(),
			expected: 1,
			err:      nil,
		},

		{
			name: "NoAnswers",
			query: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				return m
			}(),
			resp: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetReply(new(dns.Msg))
				return m
			}(),
			expected: 0,
			err:      ErrNoData,
		},

		{
			name: "MismatchedName",
			query: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				return m
			}(),
			resp: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetReply(new(dns.Msg))
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.org.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
					},
					A: net.IPv4(127, 0, 0, 1),
				})
				return m
			}(),
			expected: 0,
			err:      ErrNoData,
		},

		{
			name: "MismatchedClass",
			query: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				return m
			}(),
			resp: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetReply(new(dns.Msg))
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassCHAOS,
					},
					A: net.IPv4(127, 0, 0, 1),
				})
				return m
			}(),
			expected: 0,
			err:      ErrNoData,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			answers, err := ValidAnswers(tt.query.Question[0], tt.resp)
			if err != tt.err {
				t.Fatalf("expected error %v, got %v", tt.err, err)
			}
			if len(answers) != tt.expected {
				t.Fatalf("expected %d answers, got %d", tt.expected, len(answers))
			}
		})
	}
}
