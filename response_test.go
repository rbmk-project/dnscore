// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestValidateResponse(t *testing.T) {
	tests := []struct {
		name     string
		modify   func(*dns.Msg, *dns.Msg)
		expected error
	}{
		{
			name: "ValidResponse",
			modify: func(query, resp *dns.Msg) {
				// No modification needed, valid response
			},
			expected: nil,
		},

		{
			name: "InvalidResponseID",
			modify: func(query, resp *dns.Msg) {
				resp.Id = query.Id + 1
			},
			expected: ErrInvalidResponse,
		},

		{
			name: "InvalidResponseNotAResponse",
			modify: func(query, resp *dns.Msg) {
				resp.Response = false
			},
			expected: ErrInvalidResponse,
		},

		{
			name: "InvalidQueryNoQuestion",
			modify: func(query, resp *dns.Msg) {
				query.Question = nil
			},
			expected: ErrInvalidQuery,
		},

		{
			name: "InvalidResponseNoQuestion",
			modify: func(query, resp *dns.Msg) {
				resp.Question = nil
			},
			expected: ErrInvalidResponse,
		},

		{
			name: "InvalidResponseQuestionName",
			modify: func(query, resp *dns.Msg) {
				resp.Question[0].Name = "invalid.com."
			},
			expected: ErrInvalidResponse,
		},

		{
			name: "InvalidResponseQuestionClass",
			modify: func(query, resp *dns.Msg) {
				resp.Question[0].Qclass = dns.ClassCHAOS
			},
			expected: ErrInvalidResponse,
		},

		{
			name: "InvalidResponseQuestionType",
			modify: func(query, resp *dns.Msg) {
				resp.Question[0].Qtype = dns.TypeAAAA
			},
			expected: ErrInvalidResponse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := new(dns.Msg)
			query.SetQuestion("example.com.", dns.TypeA)

			resp := new(dns.Msg)
			resp.SetReply(query)

			tt.modify(query, resp)

			if err := ValidateResponse(query, resp); err != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, err)
			}
		})
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
		{"OnlyPrefixMatch", "example.co.", "example.co.uk.", false},
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
