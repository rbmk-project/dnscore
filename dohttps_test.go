// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/rbmk-project/common/mocks"
	"github.com/rbmk-project/common/runtimex"
	"github.com/stretchr/testify/assert"
)

func TestTransport_newHTTPRequestWithContext(t *testing.T) {
	tests := []struct {
		name           string
		setupTransport func() *Transport
		method         string
		url            string
		body           io.Reader
		expectedError  error
	}{
		{
			name: "Successful request with custom function",
			setupTransport: func() *Transport {
				return &Transport{
					NewHTTPRequestWithContext: func(ctx context.Context, method, URL string, body io.Reader) (*http.Request, error) {
						return http.NewRequestWithContext(ctx, method, URL, body)
					},
				}
			},
			method:        "GET",
			url:           "https://example.com",
			body:          nil,
			expectedError: nil,
		},

		{
			name: "Successful request with default function",
			setupTransport: func() *Transport {
				return &Transport{}
			},
			method:        "GET",
			url:           "https://example.com",
			body:          nil,
			expectedError: nil,
		},

		{
			name: "Invalid URL",
			setupTransport: func() *Transport {
				return &Transport{}
			},
			method:        "GET",
			url:           "https://example.com\t",
			body:          nil,
			expectedError: errors.New("parse \"https://example.com\\t\": net/url: invalid control character in URL"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := tt.setupTransport()
			_, err := transport.newHTTPRequestWithContext(context.Background(), tt.method, tt.url, tt.body)
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTransport_httpClient(t *testing.T) {
	tests := []struct {
		name           string
		setupTransport func() *Transport
		expectedClient *http.Client
	}{
		{
			name: "Custom HTTP client",
			setupTransport: func() *Transport {
				return &Transport{
					HTTPClient: &http.Client{},
				}
			},
			expectedClient: &http.Client{},
		},

		{
			name: "Default HTTP client",
			setupTransport: func() *Transport {
				return &Transport{}
			},
			expectedClient: http.DefaultClient,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := tt.setupTransport()
			client := transport.httpClient()
			assert.Equal(t, tt.expectedClient, client)
		})
	}
}

func TestTransport_httpClientDo(t *testing.T) {
	tests := []struct {
		name               string
		setupTransport     func() *Transport
		expectedError      error
		expectedLocalAddr  netip.AddrPort
		expectedRemoteAddr netip.AddrPort
	}{
		{
			name: "HTTPClientDo takes precedence",
			setupTransport: func() *Transport {
				return &Transport{
					HTTPClientDo: func(req *http.Request) (*http.Response, netip.AddrPort, netip.AddrPort, error) {
						return &http.Response{StatusCode: 200}, netip.AddrPort{}, netip.AddrPort{}, nil
					},
					HTTPClient: &http.Client{
						Transport: &mocks.HTTPTransport{
							MockRoundTrip: func(req *http.Request) (*http.Response, error) {
								return nil, errors.New("should not be called")
							},
						},
					},
				}
			},
			expectedError:      nil,
			expectedLocalAddr:  netip.AddrPort{},
			expectedRemoteAddr: netip.AddrPort{},
		},

		{
			name: "HTTPClientDo returns error",
			setupTransport: func() *Transport {
				return &Transport{
					HTTPClientDo: func(req *http.Request) (*http.Response, netip.AddrPort, netip.AddrPort, error) {
						return nil, netip.AddrPort{}, netip.AddrPort{}, errors.New("custom error")
					},
				}
			},
			expectedError:      errors.New("custom error"),
			expectedLocalAddr:  netip.AddrPort{},
			expectedRemoteAddr: netip.AddrPort{},
		},

		{
			name: "Fallback to HTTPClient success",
			setupTransport: func() *Transport {
				return &Transport{
					HTTPClient: &http.Client{
						Transport: &mocks.HTTPTransport{
							MockRoundTrip: func(req *http.Request) (*http.Response, error) {
								return &http.Response{StatusCode: 200}, nil
							},
						},
					},
				}
			},
			expectedError:      nil,
			expectedLocalAddr:  netip.AddrPort{},
			expectedRemoteAddr: netip.AddrPort{},
		},

		{
			name: "Fallback to HTTPClient failure",
			setupTransport: func() *Transport {
				return &Transport{
					HTTPClient: &http.Client{
						Transport: &mocks.HTTPTransport{
							MockRoundTrip: func(req *http.Request) (*http.Response, error) {
								return nil, errors.New("http error")
							},
						},
					},
				}
			},
			expectedError:      errors.New("Get \"https://example.com\": http error"),
			expectedLocalAddr:  netip.AddrPort{},
			expectedRemoteAddr: netip.AddrPort{},
		},

		{
			name: "Fallback to HTTPClient collects addresses",
			setupTransport: func() *Transport {
				return &Transport{
					HTTPClient: &http.Client{
						Transport: &mocks.HTTPTransport{
							MockRoundTrip: func(req *http.Request) (*http.Response, error) {
								trace := httptrace.ContextClientTrace(req.Context())
								if trace != nil && trace.GotConn != nil {
									trace.GotConn(httptrace.GotConnInfo{
										Conn: &mocks.Conn{
											MockLocalAddr: func() net.Addr {
												return &net.TCPAddr{
													IP:   net.ParseIP("::1"),
													Port: 12345,
												}
											},
											MockRemoteAddr: func() net.Addr {
												return &net.TCPAddr{
													IP:   net.ParseIP("::2"),
													Port: 443,
												}
											},
										},
									})
								}
								return &http.Response{StatusCode: 200}, nil
							},
						},
					},
				}
			},
			expectedError:      nil,
			expectedLocalAddr:  netip.MustParseAddrPort("[::1]:12345"),
			expectedRemoteAddr: netip.MustParseAddrPort("[::2]:443"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := tt.setupTransport()
			req := runtimex.Try1(http.NewRequest("GET", "https://example.com", nil))
			resp, la, ra, err := transport.httpClientDo(req)
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
			}
			assert.Equal(t, tt.expectedLocalAddr, la)
			assert.Equal(t, tt.expectedRemoteAddr, ra)
		})
	}
}

func TestTransport_readAllContext(t *testing.T) {
	tests := []struct {
		name           string
		setupTransport func() *Transport
		reader         io.Reader
		closer         io.Closer
		expectedData   []byte
		expectedError  error
	}{
		{
			name: "Successful read with custom function",
			setupTransport: func() *Transport {
				return &Transport{
					ReadAllContext: func(ctx context.Context, r io.Reader, c io.Closer) ([]byte, error) {
						return io.ReadAll(r)
					},
				}
			},
			reader:        bytes.NewReader([]byte("test data")),
			closer:        io.NopCloser(nil),
			expectedData:  []byte("test data"),
			expectedError: nil,
		},

		{
			name: "Successful read with default function",
			setupTransport: func() *Transport {
				return &Transport{}
			},
			reader:        bytes.NewReader([]byte("test data")),
			closer:        io.NopCloser(nil),
			expectedData:  []byte("test data"),
			expectedError: nil,
		},

		{
			name: "Read failure",
			setupTransport: func() *Transport {
				return &Transport{}
			},
			reader:        &mocks.Conn{MockRead: func(b []byte) (int, error) { return 0, errors.New("read failed") }},
			closer:        io.NopCloser(nil),
			expectedData:  nil,
			expectedError: errors.New("read failed"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := tt.setupTransport()
			data, err := transport.readAllContext(context.Background(), tt.reader, tt.closer)
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedData, data)
			}
		})
	}
}

func TestTransport_queryHTTPS(t *testing.T) {
	tests := []struct {
		name           string
		setupTransport func() *Transport
		questionName   string
		url            string
		expectedError  error
	}{
		{
			name: "Successful query",
			setupTransport: func() *Transport {
				return &Transport{
					HTTPClient: &http.Client{
						Transport: &mocks.HTTPTransport{
							MockRoundTrip: func(req *http.Request) (*http.Response, error) {
								dnsResp := &dns.Msg{}
								rawDnsResp, err := dnsResp.Pack()
								if err != nil {
									panic(err)
								}
								resp := &http.Response{
									StatusCode: 200,
									Header:     make(http.Header),
									Body:       io.NopCloser(bytes.NewReader(rawDnsResp)),
								}
								resp.Header.Set("content-type", "application/dns-message")
								return resp, nil
							},
						},
					},
				}
			},
			questionName:  "example.com.",
			url:           "https://dns.google/dns-query",
			expectedError: nil,
		},

		{
			name: "HTTP request failure",
			setupTransport: func() *Transport {
				return &Transport{
					HTTPClient: &http.Client{
						Transport: &mocks.HTTPTransport{
							MockRoundTrip: func(req *http.Request) (*http.Response, error) {
								return nil, errors.New("http request failed")
							},
						},
					},
				}
			},
			questionName:  "example.com.",
			url:           "https://dns.google/dns-query",
			expectedError: errors.New("Post \"https://dns.google/dns-query\": http request failed"),
		},

		{
			name: "Non-200 HTTP status code",
			setupTransport: func() *Transport {
				return &Transport{
					HTTPClient: &http.Client{
						Transport: &mocks.HTTPTransport{
							MockRoundTrip: func(req *http.Request) (*http.Response, error) {
								resp := &http.Response{
									StatusCode: 500,
									Header:     make(http.Header),
									Body:       io.NopCloser(bytes.NewReader([]byte{})),
								}
								return resp, nil
							},
						},
					},
				}
			},
			questionName:  "example.com.",
			url:           "https://dns.google/dns-query",
			expectedError: ErrServerMisbehaving,
		},

		{
			name: "Invalid content type",
			setupTransport: func() *Transport {
				return &Transport{
					HTTPClient: &http.Client{
						Transport: &mocks.HTTPTransport{
							MockRoundTrip: func(req *http.Request) (*http.Response, error) {
								resp := &http.Response{
									StatusCode: 200,
									Header:     make(http.Header),
									Body:       io.NopCloser(bytes.NewReader([]byte{})),
								}
								resp.Header.Set("content-type", "text/plain")
								return resp, nil
							},
						},
					},
				}
			},
			questionName:  "example.com.",
			url:           "https://dns.google/dns-query",
			expectedError: ErrServerMisbehaving,
		},

		{
			name: "Invalid DNS response",
			setupTransport: func() *Transport {
				return &Transport{
					HTTPClient: &http.Client{
						Transport: &mocks.HTTPTransport{
							MockRoundTrip: func(req *http.Request) (*http.Response, error) {
								resp := &http.Response{
									StatusCode: 200,
									Header:     make(http.Header),
									Body:       io.NopCloser(bytes.NewReader([]byte{0xFF})),
								}
								resp.Header.Set("content-type", "application/dns-message")
								return resp, nil
							},
						},
					},
				}
			},
			questionName:  "example.com.",
			url:           "https://dns.google/dns-query",
			expectedError: errors.New("dns: overflow unpacking uint16"),
		},

		{
			name: "Non-FQDN domain name",
			setupTransport: func() *Transport {
				return &Transport{
					HTTPClient: &http.Client{
						Transport: &mocks.HTTPTransport{
							MockRoundTrip: func(req *http.Request) (*http.Response, error) {
								return nil, nil
							},
						},
					},
				}
			},
			questionName:  "example",
			url:           "https://dns.google/dns-query",
			expectedError: errors.New("dns: domain must be fully qualified"),
		},

		{
			name: "Invalid URL",
			setupTransport: func() *Transport {
				return &Transport{
					HTTPClient: &http.Client{
						Transport: &mocks.HTTPTransport{
							MockRoundTrip: func(req *http.Request) (*http.Response, error) {
								return nil, nil
							},
						},
					},
				}
			},
			questionName:  "example.com.",
			url:           "https://dns.google/dns-query\t",
			expectedError: errors.New("parse \"https://dns.google/dns-query\\t\": net/url: invalid control character in URL"),
		},

		{
			name: "Fail reading response body",
			setupTransport: func() *Transport {
				return &Transport{
					HTTPClient: &http.Client{
						Transport: &mocks.HTTPTransport{
							MockRoundTrip: func(req *http.Request) (*http.Response, error) {
								resp := &http.Response{
									StatusCode: 200,
									Header:     make(http.Header),
									Body: &mocks.Conn{
										MockRead: func(b []byte) (int, error) {
											return 0, errors.New("read failed")
										},
										MockClose: func() error {
											return nil
										},
									},
								}
								resp.Header.Set("content-type", "application/dns-message")
								return resp, nil
							},
						},
					},
				}
			},
			questionName:  "example.com.",
			url:           "https://dns.google/dns-query",
			expectedError: errors.New("read failed"),
		},

		{
			name: "HTTPClientDo takes precedence over HTTPClient",
			setupTransport: func() *Transport {
				return &Transport{
					// Should be used
					HTTPClientDo: func(req *http.Request) (*http.Response, netip.AddrPort, netip.AddrPort, error) {
						dnsResp := &dns.Msg{}
						rawDnsResp, err := dnsResp.Pack()
						if err != nil {
							panic(err)
						}
						resp := &http.Response{
							StatusCode: 200,
							Header:     make(http.Header),
							Body:       io.NopCloser(bytes.NewReader(rawDnsResp)),
						}
						resp.Header.Set("content-type", "application/dns-message")
						return resp, netip.AddrPort{}, netip.AddrPort{}, nil
					},
					// Should not be used
					HTTPClient: &http.Client{
						Transport: &mocks.HTTPTransport{
							MockRoundTrip: func(req *http.Request) (*http.Response, error) {
								return nil, errors.New("HTTPClient should not be used")
							},
						},
					},
				}
			},
			questionName:  "example.com.",
			url:           "https://dns.google/dns-query",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := tt.setupTransport()
			addr := &ServerAddr{Address: tt.url, Protocol: ProtocolDoH}
			query := new(dns.Msg)
			query.SetQuestion(tt.questionName, dns.TypeA)

			_, err := transport.queryHTTPS(context.Background(), addr, query)
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
