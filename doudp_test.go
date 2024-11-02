// SPDX-License-Identifier: GPL-3.0-or-later

package dnscore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rbmk-project/dnscore/internal/mocks"
	"github.com/stretchr/testify/assert"
)

func TestTransport_dialContext(t *testing.T) {
	tests := []struct {
		name          string
		dialContext   func(ctx context.Context, network, address string) (net.Conn, error)
		expectedError error
	}{
		{
			name: "Custom dialer success",
			dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return &mocks.Conn{}, nil
			},
			expectedError: nil,
		},

		{
			name: "Custom dialer failure",
			dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, errors.New("dial failed")
			},
			expectedError: errors.New("dial failed"),
		},

		{
			// note: this is still a unit test because dialing a UDP
			// connection doesn't involve any network activity
			name:          "Default dialer success",
			dialContext:   nil,
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &Transport{
				DialContext: tt.dialContext,
			}
			_, err := transport.dialContext(context.Background(), "udp", "8.8.8.8:53")
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTransport_timeNow(t *testing.T) {
	tests := []struct {
		name     string
		timeNow  func() time.Time
		expected time.Time
	}{
		{
			name: "Custom time function",
			timeNow: func() time.Time {
				return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
			},
			expected: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		},

		{
			name:     "Default time function",
			timeNow:  nil,
			expected: time.Now(), // This will be close to the current time
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &Transport{
				TimeNow: tt.timeNow,
			}
			actual := transport.timeNow()
			if tt.timeNow != nil {
				assert.Equal(t, tt.expected, actual)
			} else {
				assert.WithinDuration(t, tt.expected, actual, 5*time.Second)
			}
		})
	}
}

func TestTransport_maybeLogQuery(t *testing.T) {
	tests := []struct {
		name       string
		newLogger  func(w io.Writer) *slog.Logger
		expectTime time.Time
		expectLog  string
	}{
		{
			name: "Logger set",
			newLogger: func(w io.Writer) *slog.Logger {
				return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
					Level: slog.LevelDebug,
					ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
						if attr.Key == slog.TimeKey {
							return slog.Attr{}
						}
						return attr
					},
				}))
			},
			expectTime: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			expectLog:  "{\"level\":\"INFO\",\"msg\":\"dnsQuery\",\"rawQuery\":\"AAAAAA==\",\"serverAddr\":\"8.8.8.8:53\",\"serverProtocol\":\"udp\",\"t\":\"2020-01-01T00:00:00Z\"}\n",
		},

		{
			name:       "Logger not set",
			newLogger:  func(w io.Writer) *slog.Logger { return nil },
			expectTime: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			expectLog:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			transport := &Transport{
				Logger: tt.newLogger(&out),
				TimeNow: func() time.Time {
					return tt.expectTime
				},
			}

			addr := &ServerAddr{Address: "8.8.8.8:53", Protocol: ProtocolUDP}
			rawQuery := []byte{0, 0, 0, 0}

			actualTime := transport.maybeLogQuery(addr, rawQuery)

			assert.Equal(t, tt.expectTime, actualTime)

			actualLog := out.String()
			assert.Equal(t, tt.expectLog, actualLog)
		})
	}
}

func TestTransport_maybeLogResponse(t *testing.T) {
	tests := []struct {
		name      string
		newLogger func(w io.Writer) *slog.Logger
		expectLog string
	}{
		{
			name: "Logger set",
			newLogger: func(w io.Writer) *slog.Logger {
				return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
					Level: slog.LevelDebug,
					ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
						if attr.Key == slog.TimeKey {
							return slog.Attr{}
						}
						return attr
					},
				}))
			},
			expectLog: "{\"level\":\"INFO\",\"msg\":\"dnsResponse\",\"rawQuery\":\"AAAAAA==\",\"rawResponse\":\"AQEBAQ==\",\"serverAddr\":\"8.8.8.8:53\",\"serverProtocol\":\"udp\",\"t0\":\"2020-01-01T00:00:00Z\",\"t\":\"2020-01-01T00:00:11Z\"}\n",
		},

		{
			name:      "Logger not set",
			newLogger: func(w io.Writer) *slog.Logger { return nil },
			expectLog: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			transport := &Transport{
				Logger: tt.newLogger(&out),
				TimeNow: func() time.Time {
					return time.Date(2020, 1, 1, 0, 0, 11, 0, time.UTC)
				},
			}

			addr := &ServerAddr{Address: "8.8.8.8:53", Protocol: ProtocolUDP}
			rawQuery := []byte{0, 0, 0, 0}
			rawResponse := []byte{1, 1, 1, 1}

			transport.maybeLogResponse(
				addr,
				time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
				rawQuery,
				rawResponse,
			)

			actualLog := out.String()
			assert.Equal(t, tt.expectLog, actualLog)
		})
	}
}
func TestTransport_sendQueryUDP(t *testing.T) {
	tests := []struct {
		name           string
		questionName   string
		setupTransport func(setDeadlineCalled *bool) *Transport
		expectedError  error
		expectDeadline bool
	}{
		{
			name:         "Successful send",
			questionName: "example.com.",
			setupTransport: func(setDeadlineCalled *bool) *Transport {
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return &mocks.Conn{
							MockWrite: func(b []byte) (int, error) {
								return len(b), nil
							},
							MockClose: func() error {
								return nil
							},
							MockSetDeadline: func(t time.Time) error {
								*setDeadlineCalled = true
								return nil
							},
						}, nil
					},
				}
			},
			expectedError:  nil,
			expectDeadline: true,
		},

		{
			name:         "Dial failure",
			questionName: "example.com.",
			setupTransport: func(_ *bool) *Transport {
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return nil, errors.New("dial failed")
					},
				}
			},
			expectedError:  errors.New("dial failed"),
			expectDeadline: false,
		},

		{
			name:         "Write failure",
			questionName: "example.com.",
			setupTransport: func(setDeadlineCalled *bool) *Transport {
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return &mocks.Conn{
							MockWrite: func(b []byte) (int, error) {
								return 0, errors.New("write failed")
							},
							MockClose: func() error {
								return nil
							},
							MockSetDeadline: func(t time.Time) error {
								*setDeadlineCalled = true
								return nil
							},
						}, nil
					},
				}
			},
			expectedError:  errors.New("write failed"),
			expectDeadline: true,
		},

		{
			name:         "Cannot pack query",
			questionName: "nameThatIsNotCanonicalFQDN",
			setupTransport: func(setDeadlineCalled *bool) *Transport {
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return &mocks.Conn{
							MockClose: func() error {
								return nil
							},
							MockSetDeadline: func(t time.Time) error {
								*setDeadlineCalled = true
								return nil
							},
						}, nil
					},
				}
			},
			expectedError:  errors.New("dns: domain must be fully qualified"),
			expectDeadline: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var setDeadlineCalled bool

			transport := tt.setupTransport(&setDeadlineCalled)
			addr := &ServerAddr{Address: "8.8.8.8:53", Protocol: ProtocolUDP}
			query := new(dns.Msg)
			query.SetQuestion(tt.questionName, dns.TypeA)

			ctx := context.Background()
			if tt.expectDeadline {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(1*time.Hour))
				defer cancel()
			}

			conn, _, _, err := transport.sendQueryUDP(ctx, addr, query)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
				if tt.expectDeadline {
					assert.NotNil(t, conn)
					assert.True(t, setDeadlineCalled)
				}
			}
		})
	}
}

func Test_edns0MaxResponseSize(t *testing.T) {
	tests := []struct {
		name     string
		query    *dns.Msg
		expected uint16
	}{
		{
			name: "EDNS0 option set",
			query: func() *dns.Msg {
				msg := new(dns.Msg)
				opt := new(dns.OPT)
				opt.SetUDPSize(4096)
				msg.Extra = append(msg.Extra, opt)
				return msg
			}(),
			expected: 4096,
		},

		{
			name: "No EDNS0 option set",
			query: func() *dns.Msg {
				return new(dns.Msg)
			}(),
			expected: 512,
		},

		{
			name: "EDNS0 option with zero size",
			query: func() *dns.Msg {
				msg := new(dns.Msg)
				opt := new(dns.OPT)
				opt.SetUDPSize(0)
				msg.Extra = append(msg.Extra, opt)
				return msg
			}(),
			expected: 512,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := edns0MaxResponseSize(tt.query)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestTransport_recvResponseUDP(t *testing.T) {
	tests := []struct {
		name           string
		setupTransport func() *Transport
		expectedError  error
	}{
		{
			name: "Successful receive",
			setupTransport: func() *Transport {
				return &Transport{}
			},
			expectedError: nil,
		},

		{
			name: "Read failure",
			setupTransport: func() *Transport {
				return &Transport{}
			},
			expectedError: errors.New("read failed"),
		},

		{
			name: "Unpack failure",
			setupTransport: func() *Transport {
				return &Transport{}
			},
			expectedError: errors.New("dns: overflow unpacking uint16"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := tt.setupTransport()
			addr := &ServerAddr{Address: "8.8.8.8:53", Protocol: ProtocolUDP}
			query := new(dns.Msg)
			query.SetQuestion("example.com.", dns.TypeA)
			conn := &mocks.Conn{
				MockRead: func(b []byte) (int, error) {
					if tt.expectedError != nil {
						return 0, tt.expectedError
					}
					copy(b, []byte{0, 0, 0, 0})
					return len(b), nil
				},
				MockClose: func() error {
					return nil
				},
			}

			_, err := transport.recvResponseUDP(addr, conn, time.Now(), query, []byte{0, 0, 0, 0})

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTransport_queryUDP(t *testing.T) {
	tests := []struct {
		name           string
		setupTransport func() *Transport
		expectedError  error
	}{
		{
			name: "Successful query",
			setupTransport: func() *Transport {
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return &mocks.Conn{
							MockWrite: func(b []byte) (int, error) {
								return len(b), nil
							},
							MockRead: func(b []byte) (int, error) {
								copy(b, []byte{0, 0, 0, 0})
								return len(b), nil
							},
							MockClose: func() error {
								return nil
							},
						}, nil
					},
				}
			},
			expectedError: nil,
		},

		{
			name: "Dial failure",
			setupTransport: func() *Transport {
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return nil, errors.New("dial failed")
					},
				}
			},
			expectedError: errors.New("dial failed"),
		},

		{
			name: "Write failure",
			setupTransport: func() *Transport {
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return &mocks.Conn{
							MockWrite: func(b []byte) (int, error) {
								return 0, errors.New("write failed")
							},
							MockClose: func() error {
								return nil
							},
						}, nil
					},
				}
			},
			expectedError: errors.New("write failed"),
		},

		{
			name: "Read failure",
			setupTransport: func() *Transport {
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return &mocks.Conn{
							MockWrite: func(b []byte) (int, error) {
								return len(b), nil
							},
							MockRead: func(b []byte) (int, error) {
								return 0, errors.New("read failed")
							},
							MockClose: func() error {
								return nil
							},
						}, nil
					},
				}
			},
			expectedError: errors.New("read failed"),
		},

		{
			name: "Send query failure",
			setupTransport: func() *Transport {
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return &mocks.Conn{
							MockWrite: func(b []byte) (int, error) {
								return 0, errors.New("send query failed")
							},
							MockClose: func() error {
								return nil
							},
						}, nil
					},
				}
			},
			expectedError: errors.New("send query failed"),
		},

		{
			name: "Garbage response",
			setupTransport: func() *Transport {
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return &mocks.Conn{
							MockWrite: func(b []byte) (int, error) {
								return len(b), nil
							},
							MockRead: func(b []byte) (int, error) {
								copy(b, []byte{0xFF})
								return 1, nil
							},
							MockClose: func() error {
								return nil
							},
						}, nil
					},
				}
			},
			expectedError: errors.New("dns: overflow unpacking uint16"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := tt.setupTransport()
			addr := NewServerAddr(ProtocolUDP, "8.8.8.8:53")
			query := new(dns.Msg)
			query.SetQuestion("example.com.", dns.TypeA)

			_, err := transport.queryUDP(context.Background(), addr, query)
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTransport_emitMessageOrError(t *testing.T) {
	tests := []struct {
		name          string
		msg           *dns.Msg
		err           error
		expectedError error
	}{
		{
			name:          "Send message",
			msg:           new(dns.Msg),
			err:           nil,
			expectedError: nil,
		},

		{
			name:          "Send error",
			msg:           nil,
			err:           errors.New("test error"),
			expectedError: errors.New("test error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &Transport{}
			out := make(chan *MessageOrError, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			transport.emitMessageOrError(ctx, tt.msg, tt.err, out)
			messageOrError := <-out

			if tt.expectedError != nil {
				assert.Error(t, messageOrError.Err)
				assert.Equal(t, tt.expectedError.Error(), messageOrError.Err.Error())
			} else {
				assert.NoError(t, messageOrError.Err)
				assert.Equal(t, tt.msg, messageOrError.Msg)
			}
		})
	}
}

func TestTransport_queryUDPWithDuplicates(t *testing.T) {
	tests := []struct {
		name           string
		setupTransport func() *Transport
		expectedError  error
	}{
		{
			name: "Successful query with duplicates",
			setupTransport: func() *Transport {
				count := &atomic.Int64{}
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return &mocks.Conn{
							MockWrite: func(b []byte) (int, error) {
								return len(b), nil
							},
							MockRead: func(b []byte) (int, error) {
								if count.Add(1) > 3 {
									return 0, os.ErrDeadlineExceeded
								}
								copy(b, []byte{0, 0, 0, 0})
								return len(b), nil
							},
							MockClose: func() error {
								return nil
							},
						}, nil
					},
				}
			},
			expectedError: os.ErrDeadlineExceeded,
		},

		{
			name: "Dial failure",
			setupTransport: func() *Transport {
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return nil, errors.New("dial failed")
					},
				}
			},
			expectedError: errors.New("dial failed"),
		},

		{
			name: "Write failure",
			setupTransport: func() *Transport {
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return &mocks.Conn{
							MockWrite: func(b []byte) (int, error) {
								return 0, errors.New("write failed")
							},
							MockClose: func() error {
								return nil
							},
						}, nil
					},
				}
			},
			expectedError: errors.New("write failed"),
		},

		{
			name: "Read failure",
			setupTransport: func() *Transport {
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return &mocks.Conn{
							MockWrite: func(b []byte) (int, error) {
								return len(b), nil
							},
							MockRead: func(b []byte) (int, error) {
								return 0, errors.New("read failed")
							},
							MockClose: func() error {
								return nil
							},
						}, nil
					},
				}
			},
			expectedError: errors.New("read failed"),
		},

		{
			name: "Garbage response",
			setupTransport: func() *Transport {
				return &Transport{
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return &mocks.Conn{
							MockWrite: func(b []byte) (int, error) {
								return len(b), nil
							},
							MockRead: func(b []byte) (int, error) {
								copy(b, []byte{0xFF})
								return 1, nil
							},
							MockClose: func() error {
								return nil
							},
						}, nil
					},
				}
			},
			expectedError: errors.New("dns: overflow unpacking uint16"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := tt.setupTransport()
			addr := NewServerAddr(ProtocolUDP, "8.8.8.8:53")
			query := new(dns.Msg)
			query.SetQuestion("example.com.", dns.TypeA)

			ch := transport.queryUDPWithDuplicates(context.Background(), addr, query)
			messages := []*MessageOrError{}
			for msgOrErr := range ch {
				messages = append(messages, msgOrErr)
			}
			if len(messages) <= 0 {
				t.Fatal("No messages received")
			}
			last := messages[len(messages)-1]
			if tt.expectedError != nil {
				assert.Error(t, last.Err)
				assert.Equal(t, tt.expectedError.Error(), last.Err.Error())
			} else {
				assert.NoError(t, last.Err)
			}
		})
	}
}
