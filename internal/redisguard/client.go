package redisguard

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/redis/go-redis/v9"
)

// Limits are internal application profiles, not untrusted runtime input.
// Allocation headers, complete replies and a serialized read each have bounds.
type Limits struct {
	ReadBytes, ReplyBytes, BulkBytes         int64
	ReadElements, ReplyElements, ArrayLength int64
	Depth                                    int
	Error                                    error
}

// Client bounds replies before go-redis sees allocation headers.
// It uses RESP2, available on the supported legacy Redis as well as Redis 8;
// TLS and caller-supplied dialers still run before the plaintext reply guard.
type Client struct {
	*redis.Client
	budget *readBudget
	gate   chan struct{}
}

func NewClient(options *redis.Options, limits Limits) *Client {
	if options == nil {
		options = &redis.Options{}
	}
	copy := *options
	copy.Protocol, copy.PoolSize = 2, 1
	copy.MaxActiveConns, copy.MinIdleConns = 1, 0
	copy.ContextTimeoutEnabled = true
	dial := copy.Dialer
	if dial == nil {
		dial = redis.NewDialer(&copy)
	}
	if limits.Error == nil || limits.Depth < 1 || limits.BulkBytes < 1 || limits.ReplyBytes < limits.BulkBytes || limits.ReadBytes < limits.ReplyBytes || limits.ArrayLength < 1 || limits.ReplyElements < limits.ArrayLength || limits.ReadElements < limits.ReplyElements {
		panic("invalid Redis reply limits")
	}
	budget := &readBudget{limits: limits}
	copy.Dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return newReplyConn(conn, budget), nil
	}
	return &Client{Client: redis.NewClient(&copy), budget: budget, gate: make(chan struct{}, 1)}
}

func (c *Client) BeginRead(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case c.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	c.budget.mu.Lock()
	c.budget.active, c.budget.bytes, c.budget.elements = true, 0, 0
	c.budget.mu.Unlock()
	return func() {
		c.budget.mu.Lock()
		c.budget.active = false
		c.budget.mu.Unlock()
		<-c.gate
	}, nil
}

type readBudget struct {
	limits   Limits
	mu       sync.Mutex
	active   bool
	bytes    int64
	elements int64
}

func (b *readBudget) reserve(bytes, elements int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.active {
		return nil
	}
	if bytes > b.limits.ReadBytes-b.bytes || elements > b.limits.ReadElements-b.elements {
		return b.limits.Error
	}
	b.bytes += bytes
	b.elements += elements
	return nil
}

// Headers are held until validated. Forwarding a "$1073741824" prefix and
// checking only payload reads would be too late: the driver allocates first.
// The guard streams permitted payloads, rather than buffering full replies.
type replyConn struct {
	net.Conn
	reader        *bufio.Reader
	budget        *readBudget
	pending       []byte
	stack         []int64
	bodyRemaining int64
	body          bool
	frameBytes    int64
	frameElements int64
}

func newReplyConn(conn net.Conn, budget *readBudget) *replyConn {
	return &replyConn{Conn: conn, reader: bufio.NewReaderSize(conn, 4096), budget: budget}
}

func (c *replyConn) charge(bytes, elements int64) error {
	if bytes > c.budget.limits.ReplyBytes-c.frameBytes || elements > c.budget.limits.ReplyElements-c.frameElements {
		return c.budget.limits.Error
	}
	if err := c.budget.reserve(bytes, elements); err != nil {
		return err
	}
	c.frameBytes += bytes
	c.frameElements += elements
	return nil
}

func (c *replyConn) finishValue() {
	for len(c.stack) > 0 {
		last := len(c.stack) - 1
		c.stack[last]--
		if c.stack[last] > 0 {
			return
		}
		c.stack = c.stack[:last]
	}
	c.frameBytes, c.frameElements = 0, 0
}

func (c *replyConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if c.body {
		if c.bodyRemaining > 0 {
			want := int64(len(p))
			if want > c.bodyRemaining {
				want = c.bodyRemaining
			}
			n, err := c.reader.Read(p[:int(want)])
			c.bodyRemaining -= int64(n)
			return n, err
		}
		var terminator [2]byte
		if _, err := io.ReadFull(c.reader, terminator[:]); err != nil {
			return 0, err
		}
		if terminator != [2]byte{'\r', '\n'} {
			return 0, fmt.Errorf("invalid bounded Redis bulk terminator")
		}
		c.body = false
		c.pending = append(c.pending, terminator[:]...)
		c.finishValue()
		return c.Read(p)
	}
	line, err := c.reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return 0, c.budget.limits.Error
	}
	if err != nil {
		return 0, err
	}
	if len(line) < 3 || line[len(line)-2] != '\r' {
		return 0, fmt.Errorf("invalid bounded Redis reply header")
	}
	if err := c.charge(int64(len(line)), 0); err != nil {
		return 0, err
	}
	switch line[0] {
	case '+', '-', ':':
		c.finishValue()
	case '$', '*':
		length, err := strconv.ParseInt(string(line[1:len(line)-2]), 10, 64)
		if err != nil || length < -1 {
			return 0, fmt.Errorf("invalid bounded Redis reply length")
		}
		if line[0] == '$' {
			if length > c.budget.limits.BulkBytes {
				return 0, c.budget.limits.Error
			}
			if length < 0 {
				c.finishValue()
			} else {
				if err := c.charge(length+2, 0); err != nil {
					return 0, err
				}
				c.body, c.bodyRemaining = true, length
			}
		} else {
			if length > c.budget.limits.ArrayLength || len(c.stack) >= c.budget.limits.Depth {
				return 0, c.budget.limits.Error
			}
			if length <= 0 {
				c.finishValue()
			} else {
				if err := c.charge(0, length); err != nil {
					return 0, err
				}
				c.stack = append(c.stack, length)
			}
		}
	default:
		return 0, fmt.Errorf("unsupported bounded Redis reply type")
	}
	c.pending = append(c.pending, line...)
	return c.Read(p)
}

// Initialized also rejects zero-value wrappers before any network call.
func (c *Client) Initialized() bool { return c != nil && c.Client != nil && c.budget != nil }

type Usage struct{ Bytes, Elements int64 }

func (c *Client) BudgetUsage() Usage {
	c.budget.mu.Lock()
	defer c.budget.mu.Unlock()
	return Usage{Bytes: c.budget.bytes, Elements: c.budget.elements}
}
