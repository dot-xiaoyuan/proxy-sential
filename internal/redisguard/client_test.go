package redisguard

import (
	"bytes"
	"context"

	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type replyFixtureConn struct {
	*bytes.Reader
	fragment int
}

func (c *replyFixtureConn) Read(p []byte) (int, error) {
	if c.fragment > 0 && len(p) > c.fragment {
		p = p[:c.fragment]
	}
	return c.Reader.Read(p)
}
func (*replyFixtureConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*replyFixtureConn) Close() error                     { return nil }
func (*replyFixtureConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*replyFixtureConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*replyFixtureConn) SetDeadline(time.Time) error      { return nil }
func (*replyFixtureConn) SetReadDeadline(time.Time) error  { return nil }
func (*replyFixtureConn) SetWriteDeadline(time.Time) error { return nil }

func TestCatalogReplyGuardPreservesFragmentedRESP2(t *testing.T) {
	input := "+OK\r\n-ERR fixture\r\n:123\r\n*-1\r\n$-1\r\n*0\r\n*3\r\n*2\r\n$0\r\n\r\n$3\r\nA\nB\r\n:7\r\n*1\r\n+END\r\n"
	for _, fragment := range []int{1, 2, 3, 16, 4096} {
		c := newReplyConn(&replyFixtureConn{Reader: bytes.NewReader([]byte(input)), fragment: fragment}, &readBudget{limits: testLimits})
		output, err := io.ReadAll(c)
		if err != nil || string(output) != input || len(c.stack) != 0 || c.body || c.frameBytes != 0 {
			t.Fatalf("RESP2 framing changed with fragment=%d: %v", fragment, err)
		}
	}
}

func TestCatalogReplyGuardRejectsAllocationHeadersBeforeForwarding(t *testing.T) {
	for _, input := range []string{"$1073741824\r\n", "*2147483647\r\n", strings.Repeat("*1\r\n", 9), "+" + strings.Repeat("x", 4096)} {
		c := newReplyConn(&replyFixtureConn{Reader: bytes.NewReader([]byte(input))}, &readBudget{limits: testLimits})
		out, err := io.ReadAll(c)
		if !errors.Is(err, testLimitError) {
			t.Fatalf("oversized allocation header accepted: %v", err)
		}
		if strings.Contains(string(out), "1073741824") || strings.Contains(string(out), "2147483647") {
			t.Fatal("driver received unsafe allocation length")
		}
	}
}

func TestCatalogReplyGuardBudgetsWholeFrameAndWholeRead(t *testing.T) {
	c := newReplyConn(&replyFixtureConn{Reader: bytes.NewReader([]byte("$100\r\n"))}, &readBudget{limits: testLimits})
	c.frameBytes = testLimits.ReplyBytes - 100
	if _, err := io.ReadAll(c); !errors.Is(err, testLimitError) {
		t.Fatal("frame bound not enforced before payload", err)
	}
	budget := &readBudget{limits: testLimits, active: true, bytes: testLimits.ReadBytes - 10}
	for i := 0; i < 3; i++ {
		c := newReplyConn(&replyFixtureConn{Reader: bytes.NewReader([]byte("+OK\r\n"))}, budget)
		_, err := io.ReadAll(c)
		if (i < 2 && err != nil) || (i == 2 && !errors.Is(err, testLimitError)) {
			t.Fatal("connection change reset whole-read byte budget", i, err)
		}
	}
	budget = &readBudget{limits: testLimits, active: true, elements: testLimits.ReadElements}
	c = newReplyConn(&replyFixtureConn{Reader: bytes.NewReader([]byte("*1\r\n"))}, budget)
	if _, err := io.ReadAll(c); !errors.Is(err, testLimitError) {
		t.Fatal("element budget ignored", err)
	}
}

func TestCatalogReplyGuardRejectsInvalidFraming(t *testing.T) {
	for _, input := range []string{"$-2\r\n", "*bad\r\n", "%1\r\n", "+bad\n", "$1\r\nxNO"} {
		c := newReplyConn(&replyFixtureConn{Reader: bytes.NewReader([]byte(input))}, &readBudget{limits: testLimits})
		if _, err := io.ReadAll(c); err == nil {
			t.Fatal("invalid RESP framing accepted")
		}
	}
}

func TestCatalogReadGateCancellationDoesNotResetPeerBudget(t *testing.T) {
	c := NewClient(nil, testLimits)
	defer c.Close()
	end, err := c.BeginRead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer end()
	if err := c.budget.reserve(123, 4); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.BeginRead(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if c.budget.bytes != 123 || c.budget.elements != 4 {
		t.Fatal("cancelled peer reset active budget")
	}
}

var testLimitError = errors.New("fixture resource limit")
var testLimits = Limits{ReadBytes: 64 << 20, ReplyBytes: 32 << 20, BulkBytes: 1 << 20, ReadElements: 1000000, ReplyElements: 1000000, ArrayLength: 100001, Depth: 8, Error: testLimitError}
