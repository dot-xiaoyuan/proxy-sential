//go:build linux

package devicesignal

import (
	"log"
	"maps"
	"syscall"
	"time"
)

// These descriptors never feed packet/control summaries or the main capture
// coverage counters. A failed refresh can only disable fingerprint recovery.
type continuationCapture struct {
	fds       []int
	keys      map[handshakeKey]struct{}
	readError bool
}

func (c *continuationCapture) close() {
	for _, fd := range c.fds {
		_ = syscall.Close(fd)
	}
	c.fds = nil
	c.keys = nil
}

func (c *continuationCapture) refresh(ifindex int, keys map[handshakeKey]struct{}) {
	if !c.readError && maps.Equal(c.keys, keys) {
		return
	}
	c.readError = false
	next, err := openHandshakeContinuationSockets(ifindex, keys)
	c.close() // discard queued copies filtered under the previous list
	if err != nil {
		log.Printf("handshake continuation filter unavailable for %d outlets: %v", len(keys), err)
		return
	}
	c.fds, c.keys = next, keys
}

func (c *continuationCapture) drain(b *captureBucket, buf, control []byte) int {
	if len(c.fds) == 0 || c.readError {
		return 0
	}
	n := 0
	for _, fd := range c.fds {
		for i := 0; i < 256/len(c.fds); i++ {
			frame, err := receiveTaggedHandshake(fd, buf, control)
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				break
			}
			if err != nil {
				c.readError = true
				log.Printf("handshake continuation capture interrupted: %v", err)
				return n
			}
			b.helloReassembly.consume(frame, c.keys, time.Now())
			n++
		}
	}
	return n
}

func (c *continuationCapture) coverage(stats *helloReassemblyStats, total int) {
	stats.FilteredOutlets = len(c.keys)
	stats.UnfilteredOutlets = total - len(c.keys)
	stats.KernelStatsKnown = len(c.fds) > 0 && !c.readError
	for _, fd := range c.fds {
		received, dropped, known := packetCaptureStats(fd)
		stats.KernelStatsKnown = stats.KernelStatsKnown && known
		stats.Received += uint64(received)
		stats.Dropped += uint64(dropped)
	}
	if c.readError {
		stats.UnfilteredOutlets = total
		stats.FilteredOutlets = 0
	}
}
