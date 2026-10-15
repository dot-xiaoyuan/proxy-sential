//go:build linux

package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"proxy-sentinel/internal/normalized"
	"syscall"
	"time"
)

// Capture spools standard events on a separate goroutine; packet reads never wait on database work.
func Capture(ctx context.Context, iface, spool string, source Source, allow []netip.Prefix) error {
	return CaptureConfigured(ctx, iface, spool, source, allow, DefaultCollectionConfig())
}
func CaptureConfigured(ctx context.Context, iface, spool string, source Source, allow []netip.Prefix, config CollectionConfig) (result error) {
	if len(allow) == 0 {
		return fmt.Errorf("passive capture requires allowed CIDRs")
	}
	i, e := net.InterfaceByName(iface)
	if e != nil {
		return e
	}
	fd, e := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(3)))
	if e != nil {
		return e
	}
	defer syscall.Close(fd)
	if e = attachDiscoveryFilter(fd, config); e != nil {
		return e
	}
	if e = syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(3), Ifindex: i.Index}); e != nil {
		return e
	}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Usec: 100000})
	if e = os.MkdirAll(spool, 0700); e != nil {
		return e
	}
	queue := make(chan []byte, 256)
	done := make(chan error, 1)
	go func() {
		done <- drainSpoolQueue(queue, func(b []byte) error {
			h := sha256.Sum256(b)
			path := filepath.Join(spool, hex.EncodeToString(h[:16])+".json")
			if e := writeDurableSpool(path+".tmp", b); e != nil {
				return e
			}
			if e := os.Rename(path+".tmp", path); e != nil {
				return e
			}
			dir, e := os.Open(spool)
			if e != nil {
				return e
			}
			defer dir.Close()
			return dir.Sync()
		})
	}()
	defer func() {
		close(queue)
		if writerErr := <-done; writerErr != nil {
			result = writerErr
		}
	}()
	decoder := &FrameDecoder{}
	stats := NewCaptureStats()
	stats.Config = config
	pending := []normalized.Event{}
	positions := map[string]int{}
	lastFlush, lastStats := time.Now(), time.Now()
	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		b, e := json.Marshal(pending)
		if e != nil {
			return e
		}
		select {
		case queue <- b:
			pending = nil
			positions = map[string]int{}
			lastFlush = time.Now()
			return nil
		default:
			return fmt.Errorf("passive spool queue full; capture stopped to expose data loss")
		}
	}
	buffer := make([]byte, 65536)
	for ctx.Err() == nil {
		select {
		case err := <-done:
			done <- err
			return err
		default:
		}
		n, _, err := syscall.Recvfrom(fd, buffer, 0)
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
			if e = flush(); e != nil {
				return e
			}
			if time.Since(lastStats) >= time.Second {
				stats.FragmentDrops = decoder.FragmentDrops
				if e = stats.persist(spool); e != nil {
					return e
				}
				lastStats = time.Now()
			}
			continue
		}
		if err != nil {
			return err
		}

		decoded := decoder.Decode(buffer[:n], source, time.Now().UTC())
		stats.record(packetProtocol(buffer[:n]), len(decoded))
		events := filterCaptureEvents(decoded, allow)
		for _, event := range events {
			if !config.Enabled(event.SourceEventType) {
				continue
			}
			payload := map[string]any{}
			for k, v := range event.Payload {
				if k != "ttl" {
					payload[k] = v
				}
			}
			key := contentHash([]any{event.SourceEventType, event.Subject, payload})
			if at, ok := positions[key]; ok {
				pending[at] = event
				stats.Coalesced++
			} else {
				positions[key] = len(pending)
				pending = append(pending, event)
			}
			if len(pending) >= 250 {
				if e = flush(); e != nil {
					return e
				}
			}
		}
		if time.Since(lastFlush) >= 100*time.Millisecond {
			if e = flush(); e != nil {
				return e
			}
		}
		if time.Since(lastStats) >= time.Second {
			stats.FragmentDrops = decoder.FragmentDrops
			if e = stats.persist(spool); e != nil {
				return e
			}
			lastStats = time.Now()
		}

	}
	if e = flush(); e != nil {
		return e
	}
	return ctx.Err()
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	return binary.BigEndian.Uint16(b[:])
}
