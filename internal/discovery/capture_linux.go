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
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Capture spools standard events on a separate goroutine; packet reads never wait on database work.
func Capture(ctx context.Context, iface, spool string, source Source) error {
	i, e := net.InterfaceByName(iface)
	if e != nil {
		return e
	}
	fd, e := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(3)))
	if e != nil {
		return e
	}
	defer syscall.Close(fd)
	if e = syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(3), Ifindex: i.Index}); e != nil {
		return e
	}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 1})
	if e = os.MkdirAll(spool, 0700); e != nil {
		return e
	}
	queue := make(chan []byte, 256)
	done := make(chan error, 1)
	go func() {
		for b := range queue {
			h := sha256.Sum256(b)
			path := filepath.Join(spool, hex.EncodeToString(h[:16])+".json")
			if e := os.WriteFile(path+".tmp", b, 0600); e != nil {
				done <- e
				return
			}
			if e := os.Rename(path+".tmp", path); e != nil {
				done <- e
				return
			}
		}
		done <- nil
	}()
	defer close(queue)
	cache := &DNSCache{}
	buffer := make([]byte, 65536)
	for ctx.Err() == nil {
		select {
		case err := <-done:
			return err
		default:
		}
		n, _, err := syscall.Recvfrom(fd, buffer, 0)
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		events := decodeFrame(buffer[:n], source, time.Now().UTC(), cache)
		if len(events) == 0 {
			continue
		}
		b, _ := json.Marshal(events)
		select {
		case queue <- b:
		default:
			return fmt.Errorf("passive spool queue full; capture stopped to expose data loss")
		}
	}
	return ctx.Err()
}
func htons(v uint16) uint16 {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	return binary.BigEndian.Uint16(b[:])
}
