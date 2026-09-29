// campus-load generates bounded protocol load against servers created in this
// process. It intentionally accepts no destination URL or external address.
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type report struct {
	Requests    int64   `json:"attempted"`
	Success     int64   `json:"successful"`
	Failed      int64   `json:"failed"`
	HTTP        int64   `json:"http_success"`
	TLS         int64   `json:"tls_success"`
	DNS         int64   `json:"dns_success"`
	Bytes       int64   `json:"response_bytes"`
	Seconds     float64 `json:"seconds"`
	Rate        float64 `json:"requests_per_second"`
	P95MS       int64   `json:"latency_p95_upper_bound_ms"`
	PeakHeap    uint64  `json:"peak_go_heap_bytes"`
	Concurrency int     `json:"concurrency"`
	Scope       string  `json:"scope"`
}

func main() {
	n := flag.Int("requests", 10000, "bounded total requests")
	workers := flag.Int("concurrency", 16, "parallel workers, maximum 256")
	rate := flag.Int("rate", 1000, "global requests/second, maximum 10000")
	flag.Parse()
	if *n < 1 || *n > 1000000 || *workers < 1 || *workers > 256 || *rate < 1 || *rate > 10000 {
		fmt.Fprintln(os.Stderr, "invalid bounded load parameters")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	r, err := run(ctx, *n, *workers, *rate)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(r)
	if r.Failed > 0 || r.Requests != int64(*n) {
		os.Exit(1)
	}
}
func run(ctx context.Context, n, workers, rate int) (report, error) {
	r := report{Concurrency: workers, Scope: "isolated loopback DNS/HTTP/TLS transport load; no NAT, packet parser, Sentinel ingest or real-campus accuracy claim"}
	handler := http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		io.WriteString(w, "campus-lab-response\n")
	})
	hs := httptest.NewServer(handler)
	defer hs.Close()
	ts := httptest.NewTLSServer(handler)
	defer ts.Close()
	// Trust only the ephemeral laboratory certificate.
	client := ts.Client()
	tr := client.Transport.(*http.Transport)
	tr.MaxIdleConns = workers * 2
	tr.MaxIdleConnsPerHost = workers
	tr.TLSClientConfig.MinVersion = tls.VersionTLS12
	client.Timeout = 5 * time.Second
	defer tr.CloseIdleConnections()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return r, err
	}
	defer udp.Close()
	dnsDone := make(chan struct{})
	go func() {
		defer close(dnsDone)
		b := make([]byte, 512)
		for {
			sz, addr, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			if sz < 12 {
				continue
			}
			response := append([]byte{}, b[:sz]...)
			response[2] = 0x81
			response[3] = 0x80
			binary.BigEndian.PutUint16(response[6:8], 1)
			response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1)
			udp.WriteTo(response, addr)
		}
	}()
	var success, failed, bytes atomic.Int64
	var counts [3]atomic.Int64
	var buckets [17]atomic.Int64
	var peak atomic.Uint64
	sample := func() {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		for old := peak.Load(); m.HeapAlloc > old; old = peak.Load() {
			if peak.CompareAndSwap(old, m.HeapAlloc) {
				break
			}
		}
	}
	sampleDone := make(chan struct{})
	sampleExit := make(chan struct{})
	go func() {
		defer close(sampleExit)
		t := time.NewTicker(50 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				sample()
			case <-sampleDone:
				sample()
				return
			}
		}
	}()
	jobs := make(chan int)
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				began := time.Now()
				var e error
				var size int64
				kind := i % 3
				if kind == 0 {
					var conn net.Conn
					conn, e = net.DialTimeout("udp", udp.LocalAddr().String(), time.Second)
					if e == nil {
						conn.SetDeadline(time.Now().Add(3 * time.Second))
						id := uint16(i)
						q := []byte{byte(id >> 8), byte(id), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 6, 'c', 'a', 'm', 'p', 'u', 's', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
						_, e = conn.Write(q)
						if e == nil {
							b := make([]byte, 512)
							var sz int
							sz, e = conn.Read(b)
							size = int64(sz)
							if e == nil && (sz < 12 || binary.BigEndian.Uint16(b[:2]) != id || b[3]&15 != 0 || binary.BigEndian.Uint16(b[6:8]) != 1) {
								e = fmt.Errorf("invalid DNS response")
							}
						}
						conn.Close()
					}
				} else {
					url := hs.URL
					if kind == 2 {
						url = ts.URL
					}
					req, _ := http.NewRequestWithContext(ctx, "GET", url+"/campus/test", nil)
					req.Header.Set("User-Agent", []string{"CampusLab/Desktop", "CampusLab/Mobile", "CampusLab/Office"}[i%3])
					var resp *http.Response
					resp, e = client.Do(req)
					if e == nil {
						size, e = io.Copy(io.Discard, resp.Body)
						resp.Body.Close()
						if resp.StatusCode != 200 {
							e = fmt.Errorf("HTTP status %d", resp.StatusCode)
						}
					}
				}
				ms := time.Since(began).Milliseconds()
				bucket := 0
				for bucket < 16 && ms > int64(1<<bucket) {
					bucket++
				}
				buckets[bucket].Add(1)
				if e != nil {
					failed.Add(1)
				} else {
					success.Add(1)
					counts[kind].Add(1)
					bytes.Add(size)
				}
			}
		}()
	}
	ticker := time.NewTicker(time.Second / time.Duration(rate))
	for i := 0; i < n; i++ {
		select {
		case <-ctx.Done():
			goto finish
		case <-ticker.C:
		}
		select {
		case jobs <- i:
		case <-ctx.Done():
			goto finish
		}
	}
finish:
	ticker.Stop()
	close(jobs)
	wg.Wait()
	close(sampleDone)
	<-sampleExit
	udp.Close()
	<-dnsDone
	r.Success = success.Load()
	r.Failed = failed.Load()
	r.Requests = r.Success + r.Failed
	r.DNS = counts[0].Load()
	r.HTTP = counts[1].Load()
	r.TLS = counts[2].Load()
	r.Bytes = bytes.Load()
	r.Seconds = time.Since(start).Seconds()
	r.Rate = float64(r.Requests) / r.Seconds
	r.PeakHeap = peak.Load()
	target := (r.Requests*95 + 99) / 100
	var acc int64
	for i := range buckets {
		acc += buckets[i].Load()
		if acc >= target {
			r.P95MS = int64(1 << i)
			break
		}
	}
	return r, nil
}
