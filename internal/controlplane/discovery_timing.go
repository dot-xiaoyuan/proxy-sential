package controlplane

import (
	"log"
	"net/http"
	"time"
)

// Record latencies of real authenticated reads without recording the search
// string, user, address, cursor or response. Enabled during field acceptance.
type discoveryTimingWriter struct {
	http.ResponseWriter
	status int
}

func (w *discoveryTimingWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *discoveryTimingWriter) finish(start time.Time, path string, window time.Duration) {
	code := w.status
	if code == 0 {
		code = http.StatusOK
	}
	log.Printf("discovery_http route=%s window_hours=%.2f status=%d elapsed_ms=%d", path, window.Hours(), code, time.Since(start).Milliseconds())
}
