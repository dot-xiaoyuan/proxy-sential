// Package routerprober actively probes router management HTTP interfaces.
//
// For each router assessment at candidate/likely/confirmed status with a known IP, the
// prober tries the common management ports (80, 8080, 443, 8443). A successful response
// is parsed for the Server header and HTML page title, then emitted as a standard
// source_event_type="http" normalized event. Those events flow into router_signal_events_v1
// through the existing materialized view and feed the open-source catalog matchers
// (Recog http_server, WhatWeb, etc.) that could not fire on client-side handshake data.
package routerprober

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"proxy-sentinel/internal/normalized"
)

const (
	probeInterval   = 10 * time.Minute
	probeTimeout    = 8 * time.Second
	probeMaxBody    = 32 * 1024
	probeConcurrent = 8
)

var (
	managementPorts = []struct {
		port int
		tls  bool
	}{
		{80, false},
		{8080, false},
		{443, true},
		{8443, true},
	}

	titleRE = regexp.MustCompile(`(?i)<title[^>]*>([^<]{1,200})</title>`)
)

// Config holds everything the prober needs.
type Config struct {
	PostgresDSN string
	SensorID    string
	OutputPath  string
}

// Run probes router IPs until ctx is cancelled.
func Run(ctx context.Context, cfg Config) error {
	db, err := sql.Open("pgx", cfg.PostgresDSN)
	if err != nil {
		return fmt.Errorf("router prober: open db: %w", err)
	}
	defer db.Close()

	out, err := os.OpenFile(cfg.OutputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("router prober: open output: %w", err)
	}
	defer out.Close()

	enc := json.NewEncoder(out)

	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()

	// probe once at startup, then on each tick
	runRound(ctx, db, cfg.SensorID, enc)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			runRound(ctx, db, cfg.SensorID, enc)
		}
	}
}

type routerTarget struct {
	assessmentID string
	ip           string
	mac          string
	endpointID   string
}

func runRound(ctx context.Context, db *sql.DB, sensorID string, enc *json.Encoder) {
	targets, err := fetchTargets(ctx, db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "router prober: fetch targets: %v\n", err)
		return
	}
	if len(targets) == 0 {
		return
	}

	sem := make(chan struct{}, probeConcurrent)
	for _, t := range targets {
		select {
		case <-ctx.Done():
			return
		case sem <- struct{}{}:
		}
		target := t
		go func() {
			defer func() { <-sem }()
			probeTarget(ctx, target, sensorID, enc)
		}()
	}
	// drain semaphore
	for i := 0; i < probeConcurrent; i++ {
		sem <- struct{}{}
	}
}

func fetchTargets(ctx context.Context, db *sql.DB) ([]routerTarget, error) {
	// Select distinct IPs from likely/confirmed assessments that have a non-private or
	// RFC-1918 IP (management interfaces can be on either). Limit per round so a large
	// candidate pool doesn't dominate a single probe cycle.
	rows, err := db.QueryContext(ctx, `
SELECT DISTINCT ON (ip)
  assessment_id, ip::text, coalesce(mac,''), coalesce(endpoint_id,'')
FROM router_assessments
WHERE status IN ('likely','confirmed')
  AND ip IS NOT NULL
  AND expires_at > now()
ORDER BY ip, last_seen DESC
LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []routerTarget
	for rows.Next() {
		var t routerTarget
		if err := rows.Scan(&t.assessmentID, &t.ip, &t.mac, &t.endpointID); err != nil {
			return nil, err
		}
		// strip CIDR suffix if present (ip column is inet)
		if idx := strings.IndexByte(t.ip, '/'); idx >= 0 {
			t.ip = t.ip[:idx]
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

type probeResult struct {
	port       int
	scheme     string
	statusCode int
	server     string
	title      string
	location   string
}

func probeTarget(ctx context.Context, t routerTarget, sensorID string, enc *json.Encoder) {
	var results []probeResult
	for _, p := range managementPorts {
		r := tryPort(ctx, t.ip, p.port, p.tls)
		if r != nil {
			results = append(results, *r)
		}
	}
	if len(results) == 0 {
		return
	}

	// Aggregate: collect all unique server strings and titles across ports.
	servers := map[string]bool{}
	titles := map[string]bool{}
	locations := map[string]bool{}
	for _, r := range results {
		if r.server != "" {
			servers[r.server] = true
		}
		if r.title != "" {
			titles[r.title] = true
		}
		if r.location != "" {
			locations[r.location] = true
		}
	}

	event := buildEvent(t, sensorID, servers, titles, locations)
	if err := enc.Encode(event); err != nil {
		fmt.Fprintf(os.Stderr, "router prober: encode event for %s: %v\n", t.ip, err)
	}
}

func tryPort(ctx context.Context, ip string, port int, isTLS bool) *probeResult {
	scheme := "http"
	if isTLS {
		scheme = "https"
	}
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	url := fmt.Sprintf("%s://%s/", scheme, addr)

	dialCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: probeTimeout / 2,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // management certs are self-signed
			MinVersion:         tls.VersionTLS10,
		},
		ResponseHeaderTimeout: probeTimeout,
		DisableKeepAlives:     true,
	}
	client := &http.Client{
		Transport: transport,
		// Don't follow redirects automatically; capture the Location header.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: probeTimeout,
	}

	req, err := http.NewRequestWithContext(dialCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; proxy-sentinel-router-prober/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, probeMaxBody))

	r := &probeResult{
		port:       port,
		scheme:     scheme,
		statusCode: resp.StatusCode,
		server:     strings.TrimSpace(resp.Header.Get("Server")),
		location:   strings.TrimSpace(resp.Header.Get("Location")),
	}

	if m := titleRE.FindSubmatch(body); m != nil {
		r.title = strings.TrimSpace(string(bytes.ReplaceAll(m[1], []byte("\n"), []byte(" "))))
	}
	return r
}

func buildEvent(t routerTarget, sensorID string, servers, titles, locations map[string]bool) normalized.Event {
	// stable event ID: hash of assessment_id + sorted server strings
	h := sha256.New()
	h.Write([]byte(t.assessmentID))
	serverList := sortedKeys(servers)
	for _, s := range serverList {
		h.Write([]byte(s))
	}
	eventID := "rprobe-" + hex.EncodeToString(h.Sum(nil)[:16])

	payload := map[string]any{
		"origin":        "router-prober",
		"assessment_id": t.assessmentID,
	}
	if len(serverList) > 0 {
		payload["server"] = strings.Join(serverList, " ")
	}
	titleList := sortedKeys(titles)
	if len(titleList) > 0 {
		payload["title"] = strings.Join(titleList, " | ")
	}
	locationList := sortedKeys(locations)
	if len(locationList) > 0 {
		payload["location"] = strings.Join(locationList, " ")
	}

	subject := map[string]any{"ip": t.ip}
	if t.mac != "" {
		subject["mac"] = t.mac
	}

	return normalized.Event{
		SchemaVersion:   "v1",
		EventID:         eventID,
		Source:          "router-prober",
		SourceEventType: "http",
		Type:            "device",
		Timestamp:       time.Now().UTC().Format(time.RFC3339Nano),
		Observer:        map[string]any{"sensor_id": sensorID},
		Subject:         subject,
		Payload:         payload,
		Confidence:      0.9,
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
