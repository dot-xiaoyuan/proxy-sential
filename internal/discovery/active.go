package discovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"proxy-sentinel/internal/normalized"
	"strings"
	"sync"
	"time"
)

func ValidateXML(b []byte) error {
	if len(b) > 1<<20 {
		return errors.New("response too large")
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	for {
		t, e := d.Token()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		if _, ok := t.(xml.Directive); ok {
			return errors.New("XML directives forbidden")
		}
	}
}
func ReadDescription(ctx context.Context, address, target string) ([]byte, error) {
	u, e := url.Parse(address)
	if e != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() != target {
		return nil, errors.New("description must stay on literal target address")
	}
	req, e := http.NewRequestWithContext(ctx, "GET", address, nil)
	if e != nil {
		return nil, e
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect forbidden") }}
	res, e := client.Do(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, errors.New("description response unsuccessful")
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if e != nil {
		return nil, e
	}
	if e = ValidateXML(b); e != nil {
		return nil, e
	}
	return b, nil
}
func (c ScanConfig) Validate() error {
	if c.IntervalSeconds != 0 && c.IntervalSeconds < 3600 {
		return errors.New("scan interval minimum is one hour")
	}
	if len(c.Protocols) == 0 {
		return errors.New("at least one probe required")
	}
	for _, p := range c.Protocols {
		switch p {
		case "icmp", "arp", "ndp":
		case "ipp", "ipps", "ssdp", "onvif":
			if c.Sensitive {
				return errors.New("application probes disabled for sensitive networks")
			}
		default:
			return fmt.Errorf("unsupported protocol %q", p)
		}
		if (p == "arp" || p == "ndp") && c.Interface == "" {
			return errors.New("local link probes require interface")
		}
	}
	_, e := c.Targets(nil)
	return e
}

type ScanProfile struct {
	Targets      []string   `json:"targets,omitempty"`
	ID           string     `json:"id"`
	Node         string     `json:"node"`
	Site         string     `json:"site"`
	Domain       string     `json:"domain"`
	Config       ScanConfig `json:"config"`
	Version      int        `json:"version"`
	Enabled      bool       `json:"enabled"`
	TrialVersion int        `json:"trial_version"`
}

func Scan(ctx context.Context, p ScanProfile, id string, targets []string) (Snapshot, error) {
	if err := p.Config.Validate(); err != nil {
		return Snapshot{}, err
	}
	for _, protocol := range p.Config.Protocols {
		command := ""
		switch protocol {
		case "icmp":
			command = "ping"
		case "arp":
			command = "arping"
		case "ndp":
			command = "ndisc6"
		}
		if command != "" {
			if _, err := exec.LookPath(command); err != nil {
				return Snapshot{}, fmt.Errorf("probe dependency %s unavailable", command)
			}
		}
	}
	out := Snapshot{ID: id, SourceID: p.ID, ConfigVersion: p.Version, At: time.Now().UTC(), Tables: []TableStatus{}, Events: []normalized.Event{}}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	jobs := make(chan string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				for _, protocol := range p.Config.Protocols {
					var response []byte
					var err error
					for attempt := 0; attempt < 2; attempt++ {
						select {
						case <-ctx.Done():
							return
						case <-tick.C:
						}
						probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
						response, err = probe(probeCtx, target, protocol, p.Config.Interface)
						cancel()
						if err == nil {
							break
						}
					}
					mu.Lock()
					st := TableStatus{Name: target + " / " + protocol, Complete: err == nil}
					if err != nil {
						st.Error = "无有效响应或探测失败"
					} else {
						st.Count = 1
						at := time.Now().UTC()
						h := sha256.Sum256([]byte(id + ":" + target + ":" + protocol))
						e := normalized.Event{SchemaVersion: "v1", EventID: "probe-" + hex.EncodeToString(h[:16]), Type: "discovery", Confidence: 0.5, Flow: map[string]any{"src_ip": "", "dst_ip": "", "proto": "other", "direction": "unknown"}, Source: "active", Timestamp: at.Format(time.RFC3339Nano), Observer: map[string]any{"source_id": p.ID, "sensor_id": p.Node, "snapshot_id": id, "config_version": p.Version}, Subject: map[string]any{"site": p.Site, "domain": p.Domain, "ip": target}, Payload: map[string]any{"origin": "active", "protocol": protocol, "ttl": 300, "response_bytes": len(response)}}
						out.Events = append(out.Events, e)
					}
					out.Tables = append(out.Tables, st)
					mu.Unlock()
				}
			}
		}()
	}
send:
	for _, t := range targets {
		select {
		case <-ctx.Done():
			break send
		case jobs <- t:
		}
	}
	close(jobs)
	wg.Wait()
	return out, ctx.Err()
}
func localTarget(target, iface string) bool {
	i, e := net.InterfaceByName(iface)
	if e != nil {
		return false
	}
	addresses, e := i.Addrs()
	if e != nil {
		return false
	}
	ip := net.ParseIP(target)
	for _, a := range addresses {
		_, subnet, e := net.ParseCIDR(a.String())
		if e == nil && subnet.Contains(ip) {
			return true
		}
	}
	return false
}
func probe(ctx context.Context, target, protocol, iface string) ([]byte, error) {
	switch protocol {
	case "icmp", "arp", "ndp":
		if protocol != "icmp" && !localTarget(target, iface) {
			return nil, errors.New("target is not on configured link")
		}
		command := "ping"
		args := []string{"-n", "-c", "1", "-W", "2"}
		if strings.Contains(target, ":") {
			args = append(args, "-6")
		}
		if iface != "" {
			args = append(args, "-I", iface)
		}
		if protocol == "arp" {
			if strings.Contains(target, ":") {
				return nil, errors.New("ARP requires IPv4")
			}
			command = "arping"
			args = []string{"-c", "1", "-w", "2", "-I", iface}
		}
		if protocol == "ndp" {
			if !strings.Contains(target, ":") {
				return nil, errors.New("NDP requires IPv6")
			}
			command = "ndisc6"
			args = []string{"-q", "-r", "1", "-w", "2000", target, iface}
		} else {
			args = append(args, target)
		}
		return exec.CommandContext(ctx, command, args...).Output()
	case "ssdp", "onvif":
		port := "1900"
		body := "M-SEARCH * HTTP/1.1\r\nHOST: " + net.JoinHostPort(target, port) + "\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
		if protocol == "onvif" {
			port = "3702"
			body = `<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:n="http://www.onvif.org/ver10/network/wsdl"><s:Header><a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action><a:MessageID>urn:uuid:00000000-0000-4000-8000-000000000001</a:MessageID><a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To></s:Header><s:Body><d:Probe><d:Types>n:NetworkVideoTransmitter</d:Types></d:Probe></s:Body></s:Envelope>`
		}
		host := target
		if strings.HasPrefix(target, "fe80:") {
			host += "%" + iface
		}
		c, e := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(host, port))
		if e != nil {
			return nil, e
		}
		defer c.Close()
		deadline, _ := ctx.Deadline()
		_ = c.SetDeadline(deadline)
		if _, e = c.Write([]byte(body)); e != nil {
			return nil, e
		}
		b := make([]byte, 65536)
		n, e := c.Read(b)
		if e != nil {
			return nil, e
		}
		b = b[:n]
		if protocol == "onvif" {
			if e = ValidateXML(b); e != nil {
				return nil, e
			}
			if !bytes.Contains(b, []byte("ProbeMatch")) {
				return nil, errors.New("not an ONVIF discovery response")
			}
		} else if !bytes.HasPrefix(b, []byte("HTTP/1.1 200")) {
			return nil, errors.New("not an SSDP response")
		}
		return b, nil
	case "ipp", "ipps":
		scheme := "http"
		if protocol == "ipps" {
			scheme = "https"
		}
		uri := scheme + "://" + net.JoinHostPort(target, "631") + "/ipp/print"
		printerURI := "ipp://" + net.JoinHostPort(target, "631") + "/ipp/print"
		// IPP Get-Printer-Attributes, never Print-Job.
		b := []byte{1, 1, 0, 11, 0, 0, 0, 1, 1}
		attribute := func(tag byte, k, v string) {
			b = append(b, tag, byte(len(k)>>8), byte(len(k)))
			b = append(b, k...)
			b = append(b, byte(len(v)>>8), byte(len(v)))
			b = append(b, v...)
		}
		attribute(0x47, "attributes-charset", "utf-8")
		attribute(0x48, "attributes-natural-language", "en")
		attribute(0x45, "printer-uri", printerURI)
		attribute(0x44, "requested-attributes", "printer-make-and-model")
		b = append(b, 3)
		req, e := http.NewRequestWithContext(ctx, "POST", uri, bytes.NewReader(b))
		if e != nil {
			return nil, e
		}
		req.Header.Set("Content-Type", "application/ipp")
		tr := &http.Transport{Proxy: nil, DisableKeepAlives: true}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect forbidden") }}
		res, e := client.Do(req)
		if e != nil {
			return nil, e
		}
		defer res.Body.Close()
		raw, e := io.ReadAll(io.LimitReader(res.Body, 65537))
		if e != nil {
			return nil, e
		}
		if len(raw) > 65536 || len(raw) < 8 || res.StatusCode != 200 || raw[2] != 0 {
			return nil, errors.New("invalid IPP response")
		}
		return raw, nil
	}
	return nil, errors.New("unsupported probe")
}
