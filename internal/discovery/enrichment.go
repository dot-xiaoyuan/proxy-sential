package discovery

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"proxy-sentinel/internal/normalized"
)

// An explicit domain/VLAN/interface mapping is required in addition to a local
// neighbor match. Mirror visibility alone never authorizes access via local routes.
type EnrichmentPath struct {
	Domain    string `json:"domain"`
	VLAN      string `json:"vlan"`
	Interface string `json:"interface"`
}
type EnrichmentWorker struct {
	Repository Repository
	MasterKey  []byte
	Paths      []EnrichmentPath
	Verify     func(Observation, EnrichmentPath) bool
	Fetch      func(context.Context, string, string, []byte) ([]byte, error)
}

func enrichmentRequest(o Observation) (string, string, []byte) {
	p := o.Evidence.Payload
	switch o.Origin {
	case "snmp":
		return "snmp", o.IP, nil
	case "ssdp":
		return "upnp", str(p, "location"), nil
	case "dns_sd":
		if service := str(p, "service_type"); service == "_ipp._tcp" || service == "_ipps._tcp" {
			port := number(p, "service_port")
			if port <= 0 {
				port = 631
			}
			scheme := "http"
			if service == "_ipps._tcp" {
				scheme = "https"
			}
			path := "/ipp/print"
			for _, txt := range strings.Split(protocolText(p["txt"]), ";") {
				if strings.HasPrefix(txt, "rp=") {
					path = "/" + strings.TrimPrefix(txt, "rp=")
				}
			}
			location := scheme + "://" + net.JoinHostPort(o.IP, fmt.Sprint(port)) + path
			b := []byte{1, 1, 0, 11, 0, 0, 0, 1, 1}
			attr := func(tag byte, k, v string) {
				b = append(b, tag, byte(len(k)>>8), byte(len(k)))
				b = append(b, k...)
				b = append(b, byte(len(v)>>8), byte(len(v)))
				b = append(b, v...)
			}
			attr(0x47, "attributes-charset", "utf-8")
			attr(0x48, "attributes-natural-language", "en")
			attr(0x45, "printer-uri", "ipp://"+net.JoinHostPort(o.IP, fmt.Sprint(port))+path)
			attr(0x44, "requested-attributes", "printer-make-and-model")
			b = append(b, 3)
			return "ipp", location, b
		}
	case "ws_discovery":
		locations := strings.Fields(str(p, "xaddrs"))
		if len(locations) > 0 {
			return "onvif", locations[0], []byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>`)
		}
	}
	return "", "", nil
}
func queueEnrichment(ctx context.Context, tx *sql.Tx, key string, o Observation) error {
	protocol, location, _ := enrichmentRequest(o)
	if protocol == "" || location == "" || !o.Current(time.Now()) {
		return nil
	}
	raw, _ := json.Marshal(o)
	fingerprint := contentHash([]string{location, o.ModelName, serviceInstance(o)})
	_, e := tx.ExecContext(ctx, `INSERT INTO discovery_enrichment_work(device_key,protocol,fingerprint,observation) VALUES($1,$2,$3,$4) ON CONFLICT(device_key,protocol) DO UPDATE SET fingerprint=EXCLUDED.fingerprint,observation=EXCLUDED.observation,next_attempt_at=CASE WHEN discovery_enrichment_work.fingerprint<>EXCLUDED.fingerprint THEN greatest(now(),coalesce(discovery_enrichment_work.last_success+interval '1 hour',now())) ELSE discovery_enrichment_work.next_attempt_at END`, key, protocol, fingerprint, raw)
	return e
}
func fetchEnrichment(ctx context.Context, protocol, location string, body []byte) ([]byte, error) {
	method := "GET"
	if len(body) > 0 {
		method = "POST"
	}
	req, e := http.NewRequestWithContext(ctx, method, location, bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	if protocol == "ipp" {
		req.Header.Set("Content-Type", "application/ipp")
	}
	if protocol == "onvif" {
		req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := http.Client{Transport: tr, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("redirect forbidden") }}
	res, e := client.Do(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("enrichment HTTP status %d", res.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if e != nil {
		return nil, e
	}
	if len(b) > 1<<20 {
		return nil, fmt.Errorf("enrichment response budget")
	}
	return b, nil
}
func parseEnrichment(protocol string, raw []byte) (map[string]any, error) {
	switch protocol {
	case "ipp":
		return ParseIPPAttributes(raw)
	case "upnp":
		d, e := ParseDescription(raw)
		if e != nil {
			return nil, e
		}
		return map[string]any{"origin": "ssdp", "is_response": true, "ttl": 3600, "name": d.FriendlyName, "manufacturer": d.Manufacturer, "product_model": strings.TrimSpace(d.ModelName + " " + d.ModelNumber), "description": d}, nil
	case "onvif":
		if e := ValidateXML(raw); e != nil {
			return nil, e
		}
		d := xml.NewDecoder(bytes.NewReader(raw))
		fields := map[string]any{"origin": "onvif", "is_response": true, "ttl": 3600}
		field := ""
		response := false
		depth := 0
		for {
			t, e := d.Token()
			if e == io.EOF {
				break
			}
			if e != nil {
				return nil, e
			}
			switch v := t.(type) {
			case xml.StartElement:
				depth++
				if depth > 32 {
					return nil, fmt.Errorf("ONVIF XML depth")
				}
				if v.Name.Local == "GetDeviceInformationResponse" {
					response = true
				}
				field = v.Name.Local
			case xml.CharData:
				if len(v) > 512 {
					return nil, fmt.Errorf("ONVIF field budget")
				}
				switch field {
				case "Manufacturer":
					fields["manufacturer"] = cleanDescriptionText(string(v))
				case "Model":
					fields["product_model"] = cleanDescriptionText(string(v))
				case "SerialNumber":
					fields["serial_number"] = cleanDescriptionText(string(v))
				}
			case xml.EndElement:
				depth--
				field = ""
			}
		}
		if !response {
			return nil, fmt.Errorf("not an ONVIF device information response")
		}
		return fields, nil
	}
	return nil, fmt.Errorf("unsupported enrichment")
}

// Step claims with a durable lease and publishes through the same ingestion
// ledger. Crashes leave a retryable lease, never a falsely completed task.
func (w EnrichmentWorker) Step(ctx context.Context) (bool, error) {
	var key, protocol, fingerprint string
	var raw []byte
	lease := contentHash([]any{time.Now().UnixNano()})[:32]
	e := w.Repository.DB.QueryRowContext(ctx, `UPDATE discovery_enrichment_work SET lease_id=$1,lease_until=now()+interval '10 seconds' WHERE (device_key,protocol)=(SELECT device_key,protocol FROM discovery_enrichment_work WHERE next_attempt_at<=now() AND lease_until<=now() ORDER BY next_attempt_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING device_key,protocol,fingerprint,observation`, lease).Scan(&key, &protocol, &fingerprint, &raw)
	if e == sql.ErrNoRows {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	var o Observation
	if e = json.Unmarshal(raw, &o); e != nil {
		return true, e
	}
	blocked := ""
	verified := false
	for _, path := range w.Paths {
		if path.Domain != o.Domain || path.VLAN != o.VLAN {
			continue
		}
		if w.Verify != nil {
			verified = w.Verify(o, path)
		} else {
			verified = verifyEnrichmentPath(o, path)
		}
		if verified {
			break
		}
	}
	kind, location, body := enrichmentRequest(o)
	u, ue := url.Parse(location)
	if !verified {
		blocked = "scope_path_unverified"
	}
	if kind != "snmp" && (ue != nil || u.User != nil || u.Hostname() != o.IP || (u.Scheme != "http" && u.Scheme != "https") || !IsPrivateDiscoveryAddress(o.IP)) {
		blocked = "invalid_target"
	}
	var payload map[string]any
	if blocked == "" {
		fetch := w.Fetch
		if fetch == nil {
			fetch = fetchEnrichment
		}
		work, cancel := context.WithTimeout(ctx, 2*time.Second)
		var b []byte
		var err error
		if kind == "snmp" {
			payload, err = w.readSNMPProduct(work, o)
		} else {
			b, err = fetch(work, kind, location, body)
		}
		cancel()
		e = err
		if e == nil && kind != "snmp" {
			payload, e = parseEnrichment(kind, b)
		}
	} else {
		e = fmt.Errorf("%s", blocked)
	}
	if e == nil {
		event := o.Evidence
		event.Payload = payload
		event.Payload["service_instance"] = serviceInstance(o)
		event.SourceEventType = str(payload, "origin")
		event.EventID = "enriched-" + contentHash([]any{key, protocol, fingerprint, payload, time.Now().UTC().Truncate(time.Hour)})[:32]
		event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
		e = w.Repository.AcceptDiscoveryBatch(ctx, event.EventID, []normalized.Event{event})
	}
	if e != nil {
		_, dbErr := w.Repository.DB.ExecContext(ctx, `UPDATE discovery_enrichment_work SET error=$4,attempts=attempts+1,next_attempt_at=now()+least(interval '1 hour',interval '30 seconds'*power(2,least(attempts,7))),lease_until=now() WHERE device_key=$1 AND protocol=$2 AND lease_id=$3`, key, protocol, lease, e.Error())
		if dbErr != nil {
			return true, dbErr
		}
		return true, e
	}
	_, e = w.Repository.DB.ExecContext(ctx, `UPDATE discovery_enrichment_work SET error='',attempts=0,last_success=now(),next_attempt_at=greatest(now()+interval '1 hour',next_attempt_at),lease_until=now() WHERE device_key=$1 AND protocol=$2 AND lease_id=$3`, key, protocol, lease)
	return true, e
}
