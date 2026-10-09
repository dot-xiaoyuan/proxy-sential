// Package proxyprotocol consumes normalized transactions, never packet parser fields.
package proxyprotocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/policy"
	"sort"
	"strconv"
	"strings"
	"time"
)

const RuleVersion = "proxy-transactions/v2"

type Producer struct {
	SensorID      string    `json:"sensor_id"`
	Source        string    `json:"source"`
	InstanceID    string    `json:"instance_id"`
	ParserID      string    `json:"parser_id"`
	ParserVersion string    `json:"parser_version"`
	CampusID      string    `json:"campus_id"`
	AccessDomain  string    `json:"access_domain"`
	Key           string    `json:"key"`
	ValidFrom     time.Time `json:"valid_from,omitempty"`
	ValidUntil    time.Time `json:"valid_until,omitempty"`
}
type Config struct {
	Version   string     `json:"version"`
	Producers []Producer `json:"producers"`
}

func Load(path string) (Config, error) {
	if path == "" {
		return Config{}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	err = json.Unmarshal(raw, &c)
	if err != nil {
		return c, err
	}
	if c.Version == "" {
		return c, fmt.Errorf("proxy config version required")
	}
	seen := map[string]bool{}
	for _, p := range c.Producers {
		if (!p.ValidUntil.IsZero() && p.ValidFrom.IsZero()) || (!p.ValidUntil.IsZero() && !p.ValidUntil.After(p.ValidFrom)) {
			return c, fmt.Errorf("invalid proxy producer validity interval")
		}
		if p.SensorID == "" || p.Source == "" || p.InstanceID == "" || p.ParserID == "" || p.ParserVersion == "" || p.CampusID == "" || p.AccessDomain == "" || len(p.Key) < 32 {
			return c, fmt.Errorf("incomplete proxy producer registration")
		}
		expected := map[string]string{"suricata": "sentinel-suricata-http", "zeek": "sentinel-zeek-proxy"}[p.Source]
		if expected == "" || p.ParserID != expected || p.ParserVersion != "1" {
			return c, fmt.Errorf("unsupported proxy parser or version")
		}
		key := policy.StableID(p.SensorID, p.Source, p.InstanceID)
		if seen[key] {
			return c, fmt.Errorf("duplicate producer")
		}
		seen[key] = true
	}
	return c, nil
}
func (c Config) Producer(sensor, source, instance string) *Producer {
	for _, p := range c.Producers {
		if p.SensorID == sensor && p.Source == source && p.InstanceID == instance {
			return &p
		}
	}
	return nil
}
func Text(m map[string]any, k string) string {
	v := m[k]
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
func number(m map[string]any, k string) (int, bool) {
	v, err := strconv.Atoi(Text(m, k))
	return v, err == nil
}
func canonical(e normalized.Event) ([]byte, error) {
	// Sign normalized JSON rather than Go number representations; keep only stored fields.
	observer := map[string]any{}
	for k, v := range e.Observer {
		if k != "proxy_signature" {
			observer[k] = v
		}
	}
	value := map[string]any{"event_id": e.EventID, "timestamp": canonicalTime(e.Timestamp), "source": e.Source, "type": e.Type, "ip": Text(e.Subject, "ip"), "observer": observer, "flow": e.Flow, "payload": e.Payload, "raw_ref": e.RawRef}
	return json.Marshal(value)
}
func Sign(e *normalized.Event, p Producer) error {
	if e == nil {
		return fmt.Errorf("proxy event is required")
	}
	if e.Observer == nil {
		e.Observer = map[string]any{}
	}
	// A failed re-sign must not leave the previous authorization attached.
	delete(e.Observer, "proxy_signature")
	e.Observer["parser_id"] = p.ParserID
	e.Observer["parser_version"] = p.ParserVersion
	raw, err := canonical(*e)
	if err != nil {
		return fmt.Errorf("canonicalize proxy event: %w", err)
	}
	mac := hmac.New(sha256.New, []byte(p.Key))
	mac.Write(raw)
	e.Observer["proxy_signature"] = hex.EncodeToString(mac.Sum(nil))
	return nil
}

type Result struct {
	ID            string             `json:"evidence_id"`
	EventIDs      []string           `json:"event_ids"`
	SensorID      string             `json:"sensor_id"`
	Source        string             `json:"source"`
	InstanceID    string             `json:"instance_id"`
	ParserID      string             `json:"parser_id"`
	ParserVersion string             `json:"parser_version"`
	ConfigVersion string             `json:"config_version"`
	RuleVersion   string             `json:"rule_version"`
	IP            string             `json:"ip"`
	CampusID      string             `json:"campus_id"`
	AccessDomain  string             `json:"access_domain"`
	ConnectionID  string             `json:"connection_id"`
	TransactionID string             `json:"transaction_id"`
	Protocol      string             `json:"protocol"`
	Outcome       string             `json:"outcome"`
	Trusted       bool               `json:"trusted"`
	Confidence    float64            `json:"confidence"`
	Reason        string             `json:"reason"`
	RequestAt     time.Time          `json:"request_at"`
	ResponseAt    time.Time          `json:"response_at"`
	ObservedAt    time.Time          `json:"observed_at"`
	Attribution   policy.Attribution `json:"attribution"`
	RawRef        map[string]any     `json:"raw_ref"`
}

func Evaluate(e normalized.Event, c Config) Result {
	r := Result{EventIDs: []string{e.EventID}, SensorID: Text(e.Observer, "sensor_id"), Source: e.Source, InstanceID: Text(e.Observer, "collector_instance_id"), ParserID: Text(e.Observer, "parser_id"), ParserVersion: Text(e.Observer, "parser_version"), ConfigVersion: c.ID(), RuleVersion: RuleVersion, IP: Text(e.Subject, "ip"), ConnectionID: Text(e.Flow, "connection_id"), TransactionID: Text(e.Payload, "transaction_id"), Protocol: Text(e.Payload, "protocol"), Outcome: "incomplete", RawRef: e.RawRef}
	requestText, responseText := Text(e.Payload, "request_at"), Text(e.Payload, "response_at")
	var requestErr, responseErr error
	r.RequestAt, requestErr = time.Parse(time.RFC3339Nano, requestText)
	r.ResponseAt, responseErr = time.Parse(time.RFC3339Nano, responseText)
	r.ObservedAt, _ = time.Parse(time.RFC3339Nano, e.Timestamp)
	r.ID = "proxy-" + policy.StableID(r.SensorID, r.Source, r.InstanceID, r.ConnectionID, r.TransactionID, r.Protocol)
	if r.ConnectionID == "" || r.TransactionID == "" {
		r.ID = "proxy-" + policy.StableID(r.SensorID, e.EventID)
	}
	if p := c.Producer(r.SensorID, r.Source, r.InstanceID); p != nil && r.ParserID == p.ParserID && r.ParserVersion == p.ParserVersion {
		if raw, encodingErr := canonical(e); encodingErr == nil {
			mac := hmac.New(sha256.New, []byte(p.Key))
			mac.Write(raw)
			sig, err := hex.DecodeString(Text(e.Observer, "proxy_signature"))
			r.Trusted = err == nil && hmac.Equal(sig, mac.Sum(nil)) && p.contains(r.ObservedAt) && (r.RequestAt.IsZero() || p.contains(r.RequestAt)) && (r.ResponseAt.IsZero() || p.contains(r.ResponseAt))
		}
		if r.Trusted {
			r.CampusID = p.CampusID
			r.AccessDomain = p.AccessDomain
		}
	}
	if e.Type != "proxy_transaction" {
		r.Outcome = "unsupported"
	} else if r.ConnectionID != "" && r.TransactionID != "" {
		switch r.Protocol {
		case "http_connect":
			status, ok := number(e.Payload, "status")
			if Text(e.Payload, "method") != "CONNECT" {
				r.Outcome = "incomplete"
			} else if ok && status >= 200 && status <= 599 {
				if status < 300 {
					r.Outcome = "success"
				} else {
					r.Outcome = "failed"
				}
			}
		case "socks5":
			version, _ := number(e.Payload, "version")
			cmd, _ := number(e.Payload, "command")
			reply, ok := number(e.Payload, "reply")
			if version != 5 || cmd != 1 {
				r.Outcome = "unsupported"
			} else if ok && !r.RequestAt.IsZero() && !r.ResponseAt.IsZero() {
				if reply == 0 {
					r.Outcome = "success"
				} else if reply > 0 && reply <= 8 {
					r.Outcome = "failed"
				}
			}
		default:
			r.Outcome = "unsupported"
		}
	}
	if r.Protocol == "http_connect" && !r.RequestAt.IsZero() && r.ResponseAt.IsZero() {
		r.Outcome = "incomplete"
	}
	if !r.RequestAt.IsZero() && !r.ResponseAt.IsZero() && r.ResponseAt.Before(r.RequestAt) {
		r.Outcome = "incomplete"
	}
	if r.ObservedAt.IsZero() || (!r.RequestAt.IsZero() && r.RequestAt.After(r.ObservedAt)) || (!r.ResponseAt.IsZero() && r.ResponseAt.After(r.ObservedAt)) {
		r.Outcome = "incomplete"
	}
	if requestText != "" && requestErr != nil || responseText != "" && responseErr != nil {
		r.Outcome = "incomplete"
	}
	r = normalizeResult(r)
	r.Reason = map[string]string{"success": "检测到成功代理连接", "failed": "代理连接请求失败", "incomplete": "事务信息不完整，不能确认成功代理连接", "unsupported": "当前不确认该协议或命令"}[r.Outcome]
	if !r.Trusted {
		r.Reason += "；采集来源未通过校验，仅作线索"
	} else if r.Outcome == "success" {
		r.Confidence = .99
	}
	r.Attribution = policy.Attribution{State: "unknown", Reasons: []string{"identity_not_evaluated"}, SessionIDs: []string{}}
	return normalizeResult(r)
}

func (p Producer) contains(at time.Time) bool {
	return !at.IsZero() && (p.ValidFrom.IsZero() || !at.Before(p.ValidFrom)) && (p.ValidUntil.IsZero() || at.Before(p.ValidUntil))
}
func Merge(a, b Result) Result {
	a, b = normalizeResult(a), normalizeResult(b)
	if a.ID == "" {
		return b
	}
	if a.ID != b.ID {
		return a
	}
	// Never assemble partial request/response fields. Only replace with a complete transaction.
	rank := func(r Result) int {
		if !r.Trusted {
			return 0
		}
		if r.Outcome == "conflict" {
			return 4
		}
		if r.Outcome == "success" || r.Outcome == "failed" {
			return 3
		}
		return 1
	}
	out := a
	if a.Trusted && b.Trusted && ((a.Outcome == "success" && b.Outcome == "failed") || (a.Outcome == "failed" && b.Outcome == "success") || a.IP != b.IP || (!a.RequestAt.IsZero() && !b.RequestAt.IsZero() && !a.RequestAt.Equal(b.RequestAt))) {
		out.Outcome = "conflict"
		out.Confidence = 0
		out.Reason = "同一事务记录冲突，不能用于处置"
	} else if rank(b) > rank(a) || (rank(b) == rank(a) && b.ObservedAt.After(a.ObservedAt)) {
		out = b
	}
	ids := map[string]bool{}
	for _, id := range append(append([]string{}, a.EventIDs...), b.EventIDs...) {
		ids[id] = true
	}
	out.EventIDs = []string{}
	for id := range ids {
		out.EventIDs = append(out.EventIDs, id)
	}
	sort.Strings(out.EventIDs)
	return out
}
func Attribute(r Result, ss []policy.Session) Result {
	r = normalizeResult(r)
	if r.Trusted && !r.RequestAt.IsZero() {
		r.Attribution = policy.Attribute(ss, r.CampusID, r.AccessDomain, r.IP, r.RequestAt)
	} else {
		r.Attribution = policy.Attribution{State: "unknown", Reasons: []string{"missing_trusted_request_time"}, SessionIDs: []string{}}
	}
	return r
}
func Input(account string, rows []Result, ss []policy.Session, now time.Time, window time.Duration, mode string) policy.Input {
	in := policy.Input{AccountID: account, Reasons: []string{"no_fresh_confirmed_proxy_evidence"}, EvidenceIDs: []string{}}
	if mode == "automatic" {
		in.Reasons = []string{"proxy_automatic_forbidden"}
		return in
	}
	for _, row := range rows {
		row = Attribute(row, ss)
		if row.Trusted && row.Outcome == "success" && completeTransaction(row) && !row.ObservedAt.After(now) && !row.ResponseAt.After(now) && !row.RequestAt.After(now) && row.RequestAt.After(now.Add(-window)) && row.Attribution.State == "resolved" && row.Attribution.AccountID == account {
			in.Known = true
			in.Violated = true
			in.EvidenceIDs = append(in.EvidenceIDs, row.ID)
		}
	}
	if in.Violated {
		in.Reasons = []string{"confirmed_proxy_connection_requires_review"}
	}
	sort.Strings(in.EvidenceIDs)
	return in
}

func completeTransaction(r Result) bool {
	return (r.Protocol == "http_connect" || r.Protocol == "socks5") && r.ConnectionID != "" && r.TransactionID != "" && !r.RequestAt.IsZero() && !r.ResponseAt.IsZero() && !r.ObservedAt.IsZero() && !r.ResponseAt.Before(r.RequestAt) && !r.ObservedAt.Before(r.ResponseAt)
}

func completeProtocolObservation(r Result) bool {
	if completeTransaction(r) {
		return true
	}
	// Native EVE method/status are bound to one tx_id. This source can prove
	// the protocol outcome without proving when the request was sent. Never
	// let this observation-only exception reach account policy input.
	return r.Protocol == "http_connect" && r.Source == "suricata" && r.ParserID == "sentinel-suricata-http" && r.ParserVersion == "1" && r.ConnectionID != "" && r.TransactionID != "" && !r.ObservedAt.IsZero() && r.RequestAt.IsZero() && r.ResponseAt.IsZero()
}

// normalizeResult also protects persisted v1 documents and direct policy input.
// It keeps provenance and event IDs while retiring incomplete success claims.
func normalizeResult(r Result) Result {
	if (r.Outcome == "success" || r.Outcome == "failed") && !completeProtocolObservation(r) {
		r.Outcome = "incomplete"
		r.Confidence = 0
		r.Reason = "事务信息不完整，不能确认成功代理连接"
		if !r.Trusted {
			r.Reason += "；采集来源未通过校验，仅作线索"
		}
	} else if (r.Outcome == "success" || r.Outcome == "failed") && r.RequestAt.IsZero() && !strings.Contains(r.Reason, "缺少可信请求时间") {
		r.Reason += "；缺少可信请求时间，不能归责账号"
	}
	return r
}

func canonicalTime(value string) string {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return value
	}
	return t.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
}
