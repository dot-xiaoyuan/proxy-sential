package suricata

import (
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/proxyprotocol"
)

func proxyTransaction(e normalized.Event, opts Options) (normalized.Event, bool) {
	if e.Type != "http" || proxyprotocol.Text(e.Payload, "method") != "CONNECT" {
		return normalized.Event{}, false
	}
	// EVE status and method belong to tx_id, but EVE timestamp is not a proven request timestamp.
	// Keep request_at absent rather than assigning a potentially different historical account.
	p := map[string]any{"protocol": "http_connect", "transaction_id": proxyprotocol.Text(e.RawRef, "tx_id"), "method": "CONNECT"}
	if status, ok := e.Payload["status"]; ok {
		p["status"] = status
	}
	e.Subject = map[string]any{"ip": proxyprotocol.Text(e.Flow, "src_ip")}
	e.EventID += "-proxy"
	e.Type = "proxy_transaction"
	e.Payload = p
	if opts.ProxyProducer != nil {
		proxyprotocol.Sign(&e, *opts.ProxyProducer)
	}
	return e, true
}
