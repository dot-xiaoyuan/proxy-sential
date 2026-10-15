package discovery

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"proxy-sentinel/internal/normalized"
	"strings"
)

// JSONB cannot represent U+0000. Preserve exceptional input losslessly in a
// versioned base64 envelope rather than deleting protocol bytes or blocking
// every valid event sharing a capture window. Existing array tasks stay valid.
func EncodeDiscoveryBatch(events []normalized.Event) ([]byte, error) {
	raw, err := json.Marshal(events)
	if err != nil {
		return nil, err
	}
	if len(raw) > 8<<20 {
		return nil, fmt.Errorf("discovery batch exceeds byte budget")
	}
	if !bytes.Contains(raw, []byte(`\u0000`)) {
		return raw, nil
	}
	return json.Marshal(struct {
		Encoding string `json:"encoding"`
		Data     string `json:"data"`
	}{"base64-json-v1", base64.StdEncoding.EncodeToString(raw)})
}
func decodeDiscoveryBatch(raw []byte, events *[]normalized.Event) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '[' {
		return json.Unmarshal(raw, events)
	}
	var envelope struct {
		Encoding string `json:"encoding"`
		Data     string `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return err
	}
	if envelope.Encoding != "base64-json-v1" {
		return fmt.Errorf("unsupported discovery task encoding")
	}
	decoded, err := base64.StdEncoding.DecodeString(envelope.Data)
	if err != nil {
		return err
	}
	if len(decoded) > 8<<20 {
		return fmt.Errorf("discovery batch exceeds byte budget")
	}
	return json.Unmarshal(decoded, events)
}
func containsNUL(v any) bool {
	switch v := v.(type) {
	case string:
		return strings.ContainsRune(v, 0)
	case []string:
		for _, x := range v {
			if containsNUL(x) {
				return true
			}
		}
	case []any:
		for _, x := range v {
			if containsNUL(x) {
				return true
			}
		}
	case map[string]any:
		for k, x := range v {
			if containsNUL(k) || containsNUL(x) {
				return true
			}
		}
	}
	return false
}
