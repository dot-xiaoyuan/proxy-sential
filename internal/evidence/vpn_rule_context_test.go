package evidence

import (
	"bytes"
	"testing"
)

func TestVPNClassificationDoesNotUseCollectorNamespace(t *testing.T) {
	for _, tc := range []struct {
		name, signature string
		metadata        any
	}{
		{"namespace", "PROXY_SENTINEL SSH greeting", nil},
		{"source", "ET INFO TLS handshake", map[string]any{"source": []any{"proxy_sentinel"}}},
		{"confidence-key", "ET INFO TLS handshake", map[string]any{"proxy_sentinel_confidence": []any{"high"}}},
		{"description", "ET INFO ordinary application", map[string]any{"description": "proxy analysis collector"}},
		{"empty-signature", "", map[string]any{"proxy_sentinel_confidence": []any{"high"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]any{"signature": tc.signature, "metadata": tc.metadata, "category": "Generic Protocol Command Decode"}
			if IsVPNAlert(payload) {
				t.Fatal("collector metadata became a proxy protocol rule")
			}
			result, err := Analyze(bytes.NewBufferString(normalizedLine("benign-alert", "alert", payload, nil)+"\n"), Options{})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Evidence) != 0 {
				t.Fatalf("collector context produced proxy evidence: %+v", result.Evidence)
			}
		})
	}
}
