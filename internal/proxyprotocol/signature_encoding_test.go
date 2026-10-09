package proxyprotocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"testing"
	"time"

	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/policy"
)

func TestProxyVerifierRejectsUnencodableSignedFields(t *testing.T) {
	for _, field := range []string{"payload_nan", "payload_infinity", "observer_function", "flow_channel", "raw_ref_cycle"} {
		t.Run(field, func(t *testing.T) {
			e, p := fixture()
			e.Observer["parser_id"], e.Observer["parser_version"] = p.ParserID, p.ParserVersion
			switch field {
			case "payload_nan":
				e.Payload["extra"] = math.NaN()
			case "payload_infinity":
				e.Payload["extra"] = math.Inf(1)
			case "observer_function":
				e.Observer["extra"] = func() {}
			case "flow_channel":
				e.Flow["extra"] = make(chan int)
			case "raw_ref_cycle":
				e.RawRef = map[string]any{}
				e.RawRef["extra"] = e.RawRef
			}
			// The old verifier accepted the HMAC of an empty byte slice when
			// JSON encoding failed. Supply it independently of the signer.
			mac := hmac.New(sha256.New, []byte(p.Key))
			e.Observer["proxy_signature"] = hex.EncodeToString(mac.Sum(nil))
			r := Evaluate(e, Config{Version: "encoding-test", Producers: []Producer{p}})
			if r.Trusted || r.Confidence != 0 || r.CampusID != "" || r.AccessDomain != "" {
				t.Fatalf("unencodable %s passed producer verification: trusted=%v confidence=%v", field, r.Trusted, r.Confidence)
			}
			ss := []policy.Session{{ID: "owner", AccountID: "owner", IP: r.IP, CampusID: "c", AccessDomain: "nas", Source: "auth", StartedAt: r.RequestAt.Add(-time.Minute), ConfirmedAt: r.RequestAt, HeartbeatSeconds: 60}}
			if in := Input("owner", []Result{r}, ss, r.ObservedAt, time.Hour, "manual"); in.Known || in.Violated {
				t.Fatal("unencodable transaction became account policy input")
			}
		})
	}
}

// Keep this positive control beside the malformed cases so tightening the
// verifier cannot silently remove normal persisted transaction support.
func TestProxySignatureSurvivesNormalizedJSONRoundTrip(t *testing.T) {
	e, p := fixture()
	if err := Sign(&e, p); err != nil {
		t.Fatal(err)
	}
	if got := e.Observer["proxy_signature"]; got != "c577f1c4a9a4b9553a1f8d4a1031a9e20b16f927a52323069011db3059a8a066" {
		t.Fatal("valid transaction canonical bytes changed")
	}
	var persisted normalized.Event
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	r := Evaluate(persisted, Config{Producers: []Producer{p}})
	if !r.Trusted || r.Outcome != "success" || r.Confidence != .99 {
		t.Fatal("valid stored transaction no longer verifies")
	}
}

func TestProxySignerClearsStaleSignatureAfterEncodingFailure(t *testing.T) {
	e, p := fixture()
	if err := Sign(&e, p); err != nil {
		t.Fatal(err)
	}
	e.Payload["extra"] = math.NaN()
	if err := Sign(&e, p); err == nil {
		t.Fatal("signer hid the encoding failure")
	}
	if _, present := e.Observer["proxy_signature"]; present {
		t.Fatal("failed signing retained a previous signature")
	}
	delete(e.Payload, "extra")
	if Evaluate(e, Config{Producers: []Producer{p}}).Trusted {
		t.Fatal("repairing the payload resurrected a stale signature")
	}
	if err := Sign(&e, p); err != nil {
		t.Fatal(err)
	}
	if !Evaluate(e, Config{Producers: []Producer{p}}).Trusted {
		t.Fatal("explicit signing of the repaired event did not recover")
	}
}

func TestProxySignerRejectsNilEvent(t *testing.T) {
	_, p := fixture()
	if err := Sign(nil, p); err == nil {
		t.Fatal("nil event was signed")
	}
}
