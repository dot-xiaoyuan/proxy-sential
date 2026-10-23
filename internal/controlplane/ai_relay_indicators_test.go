package controlplane

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestAIRelayIndicatorsReturnsEmbeddedLibrary(t *testing.T) {
	w := httptest.NewRecorder()
	(&Server{}).handleAIRelayIndicators(w, httptest.NewRequest("GET", "/api/v1/ai-relay/indicators", nil))
	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
	var body struct {
		Version    string `json:"version"`
		Indicators []struct {
			Domain string `json:"domain"`
			NameZH string `json:"name_zh"`
		} `json:"indicators"`
		OfficialDomains []string `json:"official_domains"`
		Sources         []struct {
			ID string `json:"id"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Version == "" || len(body.Indicators) == 0 || len(body.OfficialDomains) == 0 || len(body.Sources) == 0 {
		t.Fatalf("incomplete embedded library: %+v", body)
	}
	for _, indicator := range body.Indicators {
		if indicator.NameZH == "" {
			t.Errorf("missing Chinese name for %s", indicator.Domain)
		}
	}
}
