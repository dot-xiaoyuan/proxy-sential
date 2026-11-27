package controlplane

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"proxy-sentinel/internal/store"
)

type aiRelayUsageTestReader struct {
	store.Reader
	lastQuery store.AIRelayUsageQuery
}

func (r *aiRelayUsageTestReader) ListAIRelayUsage(_ context.Context, q store.AIRelayUsageQuery) (store.AIRelayUsagePage, error) {
	r.lastQuery = q
	return store.AIRelayUsagePage{}, nil
}

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

func TestAIRelayUsagesAllowsClockSkewTolerance(t *testing.T) {
	r := &aiRelayUsageTestReader{}
	s := &Server{reader: r}
	now := time.Now().UTC()

	// 在 5 分钟时钟/网络延迟宽容范围内应放行
	fromOK := now.Add(-7*24*time.Hour - 3*time.Minute).Format(time.RFC3339)
	toOK := now.Add(-3 * time.Minute).Format(time.RFC3339)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/ai-relay/usages?from="+url.QueryEscape(fromOK)+"&to="+url.QueryEscape(toOK), nil)
	s.handleAIRelayUsages(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200 within 5m tolerance, got %d: %s", w.Code, w.Body.String())
	}

	// 超过 5 分钟宽容范围应拒绝
	fromExpired := now.Add(-7*24*time.Hour - 6*time.Minute).Format(time.RFC3339)
	toExpired := now.Add(-6 * time.Minute).Format(time.RFC3339)
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/v1/ai-relay/usages?from="+url.QueryEscape(fromExpired)+"&to="+url.QueryEscape(toExpired), nil)
	s.handleAIRelayUsages(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 beyond 5m tolerance, got %d: %s", w.Code, w.Body.String())
	}
}
