package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"dnsresolver/internal/cache"
	"dnsresolver/internal/metrics"
	"dnsresolver/internal/resolver"
	"dnsresolver/internal/security"
	"dnsresolver/internal/server"
)

func TestRootServersEndpointIncludesUpstreamDetails(t *testing.T) {
	t.Parallel()

	r := resolver.New(resolver.DefaultConfig(), cache.New(cache.Options{}))
	h := server.NewHandler(server.Options{
		Resolver:    r,
		RateLimiter: security.NewRateLimiter(100, 200),
		RRL:         security.NewRRL(10, 2),
		RRLEnabled:  true,
		Metrics:     metrics.New(),
		Prometheus:  metrics.NewPrometheus(),
	})
	a := New(Deps{
		Resolver:   r,
		DNSHandler: h,
		Cache:      cache.New(cache.Options{}),
		Metrics:    metrics.New(),
		Prometheus: metrics.NewPrometheus(),
		ReadyCheck: func() bool { return true },
	})
	router := a.Router(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rootservers", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	servers, ok := body["servers"].([]any)
	if !ok {
		t.Fatalf("expected servers array")
	}
	if len(servers) != 13 {
		t.Fatalf("expected 13 root servers, got %d", len(servers))
	}
	upstreams, ok := body["upstreams"].([]any)
	if !ok {
		t.Fatalf("expected upstreams array")
	}
	if len(upstreams) == 0 {
		t.Fatalf("expected upstreams to include at least root hints")
	}

	firstServer, ok := servers[0].(map[string]any)
	if !ok {
		t.Fatalf("expected server object shape")
	}
	if _, ok := firstServer["state_code"]; !ok {
		t.Fatalf("expected state_code field on root server")
	}
	if _, ok := firstServer["consecutive_failures"]; !ok {
		t.Fatalf("expected consecutive_failures field on root server")
	}
}
