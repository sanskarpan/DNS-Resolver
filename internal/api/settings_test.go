package api

import (
	"bytes"
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

func TestSettingsPostAppliesRuntimeHandlerConfig(t *testing.T) {
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
	a := New(Deps{Resolver: r, DNSHandler: h, Cache: cache.New(cache.Options{}), Metrics: metrics.New(), Prometheus: metrics.NewPrometheus(), ReadyCheck: func() bool { return true }, Settings: NewRuntimeSettings(nil)})
	router := a.Router(context.Background())

	payload := map[string]any{
		"rrl_enabled":           false,
		"rate_limit_qps":        55.0,
		"rate_limit_burst":      77,
		"rrl_responses_per_sec": 6,
		"rrl_slip":              3,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/settings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}

	cfg := h.RuntimeConfig()
	if cfg["rrl_enabled"] != false {
		t.Fatalf("expected rrl_enabled=false, got=%v", cfg["rrl_enabled"])
	}
	if cfg["rate_limit_qps"].(float64) != 55 {
		t.Fatalf("expected rate_limit_qps=55, got=%v", cfg["rate_limit_qps"])
	}
	if cfg["rate_limit_burst"].(int) != 77 {
		t.Fatalf("expected rate_limit_burst=77, got=%v", cfg["rate_limit_burst"])
	}
	if cfg["rrl_responses_per_sec"].(int) != 6 {
		t.Fatalf("expected rrl_responses_per_sec=6, got=%v", cfg["rrl_responses_per_sec"])
	}
	if cfg["rrl_slip"].(int) != 3 {
		t.Fatalf("expected rrl_slip=3, got=%v", cfg["rrl_slip"])
	}
}

func TestSettingsPostAppliesResolverAndCacheRuntimeConfig(t *testing.T) {
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
	a := New(Deps{Resolver: r, DNSHandler: h, Cache: cache.New(cache.Options{}), Metrics: metrics.New(), Prometheus: metrics.NewPrometheus(), ReadyCheck: func() bool { return true }, Settings: NewRuntimeSettings(nil)})
	router := a.Router(context.Background())

	payload := map[string]any{
		"qname_minimization":  false,
		"case_randomization":  false,
		"edns_enabled":        false,
		"max_udp_size":        1400,
		"upstream_timeout":    "2s",
		"max_cname_depth":     7,
		"max_recursion_depth": 8,
		"retries":             4,
		"cache_max_entries":   1500,
		"cache_min_ttl":       20,
		"cache_max_ttl":       600,
		"cache_stale_window":  120,
		"cache_stale_max_age": 1800,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/settings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}

	cfg := h.RuntimeConfig()
	if cfg["qname_minimization"] != false {
		t.Fatalf("expected qname_minimization=false, got=%v", cfg["qname_minimization"])
	}
	if cfg["case_randomization"] != false {
		t.Fatalf("expected case_randomization=false, got=%v", cfg["case_randomization"])
	}
	if cfg["edns_enabled"] != false {
		t.Fatalf("expected edns_enabled=false, got=%v", cfg["edns_enabled"])
	}
	if cfg["max_udp_size"].(int) != 1400 {
		t.Fatalf("expected max_udp_size=1400, got=%v", cfg["max_udp_size"])
	}
	if cfg["max_cname_depth"].(int) != 7 {
		t.Fatalf("expected max_cname_depth=7, got=%v", cfg["max_cname_depth"])
	}
	if cfg["max_recursion_depth"].(int) != 8 {
		t.Fatalf("expected max_recursion_depth=8, got=%v", cfg["max_recursion_depth"])
	}
	if cfg["retries"].(int) != 4 {
		t.Fatalf("expected retries=4, got=%v", cfg["retries"])
	}
	if cfg["cache_max_entries"].(int) != 1500 {
		t.Fatalf("expected cache_max_entries=1500, got=%v", cfg["cache_max_entries"])
	}
	if cfg["cache_min_ttl"].(int) != 20 {
		t.Fatalf("expected cache_min_ttl=20, got=%v", cfg["cache_min_ttl"])
	}
	if cfg["cache_max_ttl"].(int) != 600 {
		t.Fatalf("expected cache_max_ttl=600, got=%v", cfg["cache_max_ttl"])
	}
	if cfg["cache_stale_window"].(int) != 120 {
		t.Fatalf("expected cache_stale_window=120, got=%v", cfg["cache_stale_window"])
	}
	if cfg["cache_stale_max_age"].(int) != 1800 {
		t.Fatalf("expected cache_stale_max_age=1800, got=%v", cfg["cache_stale_max_age"])
	}
}

func TestSettingsPostAcceptsBlocklistArray(t *testing.T) {
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
	a := New(Deps{Resolver: r, DNSHandler: h, Cache: cache.New(cache.Options{}), Metrics: metrics.New(), Prometheus: metrics.NewPrometheus(), ReadyCheck: func() bool { return true }, Settings: NewRuntimeSettings(nil)})
	router := a.Router(context.Background())

	body, _ := json.Marshal(map[string]any{
		"blocklist": []string{"example.com", "*.ads.example.com"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/settings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if r.BlocklistStats().DomainsCount != 2 {
		t.Fatalf("expected blocklist to contain 2 entries, got %d", r.BlocklistStats().DomainsCount)
	}
	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	blocklist, ok := payload["blocklist"].([]any)
	if !ok || len(blocklist) != 2 {
		t.Fatalf("expected blocklist array in response, got=%T %#v", payload["blocklist"], payload["blocklist"])
	}
}
