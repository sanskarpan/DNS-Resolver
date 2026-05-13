package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dnsresolver/internal/cache"
	"dnsresolver/internal/metrics"
)

func TestCacheStatsAndMetricsEndpointsSuccess(t *testing.T) {
	t.Parallel()

	c := cache.New(cache.Options{})
	m := metrics.New()
	m.ObserveQuery("A", "udp", "NOERROR", true, false, 15*time.Millisecond)
	api := New(Deps{Cache: c, Metrics: m, ReadyCheck: func() bool { return true }})
	router := api.Router(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/cache/stats", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("cache stats status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"entries"`) {
		t.Fatalf("expected entries field, got %s", rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("metrics status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"total_queries":1`) {
		t.Fatalf("expected total_queries field, got %s", rr.Body.String())
	}
}

func TestPrometheusEndpointEnabledAndDisabled(t *testing.T) {
	t.Parallel()

	apiWithoutProm := New(Deps{ReadyCheck: func() bool { return true }})
	routerWithoutProm := apiWithoutProm.Router(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	routerWithoutProm.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("disabled prometheus status=%d want=%d", rr.Code, http.StatusNotFound)
	}

	prom := metrics.NewPrometheus()
	prom.ObserveQuery("A", "udp", "NOERROR", false)
	apiWithProm := New(Deps{Prometheus: prom, ReadyCheck: func() bool { return true }})
	routerWithProm := apiWithProm.Router(context.Background())
	rr = httptest.NewRecorder()
	routerWithProm.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("enabled prometheus status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "dns_query_total") {
		t.Fatalf("expected prometheus metrics output, got %s", rr.Body.String())
	}
}
