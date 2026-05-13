package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPrometheusExportsRequiredMetricLabels(t *testing.T) {
	t.Parallel()
	p := NewPrometheus()
	p.ObserveQuery("A", "udp", "NOERROR", false)
	p.ObserveResolutionStep("A", "auth_query", 12*time.Millisecond)
	p.ObserveUpstream("198.41.0.4", "root", 20*time.Millisecond)
	p.SetCacheEntries("positive", 10)
	p.SetCacheEntries("negative", 1)
	p.SetCacheEntries("stale", 2)
	p.SetCircuitState("198.41.0.4", 0)
	p.IncSecurityDrop("rate_limit")
	p.IncSecurityDrop("bailiwick")
	p.SetGoroutines(42)

	rr := httptest.NewRecorder()
	p.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()

	for _, want := range []string{
		`dns_cache_entries{kind="positive"} 10`,
		`dns_cache_entries{kind="negative"} 1`,
		`dns_cache_entries{kind="stale"} 2`,
		`dns_circuit_breaker_state{server="198.41.0.4"} 0`,
		`dns_security_drops_total{reason="rate_limit"} 1`,
		`dns_security_drops_total{reason="bailiwick"} 1`,
		`dns_goroutine_count 42`,
		`type="A"`,
		`protocol="udp"`,
		`rcode="NOERROR"`,
		`cached="false"`,
		`step="auth_query"`,
		`zone="root"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected metric line %q in body:\n%s", want, body)
		}
	}
	if !strings.Contains(body, `dns_query_total{`) {
		t.Fatalf("expected dns_query_total metric in body:\n%s", body)
	}
	if !strings.Contains(body, `dns_resolution_duration_seconds_bucket{`) {
		t.Fatalf("expected dns_resolution_duration_seconds metric in body:\n%s", body)
	}
	if !strings.Contains(body, `dns_upstream_query_duration_seconds_bucket{`) {
		t.Fatalf("expected dns_upstream_query_duration_seconds metric in body:\n%s", body)
	}
}

func TestPrometheusHistogramScrapesAreStable(t *testing.T) {
	t.Parallel()
	p := NewPrometheus()
	p.ObserveResolutionStep("A", "auth_query", 12*time.Millisecond)
	p.ObserveResolutionStep("A", "auth_query", 40*time.Millisecond)

	rr := httptest.NewRecorder()
	p.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()

	if strings.Count(body, "dns_resolution_duration_seconds_count") != 1 {
		t.Fatalf("expected exactly one count line per labelset, body:\n%s", body)
	}
	if !strings.Contains(body, `dns_resolution_duration_seconds_count{step="auth_query",type="A"} 2`) &&
		!strings.Contains(body, `dns_resolution_duration_seconds_count{type="A",step="auth_query"} 2`) {
		t.Fatalf("expected histogram count=2, body:\n%s", body)
	}
}
