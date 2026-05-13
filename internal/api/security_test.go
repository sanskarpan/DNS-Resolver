package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"dnsresolver/internal/cache"
	"dnsresolver/internal/metrics"
	"dnsresolver/internal/protocol"
	"dnsresolver/internal/resolver"
	"dnsresolver/internal/server"
)

func TestSecurityStatsEndpointShape(t *testing.T) {
	t.Parallel()

	r := resolver.New(resolver.DefaultConfig(), cache.New(cache.Options{}))
	r.ReplaceBlocklist("ads.example.com")
	h := server.NewHandler(server.Options{Resolver: r, Metrics: metrics.New(), Prometheus: metrics.NewPrometheus()})

	// Trigger a blocked query to increment security counters.
	q := &protocol.Message{Header: protocol.Header{ID: 1, RD: true}, Questions: []protocol.Question{{Name: "ads.example.com.", Type: protocol.TypeA, Class: protocol.ClassIN}}}
	wire, err := protocol.Encode(q)
	if err != nil {
		t.Fatalf("encode query: %v", err)
	}
	if _, _, err := h.HandlePacket(context.Background(), wire, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5000}, "udp"); err != nil {
		t.Fatalf("handle packet: %v", err)
	}

	a := New(Deps{Resolver: r, DNSHandler: h, Cache: cache.New(cache.Options{}), Metrics: metrics.New(), Prometheus: metrics.NewPrometheus(), ReadyCheck: func() bool { return true }})
	router := a.Router(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/stats", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := body["drops"]; !ok {
		t.Fatalf("expected drops field")
	}
	if _, ok := body["rate_limiter"]; !ok {
		t.Fatalf("expected rate_limiter field")
	}
	if _, ok := body["rrl"]; !ok {
		t.Fatalf("expected rrl field")
	}
	if _, ok := body["poisoning_attempts"]; !ok {
		t.Fatalf("expected poisoning_attempts field")
	}
	if _, ok := body["blocklist"]; !ok {
		t.Fatalf("expected blocklist field")
	}
	if _, ok := body["resolver_sec"]; !ok {
		t.Fatalf("expected resolver_sec field")
	}
}
