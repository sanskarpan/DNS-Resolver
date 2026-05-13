package api

import (
	"context"
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

func TestReverseLookupEndpoint(t *testing.T) {
	t.Parallel()
	cfg := resolver.DefaultConfig()
	cfg.QNAMEMinimization = false
	r := resolver.New(cfg, cache.New(cache.Options{}))
	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []resolver.ResolutionEvent, error) {
		if qname != "8.8.8.8.in-addr.arpa." || qtype != protocol.TypePTR {
			t.Fatalf("unexpected reverse query: %s type=%d", qname, qtype)
		}
		return &protocol.Message{
			Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
			Answers: []protocol.ResourceRecord{{
				Name:  qname,
				Type:  protocol.TypePTR,
				Class: protocol.ClassIN,
				TTL:   60,
				Data:  protocol.PTRData{Name: "dns.google."},
			}},
		}, nil, nil
	})
	h := server.NewHandler(server.Options{Resolver: r, Metrics: metrics.New(), Prometheus: metrics.NewPrometheus()})
	a := New(Deps{Resolver: r, DNSHandler: h, Cache: cache.New(cache.Options{}), Metrics: metrics.New(), Prometheus: metrics.NewPrometheus(), ReadyCheck: func() bool { return true }})
	router := a.Router(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/reverse?ip=8.8.8.8", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestReverseLookupEndpointRejectsInvalidIP(t *testing.T) {
	t.Parallel()
	a := New(Deps{ReadyCheck: func() bool { return true }})
	router := a.Router(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/reverse?ip=bad_ip", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestReverseNameFromIPV6(t *testing.T) {
	t.Parallel()
	name, ok := reverseNameFromIP(netParseOrPanic(t, "2001:db8::1"))
	if !ok {
		t.Fatalf("expected valid ipv6 reverse name")
	}
	if name == "" || name[len(name)-9:] != "ip6.arpa." {
		t.Fatalf("unexpected reverse name: %s", name)
	}
}

func netParseOrPanic(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("invalid test ip: %s", s)
	}
	return ip
}
