package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"dnsresolver/internal/cache"
	"dnsresolver/internal/metrics"
	"dnsresolver/internal/protocol"
	"dnsresolver/internal/resolver"
	"dnsresolver/internal/server"
)

func TestResolveIncludesDNSSECStatus(t *testing.T) {
	t.Parallel()
	cfg := resolver.DefaultConfig()
	cfg.QNAMEMinimization = false
	r := resolver.New(cfg, cache.New(cache.Options{}))
	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []resolver.ResolutionEvent, error) {
		return &protocol.Message{
			Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
			Answers: []protocol.ResourceRecord{
				{
					Name:  "example.com.",
					Type:  protocol.TypeA,
					Class: protocol.ClassIN,
					TTL:   60,
					Data:  protocol.AData{Address: [4]byte{1, 1, 1, 1}},
				},
				{
					Name:  "example.com.",
					Type:  protocol.TypeRRSIG,
					Class: protocol.ClassIN,
					TTL:   60,
					Data: protocol.RRSIGData{
						TypeCovered: protocol.TypeA, Algorithm: 8, Labels: 2, OriginalTTL: 60,
						Expiration: 1, Inception: 1, KeyTag: 1, SignerName: "example.com.", Signature: []byte{1},
					},
				},
			},
			Additionals: []protocol.ResourceRecord{{
				Name:  "example.com.",
				Type:  protocol.TypeDNSKEY,
				Class: protocol.ClassIN,
				TTL:   60,
				Data:  protocol.DNSKEYData{Flags: 257, Protocol: 3, Algorithm: 8, PublicKey: []byte{1, 2}},
			}},
		}, nil, nil
	})
	h := server.NewHandler(server.Options{Resolver: r, Metrics: metrics.New(), Prometheus: metrics.NewPrometheus()})
	a := New(Deps{Resolver: r, DNSHandler: h, Cache: cache.New(cache.Options{}), Metrics: metrics.New(), Prometheus: metrics.NewPrometheus(), ReadyCheck: func() bool { return true }})
	router := a.Router(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/resolve?q=example.com&type=A", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["dnssec_status"] != "secure" {
		t.Fatalf("expected dnssec_status=secure, got %v", body["dnssec_status"])
	}
	if body["query"] != "example.com" {
		t.Fatalf("expected query to be echoed, got %v", body["query"])
	}
	if body["query_type"] != "A" {
		t.Fatalf("expected query_type=A, got %v", body["query_type"])
	}
	if body["rcode"] != "NOERROR" {
		t.Fatalf("expected rcode=NOERROR, got %v", body["rcode"])
	}
	if body["steps"] == nil {
		t.Fatalf("expected steps metadata")
	}
}
