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

func TestHistoryEndpointIncludesReverseDNSClientEnrichment(t *testing.T) {
	t.Parallel()

	cfg := resolver.DefaultConfig()
	cfg.QNAMEMinimization = false
	r := resolver.New(cfg, cache.New(cache.Options{}))
	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []resolver.ResolutionEvent, error) {
		return &protocol.Message{
			Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
			Answers: []protocol.ResourceRecord{{
				Name:  qname,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   60,
				Data:  protocol.AData{Address: [4]byte{1, 1, 1, 1}},
			}},
		}, nil, nil
	})
	h := server.NewHandler(server.Options{Resolver: r, Metrics: metrics.New(), Prometheus: metrics.NewPrometheus()})
	h.SetLookupAddrFunc(func(ctx context.Context, addr string) ([]string, error) {
		if addr == "203.0.113.10" {
			return []string{"client.example.test."}, nil
		}
		return nil, nil
	})

	query := &protocol.Message{
		Header:    protocol.Header{ID: 1234, RD: true},
		Questions: []protocol.Question{{Name: "example.com.", Type: protocol.TypeA, Class: protocol.ClassIN}},
	}
	wire, err := protocol.Encode(query)
	if err != nil {
		t.Fatalf("encode query: %v", err)
	}
	if _, _, err := h.HandlePacket(context.Background(), wire, &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 53000}, "udp"); err != nil {
		t.Fatalf("handle packet: %v", err)
	}

	a := New(Deps{Resolver: r, DNSHandler: h, Cache: cache.New(cache.Options{}), Metrics: metrics.New(), Prometheus: metrics.NewPrometheus(), ReadyCheck: func() bool { return true }})
	router := a.Router(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/history?page=1&limit=10", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}

	var body struct {
		Items   []map[string]any `json:"items"`
		Queries []map[string]any `json:"queries"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Items) == 0 {
		t.Fatalf("expected at least one history item")
	}
	item := body.Items[0]
	if item["client_ip"] != "203.0.113.10" {
		t.Fatalf("expected client_ip enrichment, got=%v", item["client_ip"])
	}
	if item["client_hostname"] != "client.example.test" {
		t.Fatalf("expected client_hostname enrichment, got=%v", item["client_hostname"])
	}
	if item["type"] != "A" {
		t.Fatalf("expected type alias=A, got=%v", item["type"])
	}
	if len(body.Queries) != len(body.Items) {
		t.Fatalf("expected queries alias to mirror items")
	}
}
