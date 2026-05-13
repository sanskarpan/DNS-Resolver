package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dnsresolver/internal/cache"
	"dnsresolver/internal/metrics"
	"dnsresolver/internal/protocol"
	"dnsresolver/internal/resolver"
	"dnsresolver/internal/server"
)

func TestBulkEndpointCSVExport(t *testing.T) {
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
	a := New(Deps{Resolver: r, DNSHandler: h, Cache: cache.New(cache.Options{}), Metrics: metrics.New(), Prometheus: metrics.NewPrometheus(), ReadyCheck: func() bool { return true }})
	router := a.Router(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/bulk?queries=example.com,test.com&format=csv", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/csv") {
		t.Fatalf("expected text/csv content-type, got %q", got)
	}

	rows, err := csv.NewReader(strings.NewReader(rr.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected header + 2 rows, got %d rows: %+v", len(rows), rows)
	}
	if strings.Join(rows[0], ",") != "query,rcode,error,duration_ms" {
		t.Fatalf("unexpected csv header: %v", rows[0])
	}
}

func TestBulkEndpointJSONDefault(t *testing.T) {
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
	a := New(Deps{Resolver: r, DNSHandler: h, Cache: cache.New(cache.Options{}), Metrics: metrics.New(), Prometheus: metrics.NewPrometheus(), ReadyCheck: func() bool { return true }})
	router := a.Router(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/bulk?queries=example.com,test.com", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}

	var body struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Results) != 2 {
		t.Fatalf("expected two bulk results, got %d", len(body.Results))
	}
}
