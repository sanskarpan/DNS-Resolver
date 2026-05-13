package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"dnsresolver/internal/cache"
	"dnsresolver/internal/metrics"
	"dnsresolver/internal/protocol"
	"dnsresolver/internal/resolver"
	"dnsresolver/internal/server"
)

func TestHistoryReplayEndpoint(t *testing.T) {
	t.Parallel()

	cfg := resolver.DefaultConfig()
	cfg.QNAMEMinimization = false
	c := cache.New(cache.Options{})
	r := resolver.New(cfg, c)

	var calls int32
	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []resolver.ResolutionEvent, error) {
		call := atomic.AddInt32(&calls, 1)
		ttl := uint32(60)
		if call > 1 {
			ttl = 120
		}
		msg := &protocol.Message{
			Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
			Answers: []protocol.ResourceRecord{{
				Name:  qname,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   ttl,
				Data:  protocol.AData{Address: [4]byte{1, 1, 1, 1}},
			}},
		}
		events := []resolver.ResolutionEvent{{
			QueryID:   queryID,
			Timestamp: time.Now().UTC(),
			Step:      step,
			StepType:  "upstream_response",
			Query:     qname,
			QueryType: protocol.TypeToString(qtype),
			Success:   true,
			ParsedMsg: msg,
		}}
		return msg, events, nil
	})

	first, err := r.Resolve(context.Background(), "example.com", protocol.TypeA)
	if err != nil {
		t.Fatalf("seed resolve: %v", err)
	}
	// Ensure replay performs a fresh resolution rather than returning a cache hit.
	c.Flush()

	h := server.NewHandler(server.Options{Resolver: r, Metrics: metrics.New(), Prometheus: metrics.NewPrometheus()})
	a := New(Deps{Resolver: r, DNSHandler: h, Cache: c, Metrics: metrics.New(), Prometheus: metrics.NewPrometheus(), ReadyCheck: func() bool { return true }})
	router := a.Router(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/history/"+first.QueryID+"/replay", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["history_id"] != first.QueryID {
		t.Fatalf("expected history_id=%s got=%v", first.QueryID, body["history_id"])
	}
	diff, ok := body["diff"].(map[string]any)
	if !ok {
		t.Fatalf("missing diff payload: %v", body["diff"])
	}
	if available, ok := diff["available"].(bool); !ok || !available {
		t.Fatalf("expected diff.available=true, got=%v", diff["available"])
	}
	if ttlDiffs, ok := diff["ttl_differences"].([]any); !ok || len(ttlDiffs) == 0 {
		t.Fatalf("expected ttl differences in replay diff, got=%v", diff["ttl_differences"])
	}
}

func TestHistoryReplayEndpointNotFound(t *testing.T) {
	t.Parallel()
	r := resolver.New(resolver.DefaultConfig(), cache.New(cache.Options{}))
	a := New(Deps{Resolver: r, ReadyCheck: func() bool { return true }})
	router := a.Router(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/history/missing-id/replay", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHistoryReplayEndpointMethodNotAllowed(t *testing.T) {
	t.Parallel()

	cfg := resolver.DefaultConfig()
	cfg.QNAMEMinimization = false
	r := resolver.New(cfg, cache.New(cache.Options{}))
	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []resolver.ResolutionEvent, error) {
		msg := &protocol.Message{
			Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
			Answers: []protocol.ResourceRecord{{
				Name:  qname,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   60,
				Data:  protocol.AData{Address: [4]byte{1, 1, 1, 1}},
			}},
		}
		return msg, []resolver.ResolutionEvent{{
			QueryID:   queryID,
			Timestamp: time.Now().UTC(),
			Step:      step,
			StepType:  "upstream_response",
			Query:     qname,
			QueryType: protocol.TypeToString(qtype),
			Success:   true,
			ParsedMsg: msg,
		}}, nil
	})

	seed, err := r.Resolve(context.Background(), "example.com", protocol.TypeA)
	if err != nil {
		t.Fatalf("seed resolve: %v", err)
	}
	h := server.NewHandler(server.Options{Resolver: r, Metrics: metrics.New(), Prometheus: metrics.NewPrometheus()})
	a := New(Deps{Resolver: r, DNSHandler: h, Cache: cache.New(cache.Options{}), Metrics: metrics.New(), Prometheus: metrics.NewPrometheus(), ReadyCheck: func() bool { return true }})
	router := a.Router(context.Background())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/history/"+seed.QueryID+"/replay", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got=%d body=%s", rr.Code, rr.Body.String())
	}
}
