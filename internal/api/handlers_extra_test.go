package api

import (
	"context"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"

	"dnsresolver/internal/cache"
	"dnsresolver/internal/metrics"
	"dnsresolver/internal/protocol"
	"dnsresolver/internal/resolver"
	"dnsresolver/internal/server"
)

func TestCacheHandlers(t *testing.T) {
	c := cache.New(cache.Options{MaxEntries: 100})
	msg := &protocol.Message{
		Header:  protocol.Header{QR: true, RCode: protocol.RCodeNoError},
		Answers: []protocol.ResourceRecord{{Name: "test.com.", Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 60, Data: protocol.AData{Address: [4]byte{1, 2, 3, 4}}}},
	}
	c.Set("test.com.|A", msg, 60)

	r := resolver.New(resolver.DefaultConfig(), c)
	m := metrics.New()
	p := metrics.NewPrometheus()
	h := server.NewHandler(server.Options{Resolver: r, Metrics: m, Prometheus: p})

	ctx := context.Background()
	api := New(Deps{
		Cache:      c,
		Resolver:   r,
		DNSHandler: h,
		Metrics:    m,
		Prometheus: p,
		ReadyCheck: func() bool { return true },
	})
	router := api.Router(ctx)

	t.Run("list cache entries", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/cache?page=1&limit=10", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("status=%d want=200 body=%s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "entries") {
			t.Fatalf("expected entries in response: %s", rr.Body.String())
		}
	})

	t.Run("cache stats", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/cache/stats", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("status=%d want=200 body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("flush cache", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/cache", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("status=%d want=200 body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("evict cache key", func(t *testing.T) {
		c.Set("evict.me.|A", msg, 60)
		req := httptest.NewRequest("DELETE", "/api/v1/cache/evict.me.|A", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("status=%d want=200 body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestMetricsHandler(t *testing.T) {
	c := cache.New(cache.Options{})
	r := resolver.New(resolver.DefaultConfig(), c)
	m := metrics.New()
	p := metrics.NewPrometheus()
	h := server.NewHandler(server.Options{Resolver: r, Metrics: m, Prometheus: p})

	ctx := context.Background()
	api := New(Deps{
		Cache:      c,
		Resolver:   r,
		DNSHandler: h,
		Metrics:    m,
		Prometheus: p,
		ReadyCheck: func() bool { return true },
	})
	router := api.Router(ctx)

	req := httptest.NewRequest("GET", "/api/v1/metrics", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status=%d want=200 body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "total_queries") {
		t.Fatalf("expected total_queries in response: %s", rr.Body.String())
	}
}

func TestPrometheusHandler(t *testing.T) {
	c := cache.New(cache.Options{})
	r := resolver.New(resolver.DefaultConfig(), c)
	m := metrics.New()
	p := metrics.NewPrometheus()
	h := server.NewHandler(server.Options{Resolver: r, Metrics: m, Prometheus: p})

	ctx := context.Background()
	api := New(Deps{
		Cache:      c,
		Resolver:   r,
		DNSHandler: h,
		Metrics:    m,
		Prometheus: p,
		ReadyCheck: func() bool { return true },
	})
	router := api.Router(ctx)

	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status=%d want=200 body=%s", rr.Code, rr.Body.String())
	}
}

func TestPrometheusHandlerDisabledWhenPrometheusNotConfigured(t *testing.T) {
	c := cache.New(cache.Options{})
	r := resolver.New(resolver.DefaultConfig(), c)
	m := metrics.New()
	h := server.NewHandler(server.Options{Resolver: r, Metrics: m})

	ctx := context.Background()
	api := New(Deps{
		Cache:      c,
		Resolver:   r,
		DNSHandler: h,
		Metrics:    m,
		ReadyCheck: func() bool { return true },
	})
	router := api.Router(ctx)

	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != 404 {
		t.Fatalf("status=%d want=404 body=%s", rr.Code, rr.Body.String())
	}
}

func TestDoHHandlerGet(t *testing.T) {
	c := cache.New(cache.Options{})
	cfg := resolver.DefaultConfig()
	cfg.QNAMEMinimization = false
	r := resolver.New(cfg, c)
	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []resolver.ResolutionEvent, error) {
		return &protocol.Message{
			Header:  protocol.Header{QR: true, RCode: protocol.RCodeNoError},
			Answers: []protocol.ResourceRecord{{Name: qname, Type: qtype, Class: protocol.ClassIN, TTL: 60, Data: protocol.AData{Address: [4]byte{1, 2, 3, 4}}}},
		}, nil, nil
	})
	m := metrics.New()
	p := metrics.NewPrometheus()
	h := server.NewHandler(server.Options{Resolver: r, Metrics: m, Prometheus: p})

	ctx := context.Background()
	api := New(Deps{
		Cache:      c,
		Resolver:   r,
		DNSHandler: h,
		Metrics:    m,
		Prometheus: p,
		ReadyCheck: func() bool { return true },
	})
	router := api.Router(ctx)

	query := &protocol.Message{
		Header:    protocol.Header{ID: 42, RD: true},
		Questions: []protocol.Question{{Name: "example.com.", Type: protocol.TypeA, Class: protocol.ClassIN}},
	}
	wire, _ := protocol.Encode(query)
	enc := base64.RawURLEncoding.EncodeToString(wire)

	req := httptest.NewRequest("GET", "/dns-query?dns="+enc, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status=%d want=200 body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Content-Type") != "application/dns-message" {
		t.Fatalf("content-type=%s want=application/dns-message", rr.Header().Get("Content-Type"))
	}
}

func TestDoHHandlerMissingParam(t *testing.T) {
	ctx := context.Background()
	api := New(Deps{})
	router := api.Router(ctx)

	req := httptest.NewRequest("GET", "/dns-query", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != 400 {
		t.Fatalf("status=%d want=400", rr.Code)
	}
}

func TestDoHHandlerInvalidBase64(t *testing.T) {
	ctx := context.Background()
	api := New(Deps{})
	router := api.Router(ctx)

	req := httptest.NewRequest("GET", "/dns-query?dns=!!!invalid!!!", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != 400 {
		t.Fatalf("status=%d want=400", rr.Code)
	}
}

func TestBulkUsesRequestedQueryType(t *testing.T) {
	c := cache.New(cache.Options{})
	cfg := resolver.DefaultConfig()
	cfg.QNAMEMinimization = false
	r := resolver.New(cfg, c)
	seenTypes := make(chan uint16, 1)
	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []resolver.ResolutionEvent, error) {
		select {
		case seenTypes <- qtype:
		default:
		}
		return &protocol.Message{
			Header:  protocol.Header{QR: true, RCode: protocol.RCodeNoError},
			Answers: []protocol.ResourceRecord{{Name: qname, Type: qtype, Class: protocol.ClassIN, TTL: 60, Data: protocol.AAAAData{Address: [16]byte{0x20, 0x01}}}},
		}, nil, nil
	})
	m := metrics.New()
	h := server.NewHandler(server.Options{Resolver: r, Metrics: m})

	api := New(Deps{
		Cache:      c,
		Resolver:   r,
		DNSHandler: h,
		Metrics:    m,
		ReadyCheck: func() bool { return true },
	})
	router := api.Router(context.Background())

	req := httptest.NewRequest("GET", "/api/v1/bulk?queries=example.com&type=AAAA", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}

	select {
	case qtype := <-seenTypes:
		if qtype != protocol.TypeAAAA {
			t.Fatalf("expected AAAA query type, got %d", qtype)
		}
	default:
		t.Fatalf("expected resolver to be called")
	}
}

func TestParseQType(t *testing.T) {
	tests := []struct {
		input string
		want  uint16
	}{
		{"A", protocol.TypeA},
		{"AAAA", protocol.TypeAAAA},
		{"MX", protocol.TypeMX},
		{"NS", protocol.TypeNS},
		{"TXT", protocol.TypeTXT},
		{"PTR", protocol.TypePTR},
		{"SRV", protocol.TypeSRV},
		{"CAA", protocol.TypeCAA},
		{"CNAME", protocol.TypeCNAME},
		{"SOA", protocol.TypeSOA},
		{"DS", protocol.TypeDS},
		{"DNSKEY", protocol.TypeDNSKEY},
		{"RRSIG", protocol.TypeRRSIG},
		{"ANY", protocol.TypeANY},
		{"43", protocol.TypeDS},
		{"", protocol.TypeA},
		{"unknown", protocol.TypeA},
		{"aaaa", protocol.TypeAAAA},
	}
	for _, tc := range tests {
		got := parseQType(tc.input)
		if got != tc.want {
			t.Errorf("parseQType(%q)=%d want=%d", tc.input, got, tc.want)
		}
	}
}

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"1.1.1.1,8.8.8.8", 2},
		{"1.1.1.1", 1},
		{"", 0},
		{"  ,  ", 0},
		{"1.1.1.1, 8.8.8.8 , 9.9.9.9", 3},
	}
	for _, tc := range tests {
		got := splitCSV(tc.input)
		if len(got) != tc.want {
			t.Errorf("splitCSV(%q)=%d items want=%d", tc.input, len(got), tc.want)
		}
	}
}

func TestSplitBulkQueries(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"example.com,google.com", 2},
		{"example.com\ngoogle.com", 2},
		{"example.com,google.com\ncloudflare.com", 3},
		{"", 0},
		{"  ,  \n  ", 0},
	}
	for _, tc := range tests {
		got := splitBulkQueries(tc.input)
		if len(got) != tc.want {
			t.Errorf("splitBulkQueries(%q)=%d items want=%d", tc.input, len(got), tc.want)
		}
	}
}

func TestCompareHandler(t *testing.T) {
	c := cache.New(cache.Options{})
	cfg := resolver.DefaultConfig()
	cfg.QNAMEMinimization = false
	r := resolver.New(cfg, c)
	m := metrics.New()
	p := metrics.NewPrometheus()
	h := server.NewHandler(server.Options{Resolver: r, Metrics: m, Prometheus: p})

	ctx := context.Background()
	api := New(Deps{
		Cache:      c,
		Resolver:   r,
		DNSHandler: h,
		Metrics:    m,
		Prometheus: p,
		ReadyCheck: func() bool { return true },
	})
	router := api.Router(ctx)

	req := httptest.NewRequest("GET", "/api/v1/compare?q=example.com&server=8.8.8.8", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status=%d want=200 body=%s", rr.Code, rr.Body.String())
	}
}

func TestCompareHandlerInvalidParams(t *testing.T) {
	c := cache.New(cache.Options{})
	r := resolver.New(resolver.DefaultConfig(), c)
	m := metrics.New()
	p := metrics.NewPrometheus()
	h := server.NewHandler(server.Options{Resolver: r, Metrics: m, Prometheus: p})

	ctx := context.Background()
	api := New(Deps{
		Cache:      c,
		Resolver:   r,
		DNSHandler: h,
		Metrics:    m,
		Prometheus: p,
		ReadyCheck: func() bool { return true },
	})
	router := api.Router(ctx)

	req := httptest.NewRequest("GET", "/api/v1/compare", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != 400 {
		t.Fatalf("status=%d want=400", rr.Code)
	}
}

func TestResolveViaServer(t *testing.T) {
	c := cache.New(cache.Options{})
	cfg := resolver.DefaultConfig()
	cfg.QNAMEMinimization = false
	r := resolver.New(cfg, c)
	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []resolver.ResolutionEvent, error) {
		return &protocol.Message{
			Header:  protocol.Header{QR: true, RCode: protocol.RCodeNoError},
			Answers: []protocol.ResourceRecord{{Name: qname, Type: qtype, Class: protocol.ClassIN, TTL: 60, Data: protocol.AData{Address: [4]byte{1, 2, 3, 4}}}},
		}, nil, nil
	})
	m := metrics.New()
	p := metrics.NewPrometheus()
	h := server.NewHandler(server.Options{Resolver: r, Metrics: m, Prometheus: p})

	ctx := context.Background()
	api := New(Deps{
		Cache:      c,
		Resolver:   r,
		DNSHandler: h,
		Metrics:    m,
		Prometheus: p,
		ReadyCheck: func() bool { return true },
	})
	router := api.Router(ctx)

	req := httptest.NewRequest("GET", "/api/v1/resolve?q=example.com&type=A&server=8.8.8.8", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status=%d want=200 body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"query":"example.com"`) {
		t.Fatalf("expected query payload in response: %s", rr.Body.String())
	}
}
