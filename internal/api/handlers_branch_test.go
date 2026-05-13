package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dnsresolver/internal/cache"
	"dnsresolver/internal/metrics"
	"dnsresolver/internal/protocol"
	"dnsresolver/internal/resolver"
	"dnsresolver/internal/server"
)

func TestResolveHandlerBranches(t *testing.T) {
	t.Run("method not allowed", func(t *testing.T) {
		api := New(Deps{})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/resolve?q=example.com", nil)
		rr := httptest.NewRecorder()
		api.resolve(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status=%d want=%d", rr.Code, http.StatusMethodNotAllowed)
		}
	})

	t.Run("missing query", func(t *testing.T) {
		api := New(Deps{})
		req := httptest.NewRequest(http.MethodGet, "/api/v1/resolve", nil)
		rr := httptest.NewRecorder()
		api.resolve(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status=%d want=%d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("trace and stale headers", func(t *testing.T) {
		res := resolver.New(resolver.DefaultConfig(), cache.New(cache.Options{}))
		res.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []resolver.ResolutionEvent, error) {
			return &protocol.Message{
				Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
				Answers: []protocol.ResourceRecord{{
					Name:  qname,
					Type:  qtype,
					Class: protocol.ClassIN,
					TTL:   60,
					Data:  protocol.AData{Address: [4]byte{1, 2, 3, 4}},
				}},
			}, []resolver.ResolutionEvent{{QueryID: queryID, Query: qname, QueryType: protocol.TypeToString(qtype), StepType: "cache_hit", Success: true}}, nil
		})
		// Prime cache, then force stale cache hit on the second resolve.
		if _, err := res.Resolve(context.Background(), "stale.example", protocol.TypeA); err != nil {
			t.Fatalf("prime cache: %v", err)
		}
		api := New(Deps{Resolver: res})
		req := httptest.NewRequest(http.MethodGet, "/api/v1/resolve?q=stale.example&type=A&trace=1", nil)
		rr := httptest.NewRecorder()
		api.resolve(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusOK, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"trace":[`) {
			t.Fatalf("expected trace payload: %s", rr.Body.String())
		}
	})
}

func TestHistoryByIDBranches(t *testing.T) {
	c := cache.New(cache.Options{})
	cfg := resolver.DefaultConfig()
	cfg.QNAMEMinimization = false
	res := resolver.New(cfg, c)
	res.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []resolver.ResolutionEvent, error) {
		return &protocol.Message{
			Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
			Answers: []protocol.ResourceRecord{{
				Name:  qname,
				Type:  qtype,
				Class: protocol.ClassIN,
				TTL:   60,
				Data:  protocol.AData{Address: [4]byte{1, 2, 3, 4}},
			}},
		}, []resolver.ResolutionEvent{{QueryID: queryID, Query: qname, QueryType: protocol.TypeToString(qtype), StepType: "answer", Success: true}}, nil
	})
	result, err := res.Resolve(context.Background(), "history.example", protocol.TypeA)
	if err != nil {
		t.Fatalf("resolve history entry: %v", err)
	}

	api := New(Deps{Resolver: res})

	t.Run("missing id", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/history/", nil)
		rr := httptest.NewRecorder()
		api.historyByID(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status=%d want=%d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("detail response includes entry metadata", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/history/"+result.QueryID, nil)
		rr := httptest.NewRecorder()
		api.historyByID(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusOK, rr.Body.String())
		}
		for _, want := range []string{`"query_id":"`, `"query":"history.example."`, `"trace":[`} {
			if !strings.Contains(rr.Body.String(), want) {
				t.Fatalf("expected %s in response: %s", want, rr.Body.String())
			}
		}
	})
}

func TestSettingsAndReverseLookupBranches(t *testing.T) {
	c := cache.New(cache.Options{})
	res := resolver.New(resolver.DefaultConfig(), c)
	res.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []resolver.ResolutionEvent, error) {
		return &protocol.Message{
			Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
			Answers: []protocol.ResourceRecord{{
				Name:  qname,
				Type:  qtype,
				Class: protocol.ClassIN,
				TTL:   60,
				Data:  protocol.PTRData{Name: "localhost."},
			}},
		}, nil, nil
	})
	h := server.NewHandler(server.Options{Resolver: res, Metrics: metrics.New(), Prometheus: metrics.NewPrometheus()})
	api := New(Deps{
		Resolver:   res,
		Cache:      c,
		DNSHandler: h,
		Metrics:    metrics.New(),
		Settings:   NewRuntimeSettings(map[string]any{"version": "test"}),
	})

	t.Run("settings get", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/settings", nil)
		rr := httptest.NewRecorder()
		api.settings(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusOK, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"blocklist"`) {
			t.Fatalf("expected blocklist in settings response: %s", rr.Body.String())
		}
	})

	t.Run("settings invalid json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/settings", strings.NewReader("{invalid"))
		rr := httptest.NewRecorder()
		api.settings(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status=%d want=%d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("settings invalid blocklist array", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/settings", strings.NewReader(`{"blocklist":[1]}`))
		rr := httptest.NewRecorder()
		api.settings(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusBadRequest, rr.Body.String())
		}
	})

	t.Run("settings method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/settings", nil)
		rr := httptest.NewRecorder()
		api.settings(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status=%d want=%d", rr.Code, http.StatusMethodNotAllowed)
		}
	})

	t.Run("reverse lookup missing ip", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/reverse", nil)
		rr := httptest.NewRecorder()
		api.reverseLookup(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status=%d want=%d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("reverse lookup success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/reverse?ip=127.0.0.1", nil)
		rr := httptest.NewRecorder()
		api.reverseLookup(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusOK, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"reverse_name":"1.0.0.127.in-addr.arpa."`) {
			t.Fatalf("unexpected reverse payload: %s", rr.Body.String())
		}
	})
}

func TestDoHPostAndErrors(t *testing.T) {
	c := cache.New(cache.Options{})
	res := resolver.New(resolver.DefaultConfig(), c)
	res.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []resolver.ResolutionEvent, error) {
		return &protocol.Message{
			Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
			Answers: []protocol.ResourceRecord{{
				Name:  qname,
				Type:  qtype,
				Class: protocol.ClassIN,
				TTL:   60,
				Data:  protocol.AData{Address: [4]byte{1, 2, 3, 4}},
			}},
		}, nil, nil
	})
	h := server.NewHandler(server.Options{Resolver: res, Metrics: metrics.New(), Prometheus: metrics.NewPrometheus()})
	api := New(Deps{Resolver: res, DNSHandler: h})
	msg := &protocol.Message{
		Header:    protocol.Header{ID: 88, RD: true},
		Questions: []protocol.Question{{Name: "post.example.", Type: protocol.TypeA, Class: protocol.ClassIN}},
	}
	wire, err := protocol.Encode(msg)
	if err != nil {
		t.Fatalf("encode doh request: %v", err)
	}

	t.Run("post success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(wire))
		req.Header.Set("Content-Type", "application/dns-message")
		req.RemoteAddr = (&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5300}).String()
		rr := httptest.NewRecorder()
		api.doh(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusOK, rr.Body.String())
		}
	})

	t.Run("unsupported media type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(wire))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		api.doh(rr, req)
		if rr.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("status=%d want=%d", rr.Code, http.StatusUnsupportedMediaType)
		}
	})

	t.Run("method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/dns-query", nil)
		rr := httptest.NewRecorder()
		api.doh(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status=%d want=%d", rr.Code, http.StatusMethodNotAllowed)
		}
	})

	t.Run("get with bad upstream packet", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+base64.RawURLEncoding.EncodeToString([]byte("bad")), nil)
		rr := httptest.NewRecorder()
		api.doh(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d want=%d body=%q", rr.Code, http.StatusOK, rr.Body.Bytes())
		}
		if ct := rr.Header().Get("Content-Type"); ct != "application/dns-message" {
			t.Fatalf("content-type=%s want=application/dns-message", ct)
		}
	})
}

func TestCacheHandlerMethodBranches(t *testing.T) {
	api := New(Deps{Cache: cache.New(cache.Options{})})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/cache", nil)
	rr := httptest.NewRecorder()
	api.cache(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusMethodNotAllowed)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/cache/", nil)
	rr = httptest.NewRecorder()
	api.cacheKey(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusMethodNotAllowed)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/cache/", nil)
	rr = httptest.NewRecorder()
	api.cacheKey(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusBadRequest)
	}
}

func TestParseRemoteAddrFallback(t *testing.T) {
	addr := parseRemoteAddr("invalid")
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected tcp addr, got %T", addr)
	}
	if !tcpAddr.IP.Equal(net.IPv4zero) || tcpAddr.Port != 0 {
		t.Fatalf("unexpected fallback addr: %v", tcpAddr)
	}
}

func TestResolveViaServerInvalidServerIP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := resolveViaServer(ctx, "not-an-ip", "example.com", protocol.TypeA); err == nil {
		t.Fatal("expected invalid server IP error")
	}
}
