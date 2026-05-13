package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dnsresolver/internal/protocol"
	"dnsresolver/internal/resolver"
)

func TestParseQTypeSupportsSOAAndNumeric(t *testing.T) {
	t.Parallel()

	if got := parseQType("SOA"); got != protocol.TypeSOA {
		t.Fatalf("parseQType(SOA)=%d want=%d", got, protocol.TypeSOA)
	}
	if got := parseQType("43"); got != protocol.TypeDS {
		t.Fatalf("parseQType(43)=%d want=%d", got, protocol.TypeDS)
	}
}

func TestNormalizeServersDropsInvalidDuplicates(t *testing.T) {
	t.Parallel()

	got := normalizeServers([]string{"1.1.1.1", "1.1.1.1", "bad", "8.8.8.8"})
	if len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "8.8.8.8" {
		t.Fatalf("unexpected normalized servers: %#v", got)
	}
}

func TestValidateExternalResponseRejectsMismatches(t *testing.T) {
	t.Parallel()

	query := &protocol.Message{
		Header:    protocol.Header{ID: 10, RD: true},
		Questions: []protocol.Question{{Name: "example.com.", Type: protocol.TypeA, Class: protocol.ClassIN}},
	}

	if err := validateExternalResponse(query, &protocol.Message{}); err == nil {
		t.Fatal("expected validation error for empty response")
	}
	if err := validateExternalResponse(query, &protocol.Message{
		Header:    protocol.Header{ID: 11, QR: true},
		Questions: []protocol.Question{{Name: "example.com.", Type: protocol.TypeA, Class: protocol.ClassIN}},
	}); err == nil {
		t.Fatal("expected validation error for id mismatch")
	}
	if err := validateExternalResponse(query, &protocol.Message{
		Header:    protocol.Header{ID: 10, QR: true},
		Questions: []protocol.Question{{Name: "evil.com.", Type: protocol.TypeA, Class: protocol.ClassIN}},
	}); err == nil {
		t.Fatal("expected validation error for question mismatch")
	}
}

func TestUnavailableDepsReturn503(t *testing.T) {
	t.Parallel()

	a := New(Deps{})
	router := a.Router(context.Background())

	tests := []struct {
		path string
		want int
	}{
		{path: "/api/v1/metrics", want: http.StatusServiceUnavailable},
		{path: "/api/v1/cache", want: http.StatusServiceUnavailable},
		{path: "/api/v1/history", want: http.StatusServiceUnavailable},
		{path: "/api/v1/rootservers", want: http.StatusServiceUnavailable},
		{path: "/api/v1/security/stats", want: http.StatusServiceUnavailable},
	}

	for _, tc := range tests {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != tc.want {
			t.Fatalf("%s status=%d want=%d body=%s", tc.path, rr.Code, tc.want, rr.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/dns-query", strings.NewReader("abc"))
	req.Header.Set("Content-Type", "application/dns-message")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("/dns-query status=%d want=%d body=%s", rr.Code, http.StatusServiceUnavailable, rr.Body.String())
	}
}

func TestCompareAndBulkMethodGuards(t *testing.T) {
	t.Parallel()

	a := New(Deps{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/compare?q=example.com", nil)
	rr := httptest.NewRecorder()
	a.compare(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("compare status=%d want=%d", rr.Code, http.StatusMethodNotAllowed)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/bulk?queries=example.com", nil)
	rr = httptest.NewRecorder()
	a.bulk(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("bulk status=%d want=%d", rr.Code, http.StatusMethodNotAllowed)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/reverse?ip=127.0.0.1", nil)
	rr = httptest.NewRecorder()
	a.reverseLookup(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("reverse status=%d want=%d", rr.Code, http.StatusMethodNotAllowed)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/metrics", nil)
	rr = httptest.NewRecorder()
	a.metrics(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("metrics status=%d want=%d", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestWebSocketUnavailableDepsReturn503(t *testing.T) {
	t.Parallel()

	a := New(Deps{})
	req := httptest.NewRequest(http.MethodGet, "/ws/trace", nil)

	rr := httptest.NewRecorder()
	a.wsTrace(context.Background())(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("wsTrace status=%d want=%d", rr.Code, http.StatusServiceUnavailable)
	}

	rr = httptest.NewRecorder()
	a.wsMetrics(context.Background())(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("wsMetrics status=%d want=%d", rr.Code, http.StatusServiceUnavailable)
	}

	rr = httptest.NewRecorder()
	a.wsQueries(context.Background())(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("wsQueries status=%d want=%d", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestHistoryByIDMissingReturns404(t *testing.T) {
	t.Parallel()

	a := New(Deps{Resolver: resolver.New(resolver.DefaultConfig(), nil)})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/history/missing", nil)
	rr := httptest.NewRecorder()
	a.historyByID(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusNotFound, rr.Body.String())
	}
}
