package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ilogger "dnsresolver/internal/logger"
)

func TestMiddlewarePropagatesTraceIDToLogs(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := ilogger.NewWithWriter(&buf, "info", "json")

	a := New(Deps{Logger: l, ReadyCheck: func() bool { return true }})
	router := a.Router(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health/live", nil)
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	out := buf.String()
	if !strings.Contains(out, `"trace_id":"4bf92f3577b34da6a3ce929d0e0e4736"`) {
		t.Fatalf("expected trace_id in logs, got: %s", out)
	}
}

func TestExtractTraceID(t *testing.T) {
	t.Parallel()
	if got := extractTraceID("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"); got == "" {
		t.Fatalf("expected valid trace id")
	}
	if got := extractTraceID("not-a-traceparent"); got != "" {
		t.Fatalf("expected invalid traceparent to return empty")
	}
	if got := extractTraceID("00-00000000000000000000000000000000-00f067aa0ba902b7-01"); got != "" {
		t.Fatalf("expected zero trace id to be rejected")
	}
}

func TestMiddlewareSetsTraceHeadersAndCSP(t *testing.T) {
	t.Parallel()

	a := New(Deps{ReadyCheck: func() bool { return true }})
	router := a.Router(context.Background())

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/health/live", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusNoContent)
	}
	if got := rr.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Traceparent") || !strings.Contains(got, "Tracestate") {
		t.Fatalf("unexpected allow headers: %q", got)
	}
	if got := rr.Header().Get("Content-Security-Policy"); !strings.Contains(got, "connect-src 'self' ws: wss:") {
		t.Fatalf("unexpected csp: %q", got)
	}
}
