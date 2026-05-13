package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmbeddedFrontendServedAtRoot(t *testing.T) {
	t.Parallel()
	a := New(Deps{ReadyCheck: func() bool { return true }})
	router := a.Router(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "DNS Resolver") {
		t.Fatalf("expected embedded frontend content")
	}
}

func TestEmbeddedFrontendSPAPathFallback(t *testing.T) {
	t.Parallel()
	a := New(Deps{ReadyCheck: func() bool { return true }})
	router := a.Router(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/settings", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "DNS Resolver") {
		t.Fatalf("expected SPA fallback to embedded index.html")
	}
}

func TestEmbeddedFrontendMissingAssetReturns404(t *testing.T) {
	t.Parallel()
	a := New(Deps{ReadyCheck: func() bool { return true }})
	router := a.Router(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/js/does-not-exist.js", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusNotFound, rr.Body.String())
	}
}
