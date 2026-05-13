package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadyEndpointReflectsReadinessState(t *testing.T) {
	a := New(Deps{ReadyCheck: func() bool { return false }})
	router := a.Router(nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health/ready", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when not ready, got %d", rr.Code)
	}

	a2 := New(Deps{ReadyCheck: func() bool { return true }})
	router2 := a2.Router(nil)
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/health/ready", nil)
	rr2 := httptest.NewRecorder()
	router2.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("expected 200 when ready, got %d", rr2.Code)
	}
}

func TestLiveEndpointAlwaysOK(t *testing.T) {
	a := New(Deps{})
	router := a.Router(nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health/live", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for live endpoint, got %d", rr.Code)
	}
}
