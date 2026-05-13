package main

import (
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestRunHealthcheckReady(t *testing.T) {
	addr, shutdown := startHealthcheckServer(t, http.StatusOK)
	defer shutdown()

	t.Setenv("HTTP_PORT", strconv.Itoa(addr.Port))
	if code := runHealthcheck(); code != 0 {
		t.Fatalf("runHealthcheck=%d want=0", code)
	}
}

func TestRunHealthcheckNotReady(t *testing.T) {
	addr, shutdown := startHealthcheckServer(t, http.StatusServiceUnavailable)
	defer shutdown()

	t.Setenv("HTTP_PORT", strconv.Itoa(addr.Port))
	if code := runHealthcheck(); code == 0 {
		t.Fatalf("expected non-zero healthcheck code")
	}
}

func startHealthcheckServer(t *testing.T, status int) (*net.TCPAddr, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/health/ready" {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(status)
		}),
		ReadHeaderTimeout: time.Second,
	}
	go func() {
		_ = srv.Serve(ln)
	}()
	return ln.Addr().(*net.TCPAddr), func() {
		_ = srv.Close()
	}
}
