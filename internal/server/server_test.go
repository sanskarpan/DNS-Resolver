package server

import (
	"os"
	"testing"
)

func TestNewUDPServerDefaultWorkers(t *testing.T) {
	h := NewHandler(Options{})
	srv := NewUDPServer("127.0.0.1:0", h, 0)
	if srv == nil {
		t.Fatalf("expected server")
	}
	if srv.workers != 1000 {
		t.Fatalf("workers=%d want=1000", srv.workers)
	}
}

func TestNewUDPServerCustomWorkers(t *testing.T) {
	h := NewHandler(Options{})
	srv := NewUDPServer("127.0.0.1:0", h, 64)
	if srv.workers != 64 {
		t.Fatalf("workers=%d want=64", srv.workers)
	}
}

func TestNewTCPServerDefault(t *testing.T) {
	h := NewHandler(Options{})
	srv := NewTCPServer("127.0.0.1:0", h, 0)
	if srv == nil {
		t.Fatalf("expected server")
	}
	if srv.maxConn != 500 {
		t.Fatalf("maxConn=%d want=500", srv.maxConn)
	}
}

func TestNewTCPServerCustomMaxConn(t *testing.T) {
	h := NewHandler(Options{})
	srv := NewTCPServer("127.0.0.1:0", h, 100)
	if srv.maxConn != 100 {
		t.Fatalf("maxConn=%d want=100", srv.maxConn)
	}
}

func TestNewDoTServerAutoGenerate(t *testing.T) {
	h := NewHandler(Options{})
	tmpDir := t.TempDir()
	certPath := tmpDir + "/cert.pem"
	keyPath := tmpDir + "/key.pem"
	srv, err := NewDoTServer("127.0.0.1:0", h, 100, certPath, keyPath, true)
	if err != nil {
		t.Fatalf("new dot server: %v", err)
	}
	if srv == nil {
		t.Fatalf("expected server")
	}
	defer os.Remove(certPath)
	defer os.Remove(keyPath)
}

func TestNewDoTServerWithCertFiles(t *testing.T) {
	h := NewHandler(Options{})
	srv, err := NewDoTServer("127.0.0.1:0", h, 100, "/nonexistent/cert.pem", "/nonexistent/key.pem", false)
	if err == nil {
		t.Fatalf("expected error for nonexistent cert files")
	}
	if srv != nil {
		t.Fatalf("expected nil server on error")
	}
}

func TestLocalAddrBeforeStart(t *testing.T) {
	h := NewHandler(Options{})
	srv := NewUDPServer("127.0.0.1:0", h, 16)
	if srv.LocalAddr() != nil {
		t.Fatalf("expected nil before start")
	}
}

func TestTCPLocalAddrBeforeStart(t *testing.T) {
	h := NewHandler(Options{})
	srv := NewTCPServer("127.0.0.1:0", h, 16)
	if srv.LocalAddr() != nil {
		t.Fatalf("expected nil before start")
	}
}
