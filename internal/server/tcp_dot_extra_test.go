package server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"dnsresolver/internal/cache"
	"dnsresolver/internal/metrics"
	"dnsresolver/internal/protocol"
	"dnsresolver/internal/resolver"
)

func TestTCPServerServesDNSQuery(t *testing.T) {
	t.Parallel()

	h := testNetworkHandler()
	srv := NewTCPServer("127.0.0.1:0", h, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("start tcp server: %v", err)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer shutdownCancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	resp := roundTripTCPQuery(t, srv.LocalAddr().String(), nil)
	if resp.Header.RCode != protocol.RCodeNoError {
		t.Fatalf("expected NOERROR, got %s", protocol.RCodeToString(resp.Header.RCode))
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("expected one answer, got %d", len(resp.Answers))
	}
}

func TestDoTServerServesDNSQueryAndShutsDown(t *testing.T) {
	t.Parallel()

	h := testNetworkHandler()
	tmpDir := t.TempDir()
	srv, err := NewDoTServer("127.0.0.1:0", h, 8, filepath.Join(tmpDir, "cert.pem"), filepath.Join(tmpDir, "key.pem"), true)
	if err != nil {
		t.Fatalf("new dot server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("start dot server: %v", err)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer shutdownCancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	resp := roundTripTCPQuery(t, srv.tcp.LocalAddr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if resp.Header.RCode != protocol.RCodeNoError {
		t.Fatalf("expected NOERROR over DoT, got %s", protocol.RCodeToString(resp.Header.RCode))
	}
}

func testNetworkHandler() *Handler {
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
		}, nil, nil
	})
	return NewHandler(Options{Resolver: res, Metrics: metrics.New(), Prometheus: metrics.NewPrometheus()})
}

func roundTripTCPQuery(t *testing.T, addr string, tlsCfg *tls.Config) *protocol.Message {
	t.Helper()

	var (
		conn net.Conn
		err  error
	)
	if tlsCfg != nil {
		conn, err = tls.Dial("tcp", addr, tlsCfg)
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	query := &protocol.Message{
		Header:    protocol.Header{ID: 101, RD: true},
		Questions: []protocol.Question{{Name: "example.com.", Type: protocol.TypeA, Class: protocol.ClassIN}},
	}
	wire, err := protocol.Encode(query)
	if err != nil {
		t.Fatalf("encode query: %v", err)
	}

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(wire)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		t.Fatalf("write query length: %v", err)
	}
	if _, err := conn.Write(wire); err != nil {
		t.Fatalf("write query: %v", err)
	}
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Fatalf("read response length: %v", err)
	}

	respWire := make([]byte, int(binary.BigEndian.Uint16(lenBuf[:])))
	if _, err := io.ReadFull(conn, respWire); err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp, err := protocol.Decode(respWire)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}
