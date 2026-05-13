package server

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"dnsresolver/internal/cache"
	"dnsresolver/internal/metrics"
	"dnsresolver/internal/protocol"
	"dnsresolver/internal/resolver"
)

func TestTCPConnectionLimitReturnsREFUSED(t *testing.T) {
	t.Parallel()

	res := resolver.New(resolver.DefaultConfig(), cache.New(cache.Options{}))
	res.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []resolver.ResolutionEvent, error) {
		return &protocol.Message{
			Header:  protocol.Header{QR: true, RCode: protocol.RCodeNoError},
			Answers: []protocol.ResourceRecord{{Name: qname, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 30, Data: protocol.AData{Address: [4]byte{1, 1, 1, 1}}}},
		}, nil, nil
	})
	h := NewHandler(Options{Resolver: res, Metrics: metrics.New(), Prometheus: metrics.NewPrometheus()})

	srv := NewTCPServer("127.0.0.1:0", h, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Skipf("sandbox does not allow listening sockets: %v", err)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer shutdownCancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	addr := srv.LocalAddr().String()
	conn1, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial conn1: %v", err)
	}
	defer conn1.Close()
	// Keep connection 1 open and idle to occupy the only slot.
	_ = conn1.SetDeadline(time.Now().Add(5 * time.Second))

	conn2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial conn2: %v", err)
	}
	defer conn2.Close()
	_ = conn2.SetDeadline(time.Now().Add(5 * time.Second))

	query := &protocol.Message{
		Header:    protocol.Header{ID: 77, RD: true},
		Questions: []protocol.Question{{Name: "limit.example.", Type: protocol.TypeA, Class: protocol.ClassIN}},
	}
	wire, err := protocol.Encode(query)
	if err != nil {
		t.Fatalf("encode query: %v", err)
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(wire)))
	if _, err := conn2.Write(lenBuf[:]); err != nil {
		t.Fatalf("write len: %v", err)
	}
	if _, err := conn2.Write(wire); err != nil {
		t.Fatalf("write query: %v", err)
	}
	if _, err := io.ReadFull(conn2, lenBuf[:]); err != nil {
		t.Fatalf("read resp len: %v", err)
	}
	sz := int(binary.BigEndian.Uint16(lenBuf[:]))
	respWire := make([]byte, sz)
	if _, err := io.ReadFull(conn2, respWire); err != nil {
		t.Fatalf("read resp payload: %v", err)
	}
	resp, err := protocol.Decode(respWire)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Header.RCode != protocol.RCodeRefused {
		t.Fatalf("expected REFUSED when max tcp conn reached, got=%s", protocol.RCodeToString(resp.Header.RCode))
	}
}
