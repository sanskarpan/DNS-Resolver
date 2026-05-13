package server

import (
	"context"
	"net"
	"testing"
	"time"

	"dnsresolver/internal/protocol"
)

func TestUDPServerServesDNSQuery(t *testing.T) {
	t.Parallel()

	h := testNetworkHandler()
	srv := NewUDPServer("127.0.0.1:0", h, 2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("start udp server: %v", err)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer shutdownCancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	conn, err := net.Dial("udp", srv.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial udp server: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	query := &protocol.Message{
		Header:    protocol.Header{ID: 202, RD: true},
		Questions: []protocol.Question{{Name: "example.com.", Type: protocol.TypeA, Class: protocol.ClassIN}},
	}
	wire, err := protocol.Encode(query)
	if err != nil {
		t.Fatalf("encode query: %v", err)
	}
	if _, err := conn.Write(wire); err != nil {
		t.Fatalf("write query: %v", err)
	}

	buf := make([]byte, protocol.MaxUDPPacketLen)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp, err := protocol.Decode(buf[:n])
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Header.RCode != protocol.RCodeNoError {
		t.Fatalf("expected NOERROR, got %s", protocol.RCodeToString(resp.Header.RCode))
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("expected one answer, got %d", len(resp.Answers))
	}
}

func TestRefusedResponseFallbackPreservesID(t *testing.T) {
	t.Parallel()

	respWire, err := refusedResponse([]byte{0x12, 0x34, 0xff})
	if err != nil {
		t.Fatalf("refusedResponse fallback: %v", err)
	}
	resp, err := protocol.Decode(respWire)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Header.ID != 0x1234 {
		t.Fatalf("id=%d want=%d", resp.Header.ID, 0x1234)
	}
	if resp.Header.RCode != protocol.RCodeRefused {
		t.Fatalf("expected REFUSED, got %s", protocol.RCodeToString(resp.Header.RCode))
	}
}

func TestRefusedResponsePreservesQuestionAndFlags(t *testing.T) {
	t.Parallel()

	query := &protocol.Message{
		Header: protocol.Header{
			ID:     55,
			RD:     true,
			Opcode: 2,
		},
		Questions: []protocol.Question{{
			Name:  "example.net.",
			Type:  protocol.TypeAAAA,
			Class: protocol.ClassIN,
		}},
	}
	wire, err := protocol.Encode(query)
	if err != nil {
		t.Fatalf("encode query: %v", err)
	}
	respWire, err := refusedResponse(wire)
	if err != nil {
		t.Fatalf("refusedResponse valid query: %v", err)
	}
	resp, err := protocol.Decode(respWire)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Header.ID != query.Header.ID {
		t.Fatalf("id=%d want=%d", resp.Header.ID, query.Header.ID)
	}
	if !resp.Header.RD {
		t.Fatalf("expected RD preserved")
	}
	if resp.Header.Opcode != query.Header.Opcode {
		t.Fatalf("opcode=%d want=%d", resp.Header.Opcode, query.Header.Opcode)
	}
	if len(resp.Questions) != 1 || resp.Questions[0].Name != "example.net." || resp.Questions[0].Type != protocol.TypeAAAA {
		t.Fatalf("unexpected questions: %#v", resp.Questions)
	}
	if resp.Header.RCode != protocol.RCodeRefused {
		t.Fatalf("expected REFUSED, got %s", protocol.RCodeToString(resp.Header.RCode))
	}
}
