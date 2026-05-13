package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAcceptWebSocketNonUpgradeRequest(t *testing.T) {
	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade", "h2c")
	w := httptest.NewRecorder()
	_, err := acceptWebSocket(w, req)
	if err == nil {
		t.Fatalf("expected error for non-websocket upgrade request")
	}
	if !strings.Contains(err.Error(), "not a websocket upgrade") {
		t.Fatalf("expected websocket upgrade error, got: %v", err)
	}
}

func TestAcceptWebSocketMissingKey(t *testing.T) {
	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	w := httptest.NewRecorder()
	_, err := acceptWebSocket(w, req)
	if err == nil {
		t.Fatalf("expected error for missing websocket key")
	}
	if !strings.Contains(err.Error(), "missing websocket key") {
		t.Fatalf("expected missing key error, got: %v", err)
	}
}

func TestAcceptWebSocketWrongVersion(t *testing.T) {
	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "12")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	w := httptest.NewRecorder()
	_, err := acceptWebSocket(w, req)
	if err == nil {
		t.Fatalf("expected error for wrong websocket version")
	}
	if !strings.Contains(err.Error(), "unsupported websocket version") {
		t.Fatalf("expected unsupported version error, got: %v", err)
	}
}

func TestAcceptWebSocketRejectsCrossOrigin(t *testing.T) {
	req := httptest.NewRequest("GET", "/ws", nil)
	req.Host = "resolver.example"
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	_, err := acceptWebSocket(w, req)
	if err == nil {
		t.Fatalf("expected cross-origin websocket rejection")
	}
	if !strings.Contains(err.Error(), "forbidden websocket origin") {
		t.Fatalf("expected origin rejection error, got: %v", err)
	}
}

func TestAcceptWebSocketRejectsNonGet(t *testing.T) {
	req := httptest.NewRequest("POST", "/ws", nil)
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	w := httptest.NewRecorder()
	_, err := acceptWebSocket(w, req)
	if err == nil {
		t.Fatalf("expected method rejection")
	}
	if !strings.Contains(err.Error(), "method not allowed") {
		t.Fatalf("expected method rejection error, got: %v", err)
	}
}

func TestWebSocketAcceptKey(t *testing.T) {
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	accept := websocketAccept(key)
	expected := "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	if accept != expected {
		t.Fatalf("accept=%s want=%s", accept, expected)
	}
}

func TestWebSocketAcceptKeyConsistency(t *testing.T) {
	key := "test-key-12345"
	accept1 := websocketAccept(key)
	accept2 := websocketAccept(key)
	if accept1 != accept2 {
		t.Fatalf("accept key not consistent: %s != %s", accept1, accept2)
	}
}

func TestWebSocketAcceptKeyDifferentInputs(t *testing.T) {
	key1 := "key-one"
	key2 := "key-two"
	accept1 := websocketAccept(key1)
	accept2 := websocketAccept(key2)
	if accept1 == accept2 {
		t.Fatalf("different keys should produce different accepts: %s == %s", accept1, accept2)
	}
}
