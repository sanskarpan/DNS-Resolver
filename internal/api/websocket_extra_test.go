package api

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dnsresolver/internal/cache"
	"dnsresolver/internal/metrics"
	"dnsresolver/internal/protocol"
	"dnsresolver/internal/resolver"
	"dnsresolver/internal/server"
)

func TestAcceptWebSocketSuccessAndWriteFrame(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	w := &hijackableRecorder{conn: serverConn}
	resultCh := make(chan *wsConn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := acceptWebSocket(w, req)
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- conn
	}()

	reader := bufio.NewReader(clientConn)
	handshake := readHTTPHandshake(t, reader)
	if !strings.Contains(handshake, "101 Switching Protocols") {
		t.Fatalf("expected successful websocket handshake, got %s", handshake)
	}
	if !strings.Contains(handshake, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") {
		t.Fatalf("unexpected websocket accept header: %s", handshake)
	}

	select {
	case err := <-errCh:
		t.Fatalf("accept websocket: %v", err)
	case conn := <-resultCh:
		defer conn.Close()
		go func() {
			_ = conn.WriteJSON(map[string]string{"hello": "world"})
		}()
		opcode, payload := readWSFrame(t, clientConn, reader)
		if opcode != 0x1 {
			t.Fatalf("expected text frame opcode, got %d", opcode)
		}
		if string(payload) != `{"hello":"world"}` {
			t.Fatalf("unexpected payload %s", payload)
		}

		go func() {
			_ = conn.WritePing()
		}()
		opcode, payload = readWSFrame(t, clientConn, reader)
		if opcode != 0x9 {
			t.Fatalf("expected ping opcode, got %d", opcode)
		}
		if len(payload) != 0 {
			t.Fatalf("expected empty ping payload, got %q", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for websocket accept result")
	}
}

func TestWebSocketHandlersStreamEvents(t *testing.T) {
	c := cache.New(cache.Options{})
	cfg := resolver.DefaultConfig()
	cfg.QNAMEMinimization = false
	res := resolver.New(cfg, c)
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
			}, []resolver.ResolutionEvent{{
				QueryID:   queryID,
				StepType:  "answer",
				Query:     qname,
				QueryType: protocol.TypeToString(qtype),
				Success:   true,
			}}, nil
	})
	m := metrics.New()
	p := metrics.NewPrometheus()
	h := server.NewHandler(server.Options{Resolver: res, Metrics: m, Prometheus: p})
	api := New(Deps{Resolver: res, DNSHandler: h, Metrics: m, Prometheus: p, ReadyCheck: func() bool { return true }})

	t.Run("trace", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()
		req := websocketRequest("/ws/trace")
		w := &hijackableRecorder{conn: serverConn}
		done := make(chan struct{})
		go func() {
			api.wsTrace(ctx)(w, req)
			close(done)
		}()

		reader := bufio.NewReader(clientConn)
		_ = readHTTPHandshake(t, reader)
		time.Sleep(20 * time.Millisecond)
		if _, err := res.Resolve(context.Background(), "trace.example", protocol.TypeA); err != nil {
			t.Fatalf("resolve trace event: %v", err)
		}
		_, payload := readWSFrame(t, clientConn, reader)
		if !strings.Contains(string(payload), `"query":"trace.example."`) {
			t.Fatalf("unexpected trace payload: %s", payload)
		}
		cancel()
		_ = clientConn.Close()
		<-done
	})

	t.Run("queries", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()
		req := websocketRequest("/ws/queries")
		w := &hijackableRecorder{conn: serverConn}
		done := make(chan struct{})
		go func() {
			api.wsQueries(ctx)(w, req)
			close(done)
		}()

		reader := bufio.NewReader(clientConn)
		_ = readHTTPHandshake(t, reader)
		time.Sleep(20 * time.Millisecond)
		query := &protocol.Message{
			Header:    protocol.Header{ID: 12, RD: true},
			Questions: []protocol.Question{{Name: "query.example.", Type: protocol.TypeA, Class: protocol.ClassIN}},
		}
		wire, err := protocol.Encode(query)
		if err != nil {
			t.Fatalf("encode query: %v", err)
		}
		if _, _, err := h.HandlePacket(context.Background(), wire, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53000}, "udp"); err != nil {
			t.Fatalf("handle packet: %v", err)
		}
		_, payload := readWSFrame(t, clientConn, reader)
		if !strings.Contains(string(payload), `"domain":"query.example."`) {
			t.Fatalf("unexpected query payload: %s", payload)
		}
		cancel()
		_ = clientConn.Close()
		<-done
	})

	t.Run("metrics", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()
		req := websocketRequest("/ws/metrics")
		w := &hijackableRecorder{conn: serverConn}
		done := make(chan struct{})
		go func() {
			api.wsMetrics(ctx)(w, req)
			close(done)
		}()

		reader := bufio.NewReader(clientConn)
		_ = readHTTPHandshake(t, reader)
		_, payload := readWSFrame(t, clientConn, reader)
		var msg map[string]any
		if err := json.Unmarshal(payload, &msg); err != nil {
			t.Fatalf("unmarshal metrics payload: %v", err)
		}
		if _, ok := msg["total_queries"]; !ok {
			t.Fatalf("expected total_queries in metrics payload: %v", msg)
		}
		cancel()
		_ = clientConn.Close()
		<-done
	})
}

func TestRouterMountsPprofWhenEnabled(t *testing.T) {
	t.Parallel()

	api := New(Deps{PPROFEnabled: true})
	router := api.Router(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
}

type hijackableRecorder struct {
	header http.Header
	conn   net.Conn
}

func (w *hijackableRecorder) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *hijackableRecorder) Write(b []byte) (int, error) {
	return len(b), nil
}

func (w *hijackableRecorder) WriteHeader(statusCode int) {}

func (w *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	rw := bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn))
	return w.conn, rw, nil
}

func websocketRequest(path string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	return req
}

func readHTTPHandshake(t *testing.T, reader *bufio.Reader) string {
	t.Helper()
	var out strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read handshake: %v", err)
		}
		out.WriteString(line)
		if line == "\r\n" {
			return out.String()
		}
	}
}

func readWSFrame(t *testing.T, conn net.Conn, reader *bufio.Reader) (byte, []byte) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	opcode := header[0] & 0x0f
	length := int(header[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(reader, ext[:]); err != nil {
			t.Fatalf("read extended frame length: %v", err)
		}
		length = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(reader, ext[:]); err != nil {
			t.Fatalf("read 64-bit frame length: %v", err)
		}
		length = int(binary.BigEndian.Uint64(ext[:]))
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		t.Fatalf("read frame payload: %v", err)
	}
	return opcode, payload
}
