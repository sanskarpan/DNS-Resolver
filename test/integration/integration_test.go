package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"dnsresolver/internal/api"
	"dnsresolver/internal/cache"
	"dnsresolver/internal/metrics"
	"dnsresolver/internal/protocol"
	"dnsresolver/internal/resolver"
	"dnsresolver/internal/server"
)

func TestIntegrationDNSAndAPI(t *testing.T) {
	port := reservePort(t)
	dnsAddr := "127.0.0.1:" + strconv.Itoa(port)

	cfg := resolver.DefaultConfig()
	cfg.QNAMEMinimization = false
	c := cache.New(cache.Options{})
	r := resolver.New(cfg, c)
	r.SetQueryFunc(mockQueryFunc())
	m := metrics.New()
	p := metrics.NewPrometheus()
	h := server.NewHandler(server.Options{Resolver: r, MaxUDPSize: 4096, Metrics: m, Prometheus: p, RRLEnabled: false})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	udp := server.NewUDPServer(dnsAddr, h, 32)
	tcp := server.NewTCPServer(dnsAddr, h, 64)
	if err := udp.Start(ctx); err != nil {
		t.Fatalf("udp start: %v", err)
	}
	if err := tcp.Start(ctx); err != nil {
		t.Fatalf("tcp start: %v", err)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = udp.Shutdown(shutdownCtx)
		_ = tcp.Shutdown(shutdownCtx)
	}()

	apiServer := &http.Server{Addr: "127.0.0.1:0", Handler: api.New(api.Deps{Resolver: r, Cache: c, DNSHandler: h, Metrics: m, Prometheus: p, ReadyCheck: func() bool { return true }}).Router(ctx)}
	ln, err := net.Listen("tcp", apiServer.Addr)
	if err != nil {
		t.Skipf("sandbox does not allow listening sockets: %v", err)
	}
	go func() { _ = apiServer.Serve(ln) }()
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = apiServer.Shutdown(shutdownCtx)
	}()
	apiBase := "http://" + ln.Addr().String()

	assertDNSResponse(t, dnsAddr, "example.com.", protocol.TypeA, protocol.RCodeNoError, true)
	assertDNSResponse(t, dnsAddr, "example.com.", protocol.TypeAAAA, protocol.RCodeNoError, true)
	assertDNSResponse(t, dnsAddr, "nonexistent-xyz-123.com.", protocol.TypeA, protocol.RCodeNameError, false)
	assertDNSResponse(t, dnsAddr, "ads.example.com.", protocol.TypeA, protocol.RCodeNameError, false)

	truncReq := makeQuery(t, "large.example.com.", protocol.TypeTXT, false)
	truncResp := sendUDPQuery(t, dnsAddr, truncReq)
	msg, err := protocol.Decode(truncResp)
	if err != nil {
		t.Fatalf("decode trunc response: %v", err)
	}
	if !msg.Header.TC {
		t.Fatalf("expected TC bit for oversized UDP response")
	}

	fullResp := sendTCPQuery(t, dnsAddr, truncReq)
	fullMsg, err := protocol.Decode(fullResp)
	if err != nil {
		t.Fatalf("decode tcp response: %v", err)
	}
	if len(fullMsg.Answers) == 0 {
		t.Fatalf("expected full answer via TCP retry")
	}

	cacheReq := makeQuery(t, "cachetest.example.com.", protocol.TypeA, true)
	start1 := time.Now()
	_ = sendUDPQuery(t, dnsAddr, cacheReq)
	d1 := time.Since(start1)
	start2 := time.Now()
	_ = sendUDPQuery(t, dnsAddr, cacheReq)
	d2 := time.Since(start2)
	if d2 >= d1 {
		t.Fatalf("expected cache hit latency lower: first=%v second=%v", d1, d2)
	}

	dohReq := makeQuery(t, "example.com.", protocol.TypeA, true)
	dohURL := apiBase + "/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(dohReq)
	httpResp, err := http.Get(dohURL)
	if err != nil {
		t.Fatalf("doh get: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(httpResp.Body)
		t.Fatalf("unexpected doh status: %d body=%s", httpResp.StatusCode, string(b))
	}
	body, _ := io.ReadAll(httpResp.Body)
	dohMsg, err := protocol.Decode(body)
	if err != nil {
		t.Fatalf("decode doh response: %v", err)
	}
	if dohMsg.Header.RCode != protocol.RCodeNoError || len(dohMsg.Answers) == 0 {
		t.Fatalf("unexpected doh response: %+v", dohMsg.Header)
	}
}

func mockQueryFunc() func(context.Context, string, int, string, uint16, []string) (*protocol.Message, []resolver.ResolutionEvent, error) {
	var mu sync.Mutex
	calls := map[string]int{}
	return func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []resolver.ResolutionEvent, error) {
		name := normalize(qname)
		mu.Lock()
		calls[name]++
		n := calls[name]
		mu.Unlock()

		switch {
		case name == "example.com." && qtype == protocol.TypeA:
			return answerA(name, [4]byte{93, 184, 216, 34}), nil, nil
		case name == "example.com." && qtype == protocol.TypeAAAA:
			return answerAAAA(name, [16]byte{0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01}), nil, nil
		case name == "nonexistent-xyz-123.com.":
			return &protocol.Message{Header: protocol.Header{QR: true, RCode: protocol.RCodeNameError}, Questions: []protocol.Question{{Name: name, Type: qtype, Class: protocol.ClassIN}}}, nil, nil
		case name == "ads.example.com.":
			return &protocol.Message{Header: protocol.Header{QR: true, RCode: protocol.RCodeNameError}, Questions: []protocol.Question{{Name: name, Type: qtype, Class: protocol.ClassIN}}}, nil, nil
		case name == "large.example.com." && qtype == protocol.TypeTXT:
			return largeTXT(name), nil, nil
		case name == "cachetest.example.com." && qtype == protocol.TypeA:
			if n == 1 {
				time.Sleep(60 * time.Millisecond)
			}
			return answerA(name, [4]byte{1, 2, 3, 4}), nil, nil
		default:
			return &protocol.Message{Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError}, Questions: []protocol.Question{{Name: name, Type: qtype, Class: protocol.ClassIN}}}, nil, nil
		}
	}
}

func answerA(name string, ip [4]byte) *protocol.Message {
	return &protocol.Message{Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError}, Questions: []protocol.Question{{Name: name, Type: protocol.TypeA, Class: protocol.ClassIN}}, Answers: []protocol.ResourceRecord{{Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 120, Data: protocol.AData{Address: ip}}}}
}

func answerAAAA(name string, ip [16]byte) *protocol.Message {
	return &protocol.Message{Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError}, Questions: []protocol.Question{{Name: name, Type: protocol.TypeAAAA, Class: protocol.ClassIN}}, Answers: []protocol.ResourceRecord{{Name: name, Type: protocol.TypeAAAA, Class: protocol.ClassIN, TTL: 120, Data: protocol.AAAAData{Address: ip}}}}
}

func largeTXT(name string) *protocol.Message {
	chunk := stringsRepeat("x", 250)
	return &protocol.Message{Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError}, Questions: []protocol.Question{{Name: name, Type: protocol.TypeTXT, Class: protocol.ClassIN}}, Answers: []protocol.ResourceRecord{{Name: name, Type: protocol.TypeTXT, Class: protocol.ClassIN, TTL: 60, Data: protocol.TXTData{Texts: []string{chunk, chunk, chunk}}}}}
}

func assertDNSResponse(t *testing.T, dnsAddr, qname string, qtype uint16, rcode uint8, hasAnswer bool) {
	t.Helper()
	req := makeQuery(t, qname, qtype, true)
	resp := sendUDPQuery(t, dnsAddr, req)
	msg, err := protocol.Decode(resp)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if msg.Header.RCode != rcode {
		t.Fatalf("rcode=%d want=%d", msg.Header.RCode, rcode)
	}
	if hasAnswer && len(msg.Answers) == 0 {
		t.Fatalf("expected answers for %s", qname)
	}
}

func makeQuery(t *testing.T, qname string, qtype uint16, withEDNS bool) []byte {
	t.Helper()
	msg := &protocol.Message{Header: protocol.Header{ID: 42, RD: true}, Questions: []protocol.Question{{Name: qname, Type: qtype, Class: protocol.ClassIN}}}
	if withEDNS {
		msg.Additionals = []protocol.ResourceRecord{{Name: ".", Type: protocol.TypeOPT, Class: 4096, TTL: 0, Data: protocol.OPTData{UDPSize: 4096}}}
	}
	wire, err := protocol.Encode(msg)
	if err != nil {
		t.Fatalf("encode query: %v", err)
	}
	return wire
}

func sendUDPQuery(t *testing.T, dnsAddr string, payload []byte) []byte {
	t.Helper()
	conn, err := net.Dial("udp", dnsAddr)
	if err != nil {
		t.Fatalf("udp dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("udp read: %v", err)
	}
	return append([]byte(nil), buf[:n]...)
}

func sendTCPQuery(t *testing.T, dnsAddr string, payload []byte) []byte {
	t.Helper()
	conn, err := net.Dial("tcp", dnsAddr)
	if err != nil {
		t.Fatalf("tcp dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		t.Fatalf("tcp write len: %v", err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("tcp write payload: %v", err)
	}
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Fatalf("tcp read len: %v", err)
	}
	sz := int(binary.BigEndian.Uint16(lenBuf[:]))
	buf := make([]byte, sz)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("tcp read payload: %v", err)
	}
	return buf
}

func reservePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("sandbox does not allow listening sockets: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func normalize(name string) string {
	if strings.HasSuffix(name, ".") {
		return strings.ToLower(name)
	}
	return strings.ToLower(name) + "."
}

func stringsRepeat(s string, n int) string {
	var b bytes.Buffer
	for i := 0; i < n; i++ {
		b.WriteString(s)
	}
	return b.String()
}
