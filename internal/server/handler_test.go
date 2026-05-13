package server

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dnsresolver/internal/cache"
	ilogger "dnsresolver/internal/logger"
	"dnsresolver/internal/metrics"
	"dnsresolver/internal/protocol"
	"dnsresolver/internal/resolver"
)

func TestResolverSecurityHooksFeedHandlerStats(t *testing.T) {
	t.Parallel()

	r := resolver.New(resolver.DefaultConfig(), cache.New(cache.Options{}))
	r.ReplaceBlocklist("ads.example.com")
	h := NewHandler(Options{Resolver: r, MaxUDPSize: 4096, RRLEnabled: false})

	query := &protocol.Message{
		Header:    protocol.Header{ID: 7, RD: true},
		Questions: []protocol.Question{{Name: "ads.example.com.", Type: protocol.TypeA, Class: protocol.ClassIN}},
	}
	wire, err := protocol.Encode(query)
	if err != nil {
		t.Fatalf("encode query: %v", err)
	}

	respWire, drop, err := h.HandlePacket(context.Background(), wire, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50000}, "udp")
	if err != nil {
		t.Fatalf("handle packet: %v", err)
	}
	if drop {
		t.Fatalf("unexpected drop")
	}
	resp, err := protocol.Decode(respWire)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Header.RCode != protocol.RCodeNameError {
		t.Fatalf("expected NXDOMAIN for blocked domain")
	}

	stats := h.SecurityStats()
	if stats["blocklist"] == 0 {
		t.Fatalf("expected blocklist counter increment in handler stats")
	}
}

func TestHandlerRespectsAllowRecursiveFlag(t *testing.T) {
	t.Parallel()

	allowRecursive := false
	r := resolver.New(resolver.DefaultConfig(), cache.New(cache.Options{}))
	h := NewHandler(Options{Resolver: r, MaxUDPSize: 4096, RRLEnabled: false, AllowRecursive: &allowRecursive})

	query := &protocol.Message{
		Header:    protocol.Header{ID: 9, RD: true},
		Questions: []protocol.Question{{Name: "example.com.", Type: protocol.TypeA, Class: protocol.ClassIN}},
	}
	wire, err := protocol.Encode(query)
	if err != nil {
		t.Fatalf("encode query: %v", err)
	}

	respWire, drop, err := h.HandlePacket(context.Background(), wire, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50001}, "udp")
	if err != nil {
		t.Fatalf("handle packet: %v", err)
	}
	if drop {
		t.Fatalf("unexpected drop")
	}
	resp, err := protocol.Decode(respWire)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Header.RCode != protocol.RCodeRefused {
		t.Fatalf("expected REFUSED when recursion disabled, got %s", protocol.RCodeToString(resp.Header.RCode))
	}
}

func TestRateLimitLoggingWarnThenDebugWithinWindow(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := NewHandler(Options{Logger: logger})

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }

	h.logRateLimit("1.1.1.1")
	h.logRateLimit("1.1.1.1")
	now = now.Add(61 * time.Second)
	h.logRateLimit("1.1.1.1")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 log lines, got %d", len(lines))
	}
	if !strings.Contains(lines[0], `"level":"WARN"`) {
		t.Fatalf("expected first line WARN, got: %s", lines[0])
	}
	if !strings.Contains(lines[1], `"level":"DEBUG"`) {
		t.Fatalf("expected second line DEBUG, got: %s", lines[1])
	}
	if !strings.Contains(lines[2], `"level":"WARN"`) {
		t.Fatalf("expected third line WARN after cooldown, got: %s", lines[2])
	}
}

func TestMalformedPacketLogsHexAndReturnsFORMERR(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := NewHandler(Options{Logger: logger, MaxUDPSize: 4096})

	respWire, drop, err := h.HandlePacket(context.Background(), []byte{0x00, 0x01, 0x02}, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53000}, "udp")
	if err != nil {
		t.Fatalf("handle packet: %v", err)
	}
	if drop {
		t.Fatalf("unexpected drop")
	}
	resp, err := protocol.Decode(respWire)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Header.RCode != protocol.RCodeFormatError {
		t.Fatalf("expected FORMERR, got rcode=%d", resp.Header.RCode)
	}

	logLine := strings.TrimSpace(buf.String())
	if !strings.Contains(logLine, `"reason":"decode_error"`) {
		t.Fatalf("expected decode_error in log: %s", logLine)
	}
	if !strings.Contains(logLine, `"raw_hex":"000102"`) {
		t.Fatalf("expected raw_hex in log: %s", logLine)
	}
}

func TestSecurityReasonLoggingWarnThenDebugWithinWindow(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := NewHandler(Options{Logger: logger})

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }

	h.logSecurityReason("bailiwick_rejected")
	h.logSecurityReason("bailiwick_rejected")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 log lines, got %d", len(lines))
	}
	if !strings.Contains(lines[0], `"level":"WARN"`) || !strings.Contains(lines[0], `"reason":"bailiwick_rejected"`) {
		t.Fatalf("expected first line warn bailiwick, got: %s", lines[0])
	}
	if !strings.Contains(lines[1], `"level":"DEBUG"`) || !strings.Contains(lines[1], `"reason":"bailiwick_rejected"`) {
		t.Fatalf("expected second line debug bailiwick, got: %s", lines[1])
	}
}

func TestPrometheusCacheEntryGaugesUpdatedAfterQuery(t *testing.T) {
	t.Parallel()
	cfg := resolver.DefaultConfig()
	cfg.QNAMEMinimization = false
	r := resolver.New(cfg, cache.New(cache.Options{}))
	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []resolver.ResolutionEvent, error) {
		return &protocol.Message{
			Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
			Answers: []protocol.ResourceRecord{{
				Name:  "example.com.",
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   60,
				Data:  protocol.AData{Address: [4]byte{1, 1, 1, 1}},
			}},
		}, nil, nil
	})
	p := metrics.NewPrometheus()
	h := NewHandler(Options{Resolver: r, MaxUDPSize: 4096, RRLEnabled: false, Prometheus: p})

	q := &protocol.Message{
		Header:    protocol.Header{ID: 42, RD: true},
		Questions: []protocol.Question{{Name: "example.com.", Type: protocol.TypeA, Class: protocol.ClassIN}},
	}
	wire, err := protocol.Encode(q)
	if err != nil {
		t.Fatalf("encode query: %v", err)
	}
	if _, _, err := h.HandlePacket(context.Background(), wire, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53001}, "udp"); err != nil {
		t.Fatalf("handle packet: %v", err)
	}

	rr := httptest.NewRecorder()
	h.Prometheus().Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()
	if !strings.Contains(body, `dns_cache_entries{kind="positive"} 1`) {
		t.Fatalf("expected positive cache entry gauge in metrics, got: %s", body)
	}
	if !strings.Contains(body, `dns_cache_entries{kind="negative"} 0`) {
		t.Fatalf("expected negative cache entry gauge in metrics, got: %s", body)
	}
}

func TestPrometheusObservesResolutionAndUpstreamDurations(t *testing.T) {
	t.Parallel()
	p := metrics.NewPrometheus()
	h := NewHandler(Options{Prometheus: p})
	h.observeResolutionEvents("A", &resolver.ResolveResult{
		Events: []resolver.ResolutionEvent{
			{
				Server:   "198.41.0.4",
				StepType: "root_query",
				Latency:  15,
			},
		},
	})

	rr := httptest.NewRecorder()
	h.Prometheus().Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()
	if !strings.Contains(body, `dns_resolution_duration_seconds_count{type="A",step="root_query"} 1`) &&
		!strings.Contains(body, `dns_resolution_duration_seconds_count{step="root_query",type="A"} 1`) {
		t.Fatalf("expected resolution duration metric, got: %s", body)
	}
	if !strings.Contains(body, `dns_upstream_query_duration_seconds_count{server="198.41.0.4",zone="root"} 1`) {
		t.Fatalf("expected upstream duration metric, got: %s", body)
	}
}

func TestQueryLoggingIncludesMandatoryFields(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := resolver.DefaultConfig()
	cfg.QNAMEMinimization = false
	r := resolver.New(cfg, cache.New(cache.Options{}))
	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []resolver.ResolutionEvent, error) {
		return &protocol.Message{
			Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
			Answers: []protocol.ResourceRecord{{
				Name:  "example.com.",
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   60,
				Data:  protocol.AData{Address: [4]byte{1, 1, 1, 1}},
			}},
		}, nil, nil
	})
	h := NewHandler(Options{Resolver: r, Logger: logger})

	ctx := context.Background()
	ctx = ilogger.WithRequestID(ctx, "req-123")
	ctx = ilogger.WithTraceID(ctx, "4bf92f3577b34da6a3ce929d0e0e4736")
	q := &protocol.Message{
		Header:    protocol.Header{ID: 7, RD: true},
		Questions: []protocol.Question{{Name: "example.com.", Type: protocol.TypeA, Class: protocol.ClassIN}},
	}
	wire, err := protocol.Encode(q)
	if err != nil {
		t.Fatalf("encode query: %v", err)
	}
	if _, _, err := h.HandlePacket(ctx, wire, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53002}, "udp"); err != nil {
		t.Fatalf("handle packet: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`"request_id":"req-123"`,
		`"trace_id":"4bf92f3577b34da6a3ce929d0e0e4736"`,
		`"domain":"example.com."`,
		`"type":"A"`,
		`"rcode":"NOERROR"`,
		`"duration_ms":`,
		`"cached":false`,
		`"stale":false`,
		`"client_ip":"127.0.0.1"`,
		`"protocol":"udp"`,
		`"steps":`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected log field %s in output: %s", want, out)
		}
	}
}

func TestSubscribeQueriesCreatesChannel(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{})

	ch := h.SubscribeQueries(0)
	if ch == nil {
		t.Fatal("expected non-nil channel")
	}
	if cap(ch) != 128 {
		t.Fatalf("expected buffer size 128, got %d", cap(ch))
	}

	h.UnsubscribeQueries(ch)

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("channel should be closed after unsubscribe")
		}
	default:
		t.Fatal("channel should be closed")
	}
}

func TestSubscribeQueriesCustomBuffer(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{})

	ch := h.SubscribeQueries(50)
	if cap(ch) != 50 {
		t.Fatalf("expected buffer size 50, got %d", cap(ch))
	}
	h.UnsubscribeQueries(ch)
}

func TestUnsubscribeMultipleTimes(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{})

	ch := h.SubscribeQueries(10)
	h.UnsubscribeQueries(ch)
	h.UnsubscribeQueries(ch)
}

func TestPublishQueryEvent(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{})

	ch := h.SubscribeQueries(10)
	defer h.UnsubscribeQueries(ch)

	h.publishQueryEvent(QueryEvent{
		ID:        "test-id",
		QueryID:   "test-id",
		Domain:    "test.example.com",
		Type:      "A",
		ClientIP:  "192.168.1.1",
		Protocol:  "udp",
		Timestamp: time.Now(),
	})

	select {
	case ev := <-ch:
		if ev.QueryID != "test-id" {
			t.Fatalf("expected test-id, got %s", ev.QueryID)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestPublishQueryEventNonBlocking(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{})

	ch := h.SubscribeQueries(1)
	ch <- QueryEvent{ID: "test"}

	h.publishQueryEvent(QueryEvent{ID: "test2"})

	select {
	case ev := <-ch:
		if ev.QueryID != "" {
			t.Fatalf("expected empty QueryID, got %s", ev.QueryID)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestSecurityStatsJSON(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{})

	h.incSecurityDrop("test_reason")

	jsonBytes := h.SecurityStatsJSON()
	if len(jsonBytes) == 0 {
		t.Fatal("expected non-empty JSON")
	}
	if !strings.Contains(string(jsonBytes), "test_reason") {
		t.Fatalf("expected test_reason in JSON: %s", string(jsonBytes))
	}
}

func TestSecurityStatsEmpty(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{})

	stats := h.SecurityStats()
	if len(stats) != 0 {
		t.Fatalf("expected empty stats, got %d items", len(stats))
	}
}

func TestMetricsReturnsMetrics(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{MaxUDPSize: 4096})

	m := h.Metrics()
	if m == nil {
		t.Fatal("expected non-nil metrics")
	}
}

func TestPrometheusReturnsPromMetrics(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{})

	p := h.Prometheus()
	if p != nil {
		t.Fatal("expected nil prom metrics when not configured")
	}
}

func TestPrometheusReturnsConfiguredPromMetrics(t *testing.T) {
	t.Parallel()
	p := metrics.NewPrometheus()
	h := NewHandler(Options{Prometheus: p})

	if h.Prometheus() == nil {
		t.Fatal("expected non-nil prom metrics when configured")
	}
}

func TestRRLDropsNoRRL(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{})

	drops := h.RRLDrops()
	if drops != 0 {
		t.Fatalf("expected 0 drops without RRL, got %d", drops)
	}
}

func TestRateLimiterTrackedIPsNoLimiter(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{})

	ips := h.RateLimiterTrackedIPs()
	if ips != 0 {
		t.Fatalf("expected 0 tracked IPs without limiter, got %d", ips)
	}
}

func TestRateLimiterBlockedNoLimiter(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{})

	blocked := h.RateLimiterBlocked(10)
	if blocked != nil {
		t.Fatalf("expected nil without limiter, got %v", blocked)
	}
}

func TestRateLimiterDropsNoLimiter(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{})

	drops := h.RateLimiterDrops()
	if drops != 0 {
		t.Fatalf("expected 0 drops without limiter, got %d", drops)
	}
}

func TestRRLTrackedTuplesNoRRL(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{})

	tuples := h.RRLTrackedTuples()
	if tuples != 0 {
		t.Fatalf("expected 0 tuples without RRL, got %d", tuples)
	}
}

func TestApplyRuntimeSettingsNil(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{})

	applied := h.ApplyRuntimeSettings(nil)
	if len(applied) != 0 {
		t.Fatalf("expected empty applied settings, got %v", applied)
	}
}

func TestApplyRuntimeSettingsEmpty(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{})

	applied := h.ApplyRuntimeSettings(map[string]any{})
	if len(applied) != 0 {
		t.Fatalf("expected empty applied settings, got %v", applied)
	}
}

func TestApplyRuntimeSettingsRRLEnabled(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{RRLEnabled: false})

	applied := h.ApplyRuntimeSettings(map[string]any{"rrl_enabled": true})
	if applied["rrl_enabled"] != true {
		t.Fatalf("expected rrl_enabled=true, got %v", applied["rrl_enabled"])
	}
}

func TestRuntimeConfig(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{RRLEnabled: true})

	cfg := h.RuntimeConfig()
	if cfg["rrl_enabled"] != true {
		t.Fatalf("expected rrl_enabled=true, got %v", cfg["rrl_enabled"])
	}
}

func TestBoolFromAny(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input  any
		want   bool
		wantOk bool
	}{
		{true, true, true},
		{false, false, true},
		{1, false, false},
		{"true", false, false},
		{nil, false, false},
	}

	for _, tt := range tests {
		got, ok := boolFromAny(tt.input)
		if ok != tt.wantOk {
			t.Errorf("boolFromAny(%v): ok = %v, want %v", tt.input, ok, tt.wantOk)
		}
		if ok && got != tt.want {
			t.Errorf("boolFromAny(%v): got = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestFloatFromAny(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input  any
		want   float64
		wantOk bool
	}{
		{float64(1.5), 1.5, true},
		{float32(2.5), 2.5, true},
		{int(3), 3.0, true},
		{int64(4), 4.0, true},
		{true, 0, false},
		{"1.5", 0, false},
		{nil, 0, false},
	}

	for _, tt := range tests {
		got, ok := floatFromAny(tt.input)
		if ok != tt.wantOk {
			t.Errorf("floatFromAny(%v): ok = %v, want %v", tt.input, ok, tt.wantOk)
		}
		if ok && got != tt.want {
			t.Errorf("floatFromAny(%v): got = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestIntFromAny(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input  any
		want   int
		wantOk bool
	}{
		{int(1), 1, true},
		{int64(2), 2, true},
		{float64(3), 3, true},
		{float32(4), 4, true},
		{true, 0, false},
		{"1", 0, false},
		{nil, 0, false},
	}

	for _, tt := range tests {
		got, ok := intFromAny(tt.input)
		if ok != tt.wantOk {
			t.Errorf("intFromAny(%v): ok = %v, want %v", tt.input, ok, tt.wantOk)
		}
		if ok && got != tt.want {
			t.Errorf("intFromAny(%v): got = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestClientIPForQueryEmptyID(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{})

	ip, ok := h.ClientIPForQuery("")
	if ok {
		t.Fatal("expected false for empty ID")
	}
	if ip != "" {
		t.Fatalf("expected empty IP, got %s", ip)
	}
}

func TestClientIPForQueryWhitespaceID(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{})

	ip, ok := h.ClientIPForQuery("   ")
	if ok {
		t.Fatal("expected false for whitespace ID")
	}
	if ip != "" {
		t.Fatalf("expected empty IP, got %s", ip)
	}
}

func TestClientIPForQueryNotFound(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{})

	ip, ok := h.ClientIPForQuery("nonexistent-id")
	if ok {
		t.Fatal("expected false for nonexistent ID")
	}
	if ip != "" {
		t.Fatalf("expected empty IP, got %s", ip)
	}
}

func TestReverseHostnameNilIP(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{})

	host := h.ReverseHostname("")
	if host != "" {
		t.Fatalf("expected empty host for empty IP, got %s", host)
	}
}

func TestReverseHostnameInvalidIP(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{})

	host := h.ReverseHostname("not-an-ip")
	if host != "" {
		t.Fatalf("expected empty host for invalid IP, got %s", host)
	}
}

func TestReverseHostnameCached(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{})

	h.rdnsMu.Lock()
	h.rdnsCache["192.168.1.1"] = "cached-host.example.com"
	h.rdnsMu.Unlock()

	host := h.ReverseHostname("192.168.1.1")
	if host != "cached-host.example.com" {
		t.Fatalf("expected cached host, got %s", host)
	}
}

func TestSetLookupAddrFunc(t *testing.T) {
	t.Parallel()
	h := NewHandler(Options{})

	called := false
	customFunc := func(ctx context.Context, addr string) ([]string, error) {
		called = true
		return []string{"custom-reverse.example.com"}, nil
	}

	h.SetLookupAddrFunc(customFunc)
	h.lookupAddr(context.Background(), "192.168.1.1")

	if !called {
		t.Fatal("expected custom lookup function to be called")
	}
}

func TestClientIPStringNilAddr(t *testing.T) {
	ip := clientIPString(nil)
	if ip != "" {
		t.Fatalf("expected empty string for nil addr, got %s", ip)
	}
}

func TestClientIPStringUDP(t *testing.T) {
	ip := clientIPString(&net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 53})
	if ip != "192.168.1.1" {
		t.Fatalf("expected 192.168.1.1, got %s", ip)
	}
}

func TestClientIPStringTCP(t *testing.T) {
	ip := clientIPString(&net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 53})
	if ip != "10.0.0.1" {
		t.Fatalf("expected 10.0.0.1, got %s", ip)
	}
}

func TestClientIPStringUnknown(t *testing.T) {
	ip := clientIPString(&net.UnixAddr{Name: "/path/to/socket"})
	if ip != "/path/to/socket" {
		t.Fatalf("expected /path/to/socket for unknown addr type, got %s", ip)
	}
}

func TestApplyRuntimeSettingsWithResolver(t *testing.T) {
	t.Parallel()
	cfg := resolver.DefaultConfig()
	cfg.QNAMEMinimization = false
	r := resolver.New(cfg, cache.New(cache.Options{}))
	h := NewHandler(Options{Resolver: r})

	applied := h.ApplyRuntimeSettings(map[string]any{
		"cache_max_ttl":      300,
		"qname_minimization": true,
	})
	if applied["qname_minimization"] != true {
		t.Fatalf("expected qname_minimization=true, got %v", applied["qname_minimization"])
	}
}

func TestRuntimeConfigWithResolver(t *testing.T) {
	t.Parallel()
	cfg := resolver.DefaultConfig()
	cfg.QNAMEMinimization = false
	r := resolver.New(cfg, cache.New(cache.Options{}))
	h := NewHandler(Options{Resolver: r})

	cfgMap := h.RuntimeConfig()
	if cfgMap["qname_minimization"] != false {
		t.Fatalf("expected qname_minimization=false, got %v", cfgMap["qname_minimization"])
	}
}

func TestUDPServerStartShutdown(t *testing.T) {
	h := NewHandler(Options{MaxUDPSize: 4096})
	srv := NewUDPServer(":0", h, 2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := srv.Start(ctx)
	if err != nil {
		t.Fatalf("UDP start failed: %v", err)
	}

	addr := srv.LocalAddr()
	if addr == nil {
		t.Fatal("expected local address")
	}

	err = srv.Shutdown(context.Background())
	if err != nil {
		t.Fatalf("UDP shutdown failed: %v", err)
	}
}

func TestUDPServerStartInvalidAddr(t *testing.T) {
	h := NewHandler(Options{MaxUDPSize: 4096})
	srv := NewUDPServer("invalid:addr:!", h, 2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := srv.Start(ctx)
	if err == nil {
		t.Fatal("expected error for invalid address")
	}
}

func TestUDPServerMultipleShutdowns(t *testing.T) {
	h := NewHandler(Options{MaxUDPSize: 4096})
	srv := NewUDPServer(":0", h, 2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = srv.Start(ctx)
	_ = srv.Shutdown(context.Background())
	_ = srv.Shutdown(context.Background())
}

func TestUDPServerLocalAddrNil(t *testing.T) {
	srv := NewUDPServer(":0", nil, 2)
	addr := srv.LocalAddr()
	if addr != nil {
		t.Fatalf("expected nil for unstarted server, got %v", addr)
	}
}
