package resolver

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"dnsresolver/internal/cache"
	"dnsresolver/internal/protocol"
)

func TestResolverResolveCaches(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QNAMEMinimization = false
	c := cache.New(cache.Options{MaxEntries: 100})
	r := New(cfg, c)

	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []ResolutionEvent, error) {
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

	res, err := r.Resolve(context.Background(), "example.com", protocol.TypeA)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res == nil || res.Message == nil {
		t.Fatalf("expected message")
	}

	res2, err := r.Resolve(context.Background(), "example.com", protocol.TypeA)
	if err != nil {
		t.Fatalf("resolve cached: %v", err)
	}
	if !res2.Cached {
		t.Fatalf("expected cached result")
	}
}

func TestResolverBlockedDomain(t *testing.T) {
	c := cache.New(cache.Options{})
	r := New(DefaultConfig(), c)
	r.ReplaceBlocklist("blocked.example")

	res, err := r.Resolve(context.Background(), "blocked.example", protocol.TypeA)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !res.Blocked {
		t.Fatalf("expected blocked")
	}
}

func TestResolverHistory(t *testing.T) {
	c := cache.New(cache.Options{})
	r := New(DefaultConfig(), c)

	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []ResolutionEvent, error) {
		return &protocol.Message{
			Header:  protocol.Header{QR: true, RCode: protocol.RCodeNoError},
			Answers: []protocol.ResourceRecord{{Name: qname, Type: qtype, Class: protocol.ClassIN, TTL: 60, Data: protocol.AData{Address: [4]byte{1, 2, 3, 4}}}},
		}, nil, nil
	})

	r.Resolve(context.Background(), "test.com", protocol.TypeA)
	r.Resolve(context.Background(), "test2.com", protocol.TypeAAAA)

	history := r.History(1, 10)
	if len(history) != 2 {
		t.Fatalf("history=%d want=2", len(history))
	}
}

func TestResolverSecurityStats(t *testing.T) {
	c := cache.New(cache.Options{})
	r := New(DefaultConfig(), c)
	r.ReplaceBlocklist("blocked.example")

	r.Resolve(context.Background(), "blocked.example", protocol.TypeA)

	stats := r.SecurityStats()
	if stats["blocklist"] != 1 {
		t.Fatalf("blocklist=%d want=1", stats["blocklist"])
	}
}

func TestResolverBailiwick(t *testing.T) {
	c := cache.New(cache.Options{})
	_ = c
	r := New(DefaultConfig(), c)

	result1 := InBailiwick("example.com.", "ns.example.net.")
	if result1 {
		t.Errorf("InBailiwick(example.com., ns.example.net.)=true want=false")
	}
	_ = r
}

func TestEventHub(t *testing.T) {
	hub := NewEventHub()

	sub := hub.Subscribe(10)
	if sub == nil {
		t.Fatalf("expected subscriber channel")
	}

	ev := ResolutionEvent{
		QueryID:   "test-123",
		Timestamp: time.Now(),
		Step:      1,
		StepType:  "root_query",
		Query:     "example.com",
		QueryType: "A",
		Success:   true,
	}

	hub.Publish(ev)

	select {
	case received := <-sub:
		if received.QueryID != ev.QueryID {
			t.Errorf("queryID=%s want=%s", received.QueryID, ev.QueryID)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("timeout waiting for event")
	}

	hub.Unsubscribe(sub)
}

func TestEventHubUnsubscribe(t *testing.T) {
	hub := NewEventHub()
	ch := make(chan ResolutionEvent)
	hub.mu.Lock()
	hub.subscribers[ch] = struct{}{}
	hub.mu.Unlock()

	hub.Unsubscribe(ch)

	hub.mu.RLock()
	_, ok := hub.subscribers[ch]
	hub.mu.RUnlock()
	if ok {
		t.Fatalf("expected channel to be removed")
	}
}

func TestBlocklistStats(t *testing.T) {
	bl := NewBlocklist()
	bl.Replace([]string{"a.com", "b.com", "c.com"})

	bl.IsBlocked("a.com")
	bl.IsBlocked("a.com")
	bl.IsBlocked("x.com")

	stats := bl.Stats()
	if stats.DomainsCount != 3 {
		t.Fatalf("domains=%d want=3", stats.DomainsCount)
	}
	if stats.SessionHits != 2 {
		t.Fatalf("hits=%d want=2", stats.SessionHits)
	}
}

func TestDefaultRootHints(t *testing.T) {
	hints := DefaultRootHints()
	if len(hints) == 0 {
		t.Fatalf("expected root hints")
	}

	ips := RootHintIPs()
	if len(ips) == 0 {
		t.Fatalf("expected root hint IPs")
	}
}

func TestBlocklistDomains(t *testing.T) {
	bl := NewBlocklist()
	bl.Replace([]string{"example.com", "test.org"})

	domains := bl.Domains()
	if len(domains) != 2 {
		t.Fatalf("domains=%d want=2", len(domains))
	}
}

func TestCircuitBreakerUpdateConfig(t *testing.T) {
	cb := NewCircuitBreaker(5, 2, 30*time.Second)

	cb.UpdateConfig(3, 1, 60*time.Second)

	snap := cb.Snapshot()
	if cb.failureThreshold != 3 {
		t.Errorf("failureThreshold=%d want=3", cb.failureThreshold)
	}
	_ = snap
}

func TestQueryFastest(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QNAMEMinimization = false
	c := cache.New(cache.Options{MaxEntries: 100})
	r := New(cfg, c)

	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []ResolutionEvent, error) {
		return &protocol.Message{
			Header:  protocol.Header{QR: true, RCode: protocol.RCodeNoError},
			Answers: []protocol.ResourceRecord{{Name: qname, Type: qtype, Class: protocol.ClassIN, TTL: 60, Data: protocol.AData{Address: [4]byte{1, 2, 3, 4}}}},
		}, nil, nil
	})

	ctx := context.Background()
	result, events, err := r.queryFastest(ctx, "test-id", 1, "example.com", protocol.TypeA, []string{"8.8.8.8"}, cfg)
	if err != nil {
		t.Fatalf("queryFastest: %v", err)
	}
	if result == nil {
		t.Fatalf("expected result")
	}
	if len(events) == 0 {
		t.Fatalf("expected events")
	}
}

func TestQueryFastestNoServers(t *testing.T) {
	cfg := DefaultConfig()
	c := cache.New(cache.Options{})
	r := New(cfg, c)

	ctx := context.Background()
	_, _, err := r.queryFastest(ctx, "test-id", 1, "example.com", protocol.TypeA, []string{}, cfg)
	if err == nil {
		t.Fatalf("expected error for no servers")
	}
}

func TestStepTypeFor(t *testing.T) {
	tests := []struct {
		step     int
		expected string
	}{
		{1, "root_query"},
		{2, "tld_query"},
		{3, "auth_query"},
		{10, "auth_query"},
	}

	for _, tc := range tests {
		result := stepTypeFor(tc.step)
		if result != tc.expected {
			t.Errorf("stepTypeFor(%d)=%s want=%s", tc.step, result, tc.expected)
		}
	}
}

func TestRandomJitter(t *testing.T) {
	j1, err := randomJitter(50 * time.Millisecond)
	if err != nil {
		t.Fatalf("randomJitter: %v", err)
	}
	if j1 < 0 || j1 > 50*time.Millisecond {
		t.Errorf("jitter=%v out of range", j1)
	}

	j2, err := randomJitter(0)
	if err != nil {
		t.Fatalf("randomJitter zero: %v", err)
	}
	if j2 != 0 {
		t.Errorf("jitter zero=%v want=0", j2)
	}

	j3, err := randomJitter(-1 * time.Millisecond)
	if err != nil {
		t.Fatalf("randomJitter negative: %v", err)
	}
	if j3 != 0 {
		t.Errorf("jitter negative=%v want=0", j3)
	}
}

func TestResolutionEventJSON(t *testing.T) {
	ev := ResolutionEvent{
		QueryID:     "test-123",
		Timestamp:   time.Now(),
		Step:        1,
		StepType:    "root_query",
		Server:      "198.41.0.4",
		Query:       "example.com",
		QueryType:   "A",
		Latency:     15,
		Success:     true,
		RawRequest:  []byte{0x00, 0x01},
		RawResponse: []byte{0x00, 0x02},
	}

	data, err := ev.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}

	if len(data) == 0 {
		t.Fatalf("expected non-empty json")
	}
}

func TestResolverBlocklistDomains(t *testing.T) {
	cfg := DefaultConfig()
	c := cache.New(cache.Options{})
	r := New(cfg, c)
	r.ReplaceBlocklist("example.com")

	domains := r.BlocklistDomains()
	if len(domains) == 0 {
		t.Fatalf("expected blocklist domains")
	}
}

func TestResolverCacheStats(t *testing.T) {
	cfg := DefaultConfig()
	c := cache.New(cache.Options{MaxEntries: 100})
	r := New(cfg, c)

	_ = r.CacheStats()
}

func TestResolverAddSecurityHookNil(t *testing.T) {
	cfg := DefaultConfig()
	c := cache.New(cache.Options{})
	r := New(cfg, c)

	r.AddSecurityHook(nil)
}

func TestQueryOnceFallsBackToTCPOnTruncatedUDP(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CaseRandomization = false
	cfg.QNAMEMinimization = false
	c := cache.New(cache.Options{})
	r := New(cfg, c)

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udpConn.Close()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer tcpLn.Close()

	port := udpConn.LocalAddr().(*net.UDPAddr).Port
	if tcpLn.Addr().(*net.TCPAddr).Port != port {
		tcpLn.Close()
		tcpLn, err = net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("listen tcp same port: %v", err)
		}
		defer tcpLn.Close()
	}
	r.SetUpstreamPort(port)

	go func() {
		buf := make([]byte, protocol.MaxUDPPacketLen)
		n, addr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		req, err := protocol.Decode(buf[:n])
		if err != nil || len(req.Questions) == 0 {
			return
		}
		resp := &protocol.Message{
			Header:    protocol.Header{ID: req.Header.ID, QR: true, TC: true, RD: true, RA: true, RCode: protocol.RCodeNoError},
			Questions: req.Questions,
		}
		wire, err := protocol.Encode(resp)
		if err != nil {
			return
		}
		_, _ = udpConn.WriteToUDP(wire, addr)
	}()

	go func() {
		conn, err := tcpLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		var lenBuf [2]byte
		if _, err := io.ReadFull(reader, lenBuf[:]); err != nil {
			return
		}
		size := int(binary.BigEndian.Uint16(lenBuf[:]))
		payload := make([]byte, size)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return
		}
		req, err := protocol.Decode(payload)
		if err != nil || len(req.Questions) == 0 {
			return
		}
		q := req.Questions[0]
		resp := &protocol.Message{
			Header:    protocol.Header{ID: req.Header.ID, QR: true, RD: true, RA: true, RCode: protocol.RCodeNoError},
			Questions: req.Questions,
			Answers: []protocol.ResourceRecord{{
				Name:  q.Name,
				Type:  q.Type,
				Class: protocol.ClassIN,
				TTL:   60,
				Data:  protocol.AData{Address: [4]byte{1, 2, 3, 4}},
			}},
		}
		wire, err := protocol.Encode(resp)
		if err != nil {
			return
		}
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(wire)))
		if _, err := conn.Write(lenBuf[:]); err != nil {
			return
		}
		_, _ = conn.Write(wire)
	}()

	result, _, err := r.queryFastest(context.Background(), "test-id", 1, "example.com", protocol.TypeA, []string{"127.0.0.1"}, cfg)
	if err != nil {
		t.Fatalf("queryFastest: %v", err)
	}
	if result == nil || len(result.Answers) != 1 {
		t.Fatalf("expected TCP fallback answer, got %+v", result)
	}
}

func TestResolverTraceRetentionPrunesOldEntries(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QNAMEMinimization = false
	r := New(cfg, cache.New(cache.Options{}))
	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []ResolutionEvent, error) {
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

	first, err := r.Resolve(context.Background(), "trace-0.example.", protocol.TypeA)
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	for i := 1; i <= 1000; i++ {
		if _, err := r.Resolve(context.Background(), "trace-"+strconv.Itoa(i)+".example.", protocol.TypeA); err != nil {
			t.Fatalf("resolve %d: %v", i, err)
		}
	}

	if trace := r.Trace(first.QueryID); len(trace) != 0 {
		t.Fatalf("expected oldest trace to be pruned, got %d events", len(trace))
	}
}

func TestResolverApplyRuntimeSettings(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QNAMEMinimization = false
	c := cache.New(cache.Options{MaxEntries: 100})
	r := New(cfg, c)

	applied := r.ApplyRuntimeSettings(map[string]any{
		"qname_minimization": true,
		"case_randomization": true,
	})

	if applied["qname_minimization"] != true {
		t.Fatalf("expected qname_minimization=true")
	}
	if applied["case_randomization"] != true {
		t.Fatalf("expected case_randomization=true")
	}
}

func TestResolverApplyRuntimeSettingsInvalid(t *testing.T) {
	cfg := DefaultConfig()
	c := cache.New(cache.Options{MaxEntries: 100})
	r := New(cfg, c)

	applied := r.ApplyRuntimeSettings(map[string]any{
		"invalid_key": "value",
	})

	if len(applied) != 0 {
		t.Fatalf("expected no applied settings for invalid key")
	}
}

func TestResolverRuntimeConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QNAMEMinimization = false
	c := cache.New(cache.Options{MaxEntries: 100})
	r := New(cfg, c)

	cfgMap := r.RuntimeConfig()
	if cfgMap["qname_minimization"] != false {
		t.Fatalf("expected qname_minimization=false")
	}
}

func TestResolverTrace(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QNAMEMinimization = false
	c := cache.New(cache.Options{MaxEntries: 100})
	r := New(cfg, c)

	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []ResolutionEvent, error) {
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

	result, _ := r.Resolve(context.Background(), "example.com", protocol.TypeA)
	trace := r.Trace(result.QueryID)

	if trace == nil {
		t.Fatalf("expected trace")
	}
}

func TestResolverUpstreamStatuses(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QNAMEMinimization = false
	c := cache.New(cache.Options{MaxEntries: 100})
	r := New(cfg, c)

	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []ResolutionEvent, error) {
		return &protocol.Message{
			Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
		}, nil, nil
	})

	_, _ = r.Resolve(context.Background(), "example.com", protocol.TypeA)

	statuses := r.UpstreamStatuses()
	if len(statuses) == 0 {
		t.Fatalf("expected upstream statuses")
	}
}

func TestBoolSetting(t *testing.T) {
	tests := []struct {
		input any
		want  bool
		ok    bool
	}{
		{true, true, true},
		{false, false, true},
		{int(1), false, false},
		{nil, false, false},
	}

	for _, tt := range tests {
		got, ok := boolSetting(tt.input)
		if ok != tt.ok {
			t.Errorf("boolSetting(%v): ok = %v, want %v", tt.input, ok, tt.ok)
		}
		if ok && got != tt.want {
			t.Errorf("boolSetting(%v): got = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestIntSetting(t *testing.T) {
	tests := []struct {
		input any
		want  int
		ok    bool
	}{
		{int(1), 1, true},
		{int64(2), 2, true},
		{float64(3), 3, true},
		{true, 0, false},
		{nil, 0, false},
	}

	for _, tt := range tests {
		got, ok := intSetting(tt.input)
		if ok != tt.ok {
			t.Errorf("intSetting(%v): ok = %v, want %v", tt.input, ok, tt.ok)
		}
		if ok && got != tt.want {
			t.Errorf("intSetting(%v): got = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestDurationSetting(t *testing.T) {
	tests := []struct {
		input any
		want  time.Duration
		ok    bool
	}{
		{"1s", time.Second, true},
		{"500ms", 500 * time.Millisecond, true},
		{int(1), time.Second, true},
		{int64(2), 2 * time.Second, true},
		{float64(1), time.Second, true},
		{float32(1), time.Second, true},
		{true, 0, false},
		{nil, 0, false},
		{"invalid", 0, false},
	}

	for _, tt := range tests {
		got, ok := durationSetting(tt.input)
		if ok != tt.ok {
			t.Errorf("durationSetting(%v): ok = %v, want %v", tt.input, ok, tt.ok)
		}
		if ok && got != tt.want {
			t.Errorf("durationSetting(%v): got = %v, want %v", tt.input, got, tt.want)
		}
	}
}
