package resolver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"dnsresolver/internal/cache"
	"dnsresolver/internal/protocol"
)

func TestBailiwickViolationRejected(t *testing.T) {
	t.Parallel()
	additionals := []protocol.ResourceRecord{
		{Name: "ns1.example.com.", Type: protocol.TypeA, Data: protocol.AData{Address: [4]byte{1, 1, 1, 1}}},
		{Name: "ns.evil.net.", Type: protocol.TypeA, Data: protocol.AData{Address: [4]byte{9, 9, 9, 9}}},
	}
	valid, rejected := FilterGlueByBailiwick("example.com.", additionals)
	if rejected != 1 {
		t.Fatalf("rejected=%d want=1", rejected)
	}
	if len(valid) != 1 || valid[0].Name != "ns1.example.com." {
		t.Fatalf("unexpected valid glue: %+v", valid)
	}
}

func TestCNAMEChainFollow(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.QNAMEMinimization = false
	cfg.MaxCNAMEDepth = 10
	r := New(cfg, cache.New(cache.Options{}))

	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []ResolutionEvent, error) {
		switch normalizeFQDN(qname) {
		case "a.example.com.":
			return &protocol.Message{Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError}, Answers: []protocol.ResourceRecord{{Name: "a.example.com.", Type: protocol.TypeCNAME, Class: protocol.ClassIN, TTL: 60, Data: protocol.CNAMEData{Name: "b.example.com."}}}}, nil, nil
		case "b.example.com.":
			return &protocol.Message{Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError}, Answers: []protocol.ResourceRecord{{Name: "b.example.com.", Type: protocol.TypeCNAME, Class: protocol.ClassIN, TTL: 60, Data: protocol.CNAMEData{Name: "c.example.com."}}}}, nil, nil
		case "c.example.com.":
			return &protocol.Message{Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError}, Answers: []protocol.ResourceRecord{{Name: "c.example.com.", Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 60, Data: protocol.AData{Address: [4]byte{1, 2, 3, 4}}}}}, nil, nil
		default:
			return nil, nil, fmt.Errorf("unexpected qname: %s", qname)
		}
	})

	res, err := r.Resolve(context.Background(), "a.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(res.Message.Answers) == 0 || res.Message.Answers[0].Name != "c.example.com." {
		t.Fatalf("expected final cname target answer, got %+v", res.Message.Answers)
	}
}

func TestCNAMEChainDepthExceeded(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.QNAMEMinimization = false
	cfg.MaxCNAMEDepth = 10
	r := New(cfg, cache.New(cache.Options{}))

	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []ResolutionEvent, error) {
		next := "next-" + qname
		return &protocol.Message{Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError}, Answers: []protocol.ResourceRecord{{Name: normalizeFQDN(qname), Type: protocol.TypeCNAME, Class: protocol.ClassIN, TTL: 60, Data: protocol.CNAMEData{Name: next}}}}, nil, nil
	})

	_, err := r.Resolve(context.Background(), "a.example.com.", protocol.TypeA)
	if err == nil {
		t.Fatalf("expected cname depth error")
	}
}

func TestReferralLoopDetected(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.QNAMEMinimization = false
	cfg.MaxRecursionDepth = 20
	r := New(cfg, cache.New(cache.Options{}))

	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []ResolutionEvent, error) {
		return referral("example.com.", "ns1.example.com.", [4]byte{1, 1, 1, 1}), nil, nil
	})

	_, err := r.Resolve(context.Background(), "www.example.com.", protocol.TypeA)
	if err == nil || !strings.Contains(err.Error(), "referral loop detected") {
		t.Fatalf("expected referral loop error, got: %v", err)
	}
}

func TestCircuitBreakerTransitions(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	cb := NewCircuitBreaker(2, 2, 10*time.Second)
	cb.SetClock(func() time.Time { return now })
	if !cb.Allow() {
		t.Fatalf("closed should allow")
	}
	cb.OnFailure()
	cb.OnFailure()
	if cb.State() != StateOpen {
		t.Fatalf("expected open state")
	}
	if cb.Allow() {
		t.Fatalf("open should not allow before timeout")
	}
	now = now.Add(11 * time.Second)
	if !cb.Allow() {
		t.Fatalf("expected half-open allow after timeout")
	}
	if cb.State() != StateHalfOpen {
		t.Fatalf("expected half-open")
	}
	cb.OnSuccess()
	cb.OnSuccess()
	if cb.State() != StateClosed {
		t.Fatalf("expected closed after successes")
	}
}

func TestRootServersIncludeLiveStatusFields(t *testing.T) {
	t.Parallel()
	r := New(DefaultConfig(), cache.New(cache.Options{}))

	rootIP := "198.41.0.4"
	r.observeUpstreamResult(rootIP, "a.root-servers.net", 12*time.Millisecond, nil)
	cb := r.getBreaker(rootIP, r.configSnapshot())
	for i := 0; i < 5; i++ {
		cb.OnFailure()
	}
	r.observeUpstreamResult(rootIP, "a.root-servers.net", 0, fmt.Errorf("timeout"))

	servers := r.RootServers()
	var found *RootServer
	for i := range servers {
		if servers[i].IPv4 == rootIP {
			found = &servers[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected root server %s in response", rootIP)
	}
	if found.LastLatency != 12 {
		t.Fatalf("expected last latency to remain 12ms, got %d", found.LastLatency)
	}
	if found.LastSeen.IsZero() {
		t.Fatalf("expected last_seen to be populated")
	}
	if found.State != "open" || found.StateCode != 2 {
		t.Fatalf("expected open state with code 2, got state=%s code=%d", found.State, found.StateCode)
	}
	if found.ConsecutiveFailures < 5 {
		t.Fatalf("expected consecutive failures to be tracked, got %d", found.ConsecutiveFailures)
	}
	if found.LastError == "" {
		t.Fatalf("expected last error to be included")
	}
	if found.TotalSuccesses != 1 || found.TotalFailures != 1 {
		t.Fatalf("unexpected success/failure counters: successes=%d failures=%d", found.TotalSuccesses, found.TotalFailures)
	}
}

func TestQNAMEMinimizationSequence(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.QNAMEMinimization = true
	r := New(cfg, cache.New(cache.Options{}))

	var seen []string
	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []ResolutionEvent, error) {
		seen = append(seen, normalizeFQDN(qname))
		switch normalizeFQDN(qname) {
		case "com.":
			return referral("com.", "ns1.com.", [4]byte{1, 1, 1, 1}), nil, nil
		case "example.com.":
			return referral("example.com.", "ns1.example.com.", [4]byte{2, 2, 2, 2}), nil, nil
		case "www.example.com.":
			return &protocol.Message{Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError}, Answers: []protocol.ResourceRecord{{Name: "www.example.com.", Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 60, Data: protocol.AData{Address: [4]byte{3, 3, 3, 3}}}}}, nil, nil
		default:
			return nil, nil, fmt.Errorf("unexpected query: %s", qname)
		}
	})

	_, err := r.Resolve(context.Background(), "www.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(seen) < 3 {
		t.Fatalf("expected minimization chain, got %v", seen)
	}
	if seen[0] != "com." || seen[1] != "example.com." || seen[2] != "www.example.com." {
		t.Fatalf("unexpected minimization order: %v", seen)
	}
}

func TestResolveNSHostnamesWhenGlueMissing(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.QNAMEMinimization = false
	r := New(cfg, cache.New(cache.Options{}))

	r.SetLookupIPsFunc(func(ctx context.Context, host string) ([]net.IP, error) {
		if host == "ns1.example.com" {
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		}
		return nil, fmt.Errorf("unexpected lookup host: %s", host)
	})

	var secondHopServers []string
	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []ResolutionEvent, error) {
		switch step {
		case 1:
			return referralNoGlue("example.com.", "ns1.example.com."), nil, nil
		case 2:
			secondHopServers = append(secondHopServers, servers...)
			return &protocol.Message{
				Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
				Answers: []protocol.ResourceRecord{{
					Name:  "www.example.com.",
					Type:  protocol.TypeA,
					Class: protocol.ClassIN,
					TTL:   60,
					Data:  protocol.AData{Address: [4]byte{1, 1, 1, 1}},
				}},
			}, nil, nil
		default:
			return nil, nil, fmt.Errorf("unexpected step: %d", step)
		}
	})

	if _, err := r.Resolve(context.Background(), "www.example.com.", protocol.TypeA); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(secondHopServers) == 0 || secondHopServers[0] != "203.0.113.10" {
		t.Fatalf("expected second hop to use resolved NS IP, got %v", secondHopServers)
	}
}

func TestBailiwickRejectionsIncrementSecurityCounter(t *testing.T) {
	t.Parallel()
	r := New(DefaultConfig(), cache.New(cache.Options{}))
	r.SetLookupIPsFunc(func(ctx context.Context, host string) ([]net.IP, error) {
		return nil, fmt.Errorf("no lookup for %s", host)
	})

	msg := &protocol.Message{
		Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
		Authorities: []protocol.ResourceRecord{
			{Name: "example.com.", Type: protocol.TypeNS, Class: protocol.ClassIN, TTL: 60, Data: protocol.NSData{Name: "ns1.example.com."}},
		},
		Additionals: []protocol.ResourceRecord{
			{Name: "ns.evil.net.", Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 60, Data: protocol.AData{Address: [4]byte{9, 9, 9, 9}}},
		},
	}

	_ = r.nextReferralServers(context.Background(), msg, r.configSnapshot())
	stats := r.SecurityStats()
	if stats["bailiwick_rejected"] != 1 {
		t.Fatalf("expected bailiwick_rejected=1, got %d", stats["bailiwick_rejected"])
	}
}

func TestNextReferralServersUsesAnswerSectionGlue(t *testing.T) {
	t.Parallel()
	r := New(DefaultConfig(), cache.New(cache.Options{}))
	r.SetLookupIPsFunc(func(ctx context.Context, host string) ([]net.IP, error) {
		return nil, fmt.Errorf("unexpected hostname lookup for %s", host)
	})

	msg := &protocol.Message{
		Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
		Authorities: []protocol.ResourceRecord{
			{Name: "example.com.", Type: protocol.TypeNS, Class: protocol.ClassIN, TTL: 60, Data: protocol.NSData{Name: "ns1.example.com."}},
		},
		Answers: []protocol.ResourceRecord{
			{Name: "ns1.example.com.", Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 60, Data: protocol.AData{Address: [4]byte{2, 2, 2, 2}}},
		},
	}

	servers := r.nextReferralServers(context.Background(), msg, r.configSnapshot())
	if len(servers) != 1 || servers[0] != "2.2.2.2" {
		t.Fatalf("expected glue from answer section, got %v", servers)
	}
}

func TestNextReferralServersRequiresNSRecords(t *testing.T) {
	t.Parallel()
	r := New(DefaultConfig(), cache.New(cache.Options{}))

	msg := &protocol.Message{
		Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
		Additionals: []protocol.ResourceRecord{
			{Name: "ns1.example.com.", Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 60, Data: protocol.AData{Address: [4]byte{2, 2, 2, 2}}},
		},
	}

	servers := r.nextReferralServers(context.Background(), msg, r.configSnapshot())
	if len(servers) != 0 {
		t.Fatalf("expected no referral servers without NS referral, got %v", servers)
	}
}

func TestNextReferralServersDoesNotFallbackToPublicResolvers(t *testing.T) {
	t.Parallel()
	r := New(DefaultConfig(), cache.New(cache.Options{}))
	r.SetLookupIPsFunc(func(ctx context.Context, host string) ([]net.IP, error) {
		return nil, fmt.Errorf("lookup failed for %s", host)
	})

	msg := &protocol.Message{
		Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
		Authorities: []protocol.ResourceRecord{
			{Name: "example.com.", Type: protocol.TypeNS, Class: protocol.ClassIN, TTL: 60, Data: protocol.NSData{Name: "ns1.example.com."}},
		},
	}

	servers := r.nextReferralServers(context.Background(), msg, r.configSnapshot())
	if len(servers) != 0 {
		t.Fatalf("expected no fallback public resolvers, got %v", servers)
	}
}

func TestResolverReturnsTerminalRCodeAndDoesNotCache(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.QNAMEMinimization = false
	r := New(cfg, cache.New(cache.Options{}))

	calls := 0
	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []ResolutionEvent, error) {
		calls++
		return &protocol.Message{
			Header: protocol.Header{QR: true, RCode: protocol.RCodeServerFailure},
		}, nil, nil
	})

	first, err := r.Resolve(context.Background(), "servfail.example.", protocol.TypeA)
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if first.Message == nil || first.Message.Header.RCode != protocol.RCodeServerFailure {
		t.Fatalf("expected SERVFAIL message, got %+v", first.Message)
	}

	second, err := r.Resolve(context.Background(), "servfail.example.", protocol.TypeA)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if second.Cached {
		t.Fatalf("SERVFAIL should not be cached")
	}
	if calls != 2 {
		t.Fatalf("expected two upstream attempts (no caching), got %d", calls)
	}
}

func TestResolverAuthoritativeNoDataWithoutSOATerminal(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.QNAMEMinimization = false
	r := New(cfg, cache.New(cache.Options{}))

	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []ResolutionEvent, error) {
		return &protocol.Message{
			Header: protocol.Header{QR: true, AA: true, RCode: protocol.RCodeNoError},
		}, nil, nil
	})

	res, err := r.Resolve(context.Background(), "nodata.example.", protocol.TypeAAAA)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Message == nil || res.Message.Header.RCode != protocol.RCodeNoError {
		t.Fatalf("expected terminal NOERROR response, got %+v", res.Message)
	}
	if len(res.Message.Answers) != 0 {
		t.Fatalf("expected empty answer set, got %+v", res.Message.Answers)
	}
}

func TestQNAMEMinimizationFallbackIsPerQuery(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.QNAMEMinimization = true
	r := New(cfg, cache.New(cache.Options{}))

	seen := make([]string, 0, 4)
	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []ResolutionEvent, error) {
		n := normalizeFQDN(qname)
		seen = append(seen, n)
		switch n {
		case "com.", "net.":
			return &protocol.Message{Header: protocol.Header{QR: true, RCode: protocol.RCodeNameError}}, nil, nil
		case "www.example.com.":
			return &protocol.Message{
				Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
				Answers: []protocol.ResourceRecord{{
					Name:  "www.example.com.",
					Type:  protocol.TypeA,
					Class: protocol.ClassIN,
					TTL:   60,
					Data:  protocol.AData{Address: [4]byte{1, 2, 3, 4}},
				}},
			}, nil, nil
		case "api.example.net.":
			return &protocol.Message{
				Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
				Answers: []protocol.ResourceRecord{{
					Name:  "api.example.net.",
					Type:  protocol.TypeA,
					Class: protocol.ClassIN,
					TTL:   60,
					Data:  protocol.AData{Address: [4]byte{5, 6, 7, 8}},
				}},
			}, nil, nil
		default:
			return nil, nil, fmt.Errorf("unexpected query: %s", qname)
		}
	})

	if _, err := r.Resolve(context.Background(), "www.example.com.", protocol.TypeA); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if _, err := r.Resolve(context.Background(), "api.example.net.", protocol.TypeA); err != nil {
		t.Fatalf("second resolve: %v", err)
	}

	if len(seen) != 4 {
		t.Fatalf("unexpected query sequence length: %v", seen)
	}
	if seen[0] != "com." || seen[1] != "www.example.com." {
		t.Fatalf("first resolution minimization fallback mismatch: %v", seen[:2])
	}
	if seen[2] != "net." || seen[3] != "api.example.net." {
		t.Fatalf("second resolution minimization should remain enabled, got: %v", seen[2:])
	}
}

func TestResolverCachesNODATANegativeResponses(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.QNAMEMinimization = false
	c := cache.New(cache.Options{})
	r := New(cfg, c)

	calls := 0
	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []ResolutionEvent, error) {
		calls++
		return &protocol.Message{
			Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
			Authorities: []protocol.ResourceRecord{{
				Name:  "example.com.",
				Type:  protocol.TypeSOA,
				Class: protocol.ClassIN,
				TTL:   120,
				Data: protocol.SOAData{
					MName:   "ns1.example.com.",
					RName:   "hostmaster.example.com.",
					Serial:  1,
					Refresh: 3600,
					Retry:   600,
					Expire:  86400,
					Minimum: 120,
				},
			}},
		}, nil, nil
	})

	first, err := r.Resolve(context.Background(), "missing.example.com.", protocol.TypeAAAA)
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if first.Cached {
		t.Fatalf("first resolve should not be cached")
	}
	if first.Message.Header.RCode != protocol.RCodeNoError || len(first.Message.Answers) != 0 {
		t.Fatalf("expected NODATA response, got rcode=%d answers=%d", first.Message.Header.RCode, len(first.Message.Answers))
	}

	second, err := r.Resolve(context.Background(), "missing.example.com.", protocol.TypeAAAA)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if !second.Cached {
		t.Fatalf("expected second resolve to be negative-cache hit")
	}
	if second.Message.Header.RCode != protocol.RCodeNoError || len(second.Message.Answers) != 0 {
		t.Fatalf("expected cached NODATA response, got rcode=%d answers=%d", second.Message.Header.RCode, len(second.Message.Answers))
	}
	if calls != 1 {
		t.Fatalf("expected one upstream call due to negative cache, got %d", calls)
	}
}

func TestResolverServeStaleOnErrorBeyondStaleWindow(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	c := cache.New(cache.Options{
		MaxEntries:  4,
		MinTTL:      time.Second,
		MaxTTL:      time.Hour,
		StaleWindow: 5 * time.Minute,
		StaleMaxAge: time.Hour,
		Now:         func() time.Time { return now },
	})
	r := New(DefaultConfig(), c)

	msg := &protocol.Message{
		Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
		Answers: []protocol.ResourceRecord{{
			Name:  "stale.example.com.",
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   60,
			Data:  protocol.AData{Address: [4]byte{9, 9, 9, 9}},
		}},
	}
	c.Set(cacheKey("stale.example.com.", protocol.TypeA), msg, 10*time.Second)

	now = now.Add(11 * time.Minute)
	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []ResolutionEvent, error) {
		return nil, nil, fmt.Errorf("upstream timeout")
	})

	res, err := r.Resolve(context.Background(), "stale.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !res.Cached || !res.Stale || !res.StaleOnError {
		t.Fatalf("expected stale-on-error cached response, got cached=%v stale=%v stale_on_error=%v", res.Cached, res.Stale, res.StaleOnError)
	}
	if res.Message == nil || len(res.Message.Answers) == 0 {
		t.Fatalf("expected stale answer to be returned")
	}
}

func TestDNSSECStatusClassification(t *testing.T) {
	t.Parallel()
	secure := &protocol.Message{
		Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
		Answers: []protocol.ResourceRecord{{
			Name:  "example.com.",
			Type:  protocol.TypeRRSIG,
			Class: protocol.ClassIN,
			TTL:   60,
			Data: protocol.RRSIGData{
				TypeCovered: protocol.TypeA, Algorithm: 8, Labels: 2, OriginalTTL: 60,
				Expiration: 1, Inception: 1, KeyTag: 1, SignerName: "example.com.", Signature: []byte{1},
			},
		}},
		Additionals: []protocol.ResourceRecord{{
			Name:  "example.com.",
			Type:  protocol.TypeDNSKEY,
			Class: protocol.ClassIN,
			TTL:   60,
			Data:  protocol.DNSKEYData{Flags: 257, Protocol: 3, Algorithm: 8, PublicKey: []byte{1, 2}},
		}},
	}
	if got := dnssecStatus(secure); got != "secure" {
		t.Fatalf("expected secure, got %s", got)
	}

	indeterminate := &protocol.Message{
		Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError},
		Answers: []protocol.ResourceRecord{{
			Name:  "example.com.",
			Type:  protocol.TypeRRSIG,
			Class: protocol.ClassIN,
			TTL:   60,
			Data: protocol.RRSIGData{
				TypeCovered: protocol.TypeA, Algorithm: 8, Labels: 2, OriginalTTL: 60,
				Expiration: 1, Inception: 1, KeyTag: 1, SignerName: "example.com.", Signature: []byte{1},
			},
		}},
	}
	if got := dnssecStatus(indeterminate); got != "indeterminate" {
		t.Fatalf("expected indeterminate, got %s", got)
	}

	insecure := &protocol.Message{Header: protocol.Header{QR: true, RCode: protocol.RCodeNoError}}
	if got := dnssecStatus(insecure); got != "insecure" {
		t.Fatalf("expected insecure, got %s", got)
	}

	bogus := &protocol.Message{Header: protocol.Header{QR: true, RCode: protocol.RCodeServerFailure}}
	if got := dnssecStatus(bogus); got != "bogus" {
		t.Fatalf("expected bogus, got %s", got)
	}
}

func referral(zone, ns string, ip [4]byte) *protocol.Message {
	return &protocol.Message{
		Header:      protocol.Header{QR: true, RCode: protocol.RCodeNoError},
		Authorities: []protocol.ResourceRecord{{Name: zone, Type: protocol.TypeNS, Class: protocol.ClassIN, TTL: 60, Data: protocol.NSData{Name: ns}}},
		Additionals: []protocol.ResourceRecord{{Name: ns, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 60, Data: protocol.AData{Address: ip}}},
	}
}

func referralNoGlue(zone, ns string) *protocol.Message {
	return &protocol.Message{
		Header:      protocol.Header{QR: true, RCode: protocol.RCodeNoError},
		Authorities: []protocol.ResourceRecord{{Name: zone, Type: protocol.TypeNS, Class: protocol.ClassIN, TTL: 60, Data: protocol.NSData{Name: ns}}},
	}
}

func BenchmarkResolveFromCache(b *testing.B) {
	cfg := DefaultConfig()
	cfg.QNAMEMinimization = false
	c := cache.New(cache.Options{})
	r := New(cfg, c)
	msg := &protocol.Message{
		Header:  protocol.Header{QR: true, RCode: protocol.RCodeNoError},
		Answers: []protocol.ResourceRecord{{Name: "bench.example.", Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 60, Data: protocol.AData{Address: [4]byte{1, 2, 3, 4}}}},
	}
	c.Set(cacheKey("bench.example.", protocol.TypeA), msg, time.Minute)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Resolve(context.Background(), "bench.example.", protocol.TypeA); err != nil {
			b.Fatalf("resolve: %v", err)
		}
	}
}
