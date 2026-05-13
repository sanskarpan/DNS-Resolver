package resolver

import (
	"context"
	"testing"

	"dnsresolver/internal/cache"
	"dnsresolver/internal/protocol"
)

func TestBlocklistParsesDomainsHostsAndWildcards(t *testing.T) {
	t.Parallel()
	bl := NewBlocklist()
	bl.Replace([]string{
		"# comment",
		"example.com",
		"0.0.0.0 ads.example.org tracker.example.org",
		"127.0.0.1 telemetry.example.net # inline comment",
		"*.wild.example",
	})

	blocked := []string{
		"example.com.",
		"ads.example.org.",
		"tracker.example.org.",
		"telemetry.example.net.",
		"foo.wild.example.",
		"bar.foo.wild.example.",
	}
	for _, d := range blocked {
		if !bl.IsBlocked(d) {
			t.Fatalf("expected blocked: %s", d)
		}
	}
	allowed := []string{"wild.example.", "example.net.", "ok.example.org."}
	for _, d := range allowed {
		if bl.IsBlocked(d) {
			t.Fatalf("expected allowed: %s", d)
		}
	}

	stats := bl.Stats()
	if stats.DomainsCount != 5 {
		t.Fatalf("domains_count=%d want=5", stats.DomainsCount)
	}
	if stats.SessionHits < uint64(len(blocked)) {
		t.Fatalf("session_hits=%d want>=%d", stats.SessionHits, len(blocked))
	}
}

func TestResolverBlockedDomainReturnsNXDOMAIN(t *testing.T) {
	t.Parallel()
	r := New(DefaultConfig(), cache.New(cache.Options{}))
	r.ReplaceBlocklist("ads.example.com\n*.tracking.example")

	// If this function is called, blocklist bypass failed.
	r.SetQueryFunc(func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []ResolutionEvent, error) {
		t.Fatalf("upstream query should not be called for blocked domain")
		return nil, nil, nil
	})

	res, err := r.Resolve(context.Background(), "ads.example.com", protocol.TypeA)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !res.Blocked {
		t.Fatalf("expected blocked result")
	}
	if res.Message == nil || res.Message.Header.RCode != protocol.RCodeNameError {
		t.Fatalf("expected NXDOMAIN for blocked domain")
	}

	res2, err := r.Resolve(context.Background(), "cdn.tracking.example", protocol.TypeA)
	if err != nil {
		t.Fatalf("resolve wildcard: %v", err)
	}
	if !res2.Blocked || res2.Message.Header.RCode != protocol.RCodeNameError {
		t.Fatalf("expected wildcard blocked NXDOMAIN")
	}

	sec := r.SecurityStats()
	if sec["blocklist"] < 2 {
		t.Fatalf("expected blocklist security counter increment, got=%d", sec["blocklist"])
	}
}
