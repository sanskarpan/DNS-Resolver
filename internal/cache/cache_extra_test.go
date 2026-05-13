package cache

import (
	"testing"
	"time"

	"dnsresolver/internal/protocol"
)

func TestCachePrefetchTriggeredNearExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	prefetchCh := make(chan string, 1)
	c := New(Options{
		MaxEntries:  4,
		MinTTL:      time.Second,
		MaxTTL:      time.Hour,
		StaleWindow: time.Minute,
		StaleMaxAge: time.Hour,
		Now:         func() time.Time { return now },
		Prefetch: func(key string) {
			prefetchCh <- key
		},
	})
	c.Set("prefetch.example.|A", testMessage("prefetch.example.", protocol.TypeA), 10*time.Second)

	now = now.Add(9500 * time.Millisecond)
	for i := 0; i < 3; i++ {
		if got := c.Get("prefetch.example.|A"); !got.Hit {
			t.Fatalf("expected cache hit at iteration %d", i)
		}
	}

	select {
	case key := <-prefetchCh:
		if key != "prefetch.example.|A" {
			t.Fatalf("unexpected prefetch key %q", key)
		}
	case <-time.After(time.Second):
		t.Fatal("expected prefetch callback")
	}
}

func TestGetStaleOnErrorUsesLastGoodWithinMaxAge(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	c := New(Options{
		MaxEntries:  4,
		MinTTL:      time.Second,
		MaxTTL:      time.Hour,
		StaleWindow: time.Second,
		StaleMaxAge: time.Minute,
		Now:         func() time.Time { return now },
	})
	c.Set("stale-on-error.example.|A", testMessage("stale-on-error.example.", protocol.TypeA), 2*time.Second)

	now = now.Add(5 * time.Second)
	msg, ok := c.GetStaleOnError("stale-on-error.example.|A")
	if !ok || msg == nil {
		t.Fatal("expected stale-on-error message within max age")
	}

	now = now.Add(2 * time.Minute)
	msg, ok = c.GetStaleOnError("stale-on-error.example.|A")
	if ok || msg != nil {
		t.Fatal("expected stale-on-error miss after max age")
	}
	if got := c.Get("stale-on-error.example.|A"); got.Hit {
		t.Fatal("expected expired stale-on-error entry to be removed")
	}
}

func TestTTLFromSOAHandlesNilAndAuthoritySOA(t *testing.T) {
	t.Parallel()

	if got := TTLFromSOA(nil); got != 0 {
		t.Fatalf("expected zero ttl for nil message, got %v", got)
	}

	msg := &protocol.Message{
		Authorities: []protocol.ResourceRecord{{
			Name:  "example.com.",
			Type:  protocol.TypeSOA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  protocol.SOAData{Minimum: 42},
		}},
	}
	if got := TTLFromSOA(msg); got != 42*time.Second {
		t.Fatalf("expected 42s ttl from SOA, got %v", got)
	}
}

func TestCacheDefaultsNegativeExpiryAndRuntimeClamps(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	c := New(Options{
		MaxEntries:  0,
		MinTTL:      0,
		MaxTTL:      0,
		StaleWindow: -time.Second,
		StaleMaxAge: 0,
		Now:         func() time.Time { return now },
	})
	cfg := c.RuntimeConfig()
	if cfg.MaxEntries != 10000 {
		t.Fatalf("expected default max entries, got %d", cfg.MaxEntries)
	}
	if cfg.MinTTL != 30*time.Second {
		t.Fatalf("expected default min ttl, got %v", cfg.MinTTL)
	}
	if cfg.MaxTTL != 24*time.Hour {
		t.Fatalf("expected default max ttl, got %v", cfg.MaxTTL)
	}
	if cfg.StaleWindow != 5*time.Minute {
		t.Fatalf("expected default stale window, got %v", cfg.StaleWindow)
	}
	if cfg.StaleMaxAge != time.Hour {
		t.Fatalf("expected default stale max age, got %v", cfg.StaleMaxAge)
	}

	expiring := New(Options{
		MaxEntries:  4,
		MinTTL:      time.Second,
		MaxTTL:      time.Hour,
		StaleWindow: time.Minute,
		StaleMaxAge: time.Hour,
		Now:         func() time.Time { return now },
	})
	expiring.SetNegative("expired-neg", protocol.RCodeNameError, time.Second, "soa")
	now = now.Add(2 * time.Second)
	if _, ok := expiring.GetNegative("expired-neg"); ok {
		t.Fatal("expected expired negative cache entry to miss")
	}
}

func TestCacheSetPrefetchCallbackAndPagination(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	prefetchCh := make(chan string, 1)
	c := New(Options{
		MaxEntries:  10,
		MinTTL:      time.Second,
		MaxTTL:      time.Hour,
		StaleWindow: time.Minute,
		StaleMaxAge: time.Hour,
		Now:         func() time.Time { return now },
	})
	c.SetPrefetchCallback(func(key string) {
		prefetchCh <- key
	})

	c.Set("one|A", testMessage("one.example.", protocol.TypeA), 10*time.Second)
	c.Set("two|A", testMessage("two.example.", protocol.TypeA), 10*time.Second)
	now = now.Add(9500 * time.Millisecond)
	for i := 0; i < 3; i++ {
		_ = c.Get("two|A")
	}

	select {
	case key := <-prefetchCh:
		if key != "two|A" {
			t.Fatalf("unexpected prefetch key %q", key)
		}
	case <-time.After(time.Second):
		t.Fatal("expected prefetch callback from updated prefetch function")
	}

	page := c.List(2, 1)
	if len(page) != 1 || page[0].Key != "one|A" {
		t.Fatalf("unexpected second page items: %+v", page)
	}
}

func TestCacheApplyRuntimeConfigClampsDependentValues(t *testing.T) {
	t.Parallel()

	c := New(Options{MaxEntries: 10, MinTTL: time.Second, MaxTTL: 2 * time.Second, StaleWindow: time.Second, StaleMaxAge: 2 * time.Second})
	maxEntries := 1
	minTTL := 5 * time.Second
	maxTTL := 3 * time.Second
	staleWindow := 10 * time.Second
	staleMaxAge := 4 * time.Second

	cfg := c.ApplyRuntimeConfig(RuntimeConfigUpdate{
		MaxEntries:  &maxEntries,
		MinTTL:      &minTTL,
		MaxTTL:      &maxTTL,
		StaleWindow: &staleWindow,
		StaleMaxAge: &staleMaxAge,
	})
	if cfg.MaxEntries != 1 {
		t.Fatalf("expected max entries 1, got %d", cfg.MaxEntries)
	}
	if cfg.MaxTTL != minTTL {
		t.Fatalf("expected max ttl to clamp to min ttl %v, got %v", minTTL, cfg.MaxTTL)
	}
	if cfg.StaleMaxAge != staleWindow {
		t.Fatalf("expected stale max age to clamp to stale window %v, got %v", staleWindow, cfg.StaleMaxAge)
	}
}
