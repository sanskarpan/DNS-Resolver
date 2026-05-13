package cache

import (
	"path/filepath"
	"testing"
	"time"

	"dnsresolver/internal/protocol"
)

func testMessage(name string, rrType uint16) *protocol.Message {
	msg := &protocol.Message{
		Header:    protocol.Header{ID: 1, QR: true},
		Questions: []protocol.Question{{Name: name, Type: rrType, Class: protocol.ClassIN}},
	}
	switch rrType {
	case protocol.TypeA:
		msg.Answers = []protocol.ResourceRecord{{Name: name, Type: rrType, Class: protocol.ClassIN, TTL: 60, Data: protocol.AData{Address: [4]byte{1, 2, 3, 4}}}}
	case protocol.TypeAAAA:
		msg.Answers = []protocol.ResourceRecord{{Name: name, Type: rrType, Class: protocol.ClassIN, TTL: 60, Data: protocol.AAAAData{Address: [16]byte{0x20, 0x01, 0x0d, 0xb8}}}}
	default:
		msg.Answers = []protocol.ResourceRecord{{Name: name, Type: protocol.TypeCNAME, Class: protocol.ClassIN, TTL: 60, Data: protocol.CNAMEData{Name: "target.example."}}}
	}
	return msg
}

func TestCacheTTLExpiration(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	c := New(Options{MaxEntries: 4, MinTTL: time.Second, MaxTTL: time.Hour, StaleWindow: 0, StaleMaxAge: time.Hour, Now: func() time.Time { return now }})
	c.Set("a", testMessage("a.example.", protocol.TypeA), 2*time.Second)
	if got := c.Get("a"); !got.Hit {
		t.Fatalf("expected hit before expiry")
	}
	now = now.Add(3 * time.Second)
	if got := c.Get("a"); got.Hit {
		t.Fatalf("expected miss after expiry")
	}
}

func TestCacheLRUEviction(t *testing.T) {
	t.Parallel()
	c := New(Options{MaxEntries: 2, MinTTL: time.Second, MaxTTL: time.Hour, StaleWindow: time.Minute, StaleMaxAge: time.Hour})
	c.Set("a", testMessage("a.example.", protocol.TypeA), time.Minute)
	c.Set("b", testMessage("b.example.", protocol.TypeA), time.Minute)
	_ = c.Get("a")
	c.Set("c", testMessage("c.example.", protocol.TypeA), time.Minute)

	if got := c.Get("b"); got.Hit {
		t.Fatalf("expected b to be evicted (least recently used)")
	}
	if got := c.Get("a"); !got.Hit {
		t.Fatalf("expected a to remain (recently used)")
	}
}

func TestCacheStaleWhileRevalidate(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	c := New(Options{
		MaxEntries:  10,
		MinTTL:      time.Second,
		MaxTTL:      time.Hour,
		StaleWindow: 5 * time.Minute,
		StaleMaxAge: time.Hour,
		Now:         func() time.Time { return now },
	})
	c.Set("stale.example.", testMessage("stale.example.", protocol.TypeA), 30*time.Second)
	now = now.Add(31 * time.Second)

	result := c.Get("stale.example.")
	if !result.Stale {
		t.Fatalf("expected stale entry")
	}
}

func TestNegativeCacheEntry(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	c := New(Options{MaxEntries: 10, MinTTL: time.Second, MaxTTL: time.Hour, StaleWindow: time.Minute, StaleMaxAge: time.Hour, Now: func() time.Time { return now }})

	c.SetNegative("n", protocol.RCodeNameError, time.Minute, "soa")
	neg, ok := c.GetNegative("n")
	if !ok {
		t.Fatalf("expected negative cache hit")
	}
	if neg.RCode != protocol.RCodeNameError {
		t.Fatalf("expected NXDOMAIN negative entry, got %d", neg.RCode)
	}
}

func TestCacheStats(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	c := New(Options{
		MaxEntries:  10,
		MinTTL:      time.Second,
		MaxTTL:      time.Hour,
		StaleWindow: 5 * time.Minute,
		StaleMaxAge: time.Hour,
		Now:         func() time.Time { return now },
	})
	c.Set("fresh", testMessage("fresh.example.", protocol.TypeA), 60*time.Second)
	c.Set("stale", testMessage("stale.example.", protocol.TypeA), 10*time.Second)
	now = now.Add(11 * time.Second)

	stats := c.Stats()
	if stats.Entries != 2 {
		t.Fatalf("expected entries=2, got %d", stats.Entries)
	}
	if stats.StaleEntries != 1 {
		t.Fatalf("expected stale_entries=1, got %d", stats.StaleEntries)
	}
	if stats.PositiveEntries != 1 {
		t.Fatalf("expected positive_entries=1, got %d", stats.PositiveEntries)
	}
	if stats.MemoryBytes == 0 {
		t.Fatalf("expected memory estimate to be populated")
	}
}

func TestPersistence(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")
	c := New(Options{MaxEntries: 4, MinTTL: time.Second, MaxTTL: time.Hour, StaleWindow: time.Minute, StaleMaxAge: time.Hour, PersistPath: path})
	c.Set("a", testMessage("a.example.", protocol.TypeA), time.Minute)
	c.SetNegative("n", protocol.RCodeNameError, time.Minute, "soa")
	if err := c.Persist(); err != nil {
		t.Fatalf("persist: %v", err)
	}

	loaded := New(Options{MaxEntries: 4, MinTTL: time.Second, MaxTTL: time.Hour, StaleWindow: time.Minute, StaleMaxAge: time.Hour, PersistPath: path})
	if err := loaded.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := loaded.Get("a"); !got.Hit {
		t.Fatalf("expected loaded key")
	}
	if _, ok := loaded.GetNegative("n"); !ok {
		t.Fatalf("expected loaded negative key")
	}
}

func TestCacheDeleteEntry(t *testing.T) {
	t.Parallel()
	c := New(Options{MaxEntries: 10, MinTTL: time.Second, MaxTTL: time.Hour, StaleWindow: time.Minute, StaleMaxAge: time.Hour})
	c.Set("a", testMessage("a.example.", protocol.TypeA), time.Minute)
	if got := c.Get("a"); !got.Hit {
		t.Fatalf("expected hit before delete")
	}
	c.Delete("a")
	if got := c.Get("a"); got.Hit {
		t.Fatalf("expected miss after delete")
	}
}

func TestCacheFlushAll(t *testing.T) {
	t.Parallel()
	c := New(Options{MaxEntries: 10, MinTTL: time.Second, MaxTTL: time.Hour, StaleWindow: time.Minute, StaleMaxAge: time.Hour})
	c.Set("a", testMessage("a.example.", protocol.TypeA), time.Minute)
	c.Set("b", testMessage("b.example.", protocol.TypeA), time.Minute)
	c.Flush()
	if got := c.Get("a"); got.Hit {
		t.Fatalf("expected miss after flush")
	}
	if got := c.Get("b"); got.Hit {
		t.Fatalf("expected miss after flush")
	}
}

func TestCacheRuntimeConfig(t *testing.T) {
	t.Parallel()
	c := New(Options{MaxEntries: 100, MinTTL: 10 * time.Second, MaxTTL: time.Hour, StaleWindow: time.Minute, StaleMaxAge: time.Hour})

	cfg := c.RuntimeConfig()
	if cfg.MaxEntries != 100 {
		t.Fatalf("expected MaxEntries=100, got %d", cfg.MaxEntries)
	}
	if cfg.MinTTL != 10*time.Second {
		t.Fatalf("expected MinTTL=10s, got %v", cfg.MinTTL)
	}
}

func TestCacheApplyRuntimeConfig(t *testing.T) {
	t.Parallel()
	c := New(Options{MaxEntries: 100, MinTTL: 10 * time.Second, MaxTTL: time.Hour, StaleWindow: time.Minute, StaleMaxAge: time.Hour})

	maxEntries := 200
	minTTL := 20 * time.Second

	c.ApplyRuntimeConfig(RuntimeConfigUpdate{
		MaxEntries: &maxEntries,
		MinTTL:     &minTTL,
	})

	cfg := c.RuntimeConfig()
	if cfg.MaxEntries != 200 {
		t.Fatalf("expected MaxEntries=200, got %d", cfg.MaxEntries)
	}
	if cfg.MinTTL != 20*time.Second {
		t.Fatalf("expected MinTTL=20s, got %v", cfg.MinTTL)
	}
}

func TestCacheListEntries(t *testing.T) {
	t.Parallel()
	c := New(Options{MaxEntries: 10, MinTTL: time.Second, MaxTTL: time.Hour, StaleWindow: time.Minute, StaleMaxAge: time.Hour})
	c.Set("a", testMessage("a.example.", protocol.TypeA), time.Minute)
	c.Set("b", testMessage("b.example.", protocol.TypeA), time.Minute)

	entries := c.List(1, 10)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
}

func TestTTLFromSOARecord(t *testing.T) {
	msg := &protocol.Message{
		Header: protocol.Header{QR: true},
		Answers: []protocol.ResourceRecord{{
			Name:  "example.com.",
			Type:  protocol.TypeSOA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  protocol.SOAData{Serial: 12345},
		}},
	}
	_ = TTLFromSOA(msg)
}

func BenchmarkCacheGet(b *testing.B) {
	c := New(Options{MaxEntries: 1, MinTTL: time.Second, MaxTTL: time.Hour, StaleWindow: time.Minute, StaleMaxAge: time.Hour})
	c.Set("a", testMessage("a.example.", protocol.TypeA), time.Minute)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.Get("a")
	}
}

func BenchmarkCacheSet(b *testing.B) {
	c := New(Options{MaxEntries: 10000, MinTTL: time.Second, MaxTTL: time.Hour, StaleWindow: time.Minute, StaleMaxAge: time.Hour})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Set("a", testMessage("a.example.", protocol.TypeA), time.Minute)
	}
}

func BenchmarkCacheParallel(b *testing.B) {
	c := New(Options{MaxEntries: 1000, MinTTL: time.Second, MaxTTL: time.Hour, StaleWindow: time.Minute, StaleMaxAge: time.Hour})
	c.Set("a", testMessage("a.example.", protocol.TypeA), time.Minute)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = c.Get("a")
			c.Set("a", testMessage("a.example.", protocol.TypeA), time.Minute)
		}
	})
}
