package security

import (
	"sync"
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	rl := NewRateLimiter(1, 2)
	rl.SetClock(func() time.Time { return now })

	if !rl.Allow("1.1.1.1") {
		t.Fatalf("first request should pass")
	}
	if !rl.Allow("1.1.1.1") {
		t.Fatalf("second request should pass due burst")
	}
	if rl.Allow("1.1.1.1") {
		t.Fatalf("third request should be dropped")
	}
	now = now.Add(time.Second)
	if !rl.Allow("1.1.1.1") {
		t.Fatalf("token should refill")
	}
}

func TestRateLimiterBlockedIPStats(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	rl := NewRateLimiter(1, 1)
	rl.SetClock(func() time.Time { return now })

	if !rl.Allow("1.1.1.1") {
		t.Fatalf("first request should pass")
	}
	if rl.Allow("1.1.1.1") {
		t.Fatalf("second request should be dropped")
	}
	if rl.Allow("1.1.1.1") {
		t.Fatalf("third request should be dropped")
	}

	blocked := rl.BlockedIPs(10)
	if len(blocked) != 1 {
		t.Fatalf("expected one blocked ip entry, got %d", len(blocked))
	}
	if blocked[0].IP != "1.1.1.1" || blocked[0].Drops != 2 {
		t.Fatalf("unexpected blocked ip entry: %+v", blocked[0])
	}
	if rl.TotalDrops() != 2 {
		t.Fatalf("expected total drops=2, got %d", rl.TotalDrops())
	}
}

func TestRRLSlipMode(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	r := NewRRL(2, 2)
	r.SetClock(func() time.Time { return now })

	results := []bool{r.Allow("tuple"), r.Allow("tuple"), r.Allow("tuple"), r.Allow("tuple"), r.Allow("tuple"), r.Allow("tuple")}
	want := []bool{true, true, false, true, false, true}
	for i := range want {
		if results[i] != want[i] {
			t.Fatalf("idx=%d got=%v want=%v", i, results[i], want[i])
		}
	}
}

func TestRRLGarbageCollection(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	r := NewRRL(2, 2)
	r.SetClock(func() time.Time { return now })

	if !r.Allow("tuple-a") {
		t.Fatalf("initial tuple should be allowed")
	}
	if r.Size() != 1 {
		t.Fatalf("expected one tracked tuple, got %d", r.Size())
	}

	now = now.Add(3 * time.Minute)
	if !r.Allow("tuple-b") {
		t.Fatalf("new tuple should be allowed")
	}
	if r.Size() != 1 {
		t.Fatalf("expected stale tuple to be gc'd, got size=%d", r.Size())
	}
}

func TestCaseRandomization(t *testing.T) {
	t.Parallel()
	cr := NewCaseRandomizer()
	sent, err := cr.RandomizeQName("google.com.")
	if err != nil {
		t.Fatalf("randomize: %v", err)
	}
	if !cr.Matches(sent, sent) {
		t.Fatalf("same case should match")
	}
	if cr.Matches(sent, "google.com.") && sent != "google.com." {
		t.Fatalf("case mismatch should be detected")
	}
}

func TestQueryIDRandomizer(t *testing.T) {
	t.Parallel()
	qid := NewQueryIDRandomizer()
	ids := make([]uint16, 200)
	var wg sync.WaitGroup
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id, err := qid.Acquire()
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			ids[i] = id
		}(i)
	}
	wg.Wait()

	seen := map[uint16]struct{}{}
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			t.Fatalf("duplicate in-flight id: %d", id)
		}
		seen[id] = struct{}{}
		qid.Release(id)
	}
}

func TestPortRange(t *testing.T) {
	t.Parallel()
	p := NewPortRandomizer()
	for i := 0; i < 100; i++ {
		port, err := p.RandomPort()
		if err != nil {
			t.Fatalf("random port: %v", err)
		}
		if port < minEphemeralPort || port > maxEphemeralPort {
			t.Fatalf("port out of range: %d", port)
		}
	}
}

func TestRateLimiterSize(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(10, 10)
	if rl.Size() != 0 {
		t.Fatalf("expected 0 initially")
	}
	rl.Allow("1.1.1.1")
	rl.Allow("2.2.2.2")
	if rl.Size() != 2 {
		t.Fatalf("expected 2 tracked IPs")
	}
}

func TestRateLimiterUpdate(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(1, 1)
	rl.Allow("1.1.1.1")

	rl.Update(10, 10)

	qps, burst := rl.Config()
	if qps != 10 || burst != 10 {
		t.Fatalf("expected qps=10 burst=10, got qps=%v burst=%v", qps, burst)
	}
}

func TestRateLimiterConfig(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(5, 10)
	qps, burst := rl.Config()
	if qps != 5 || burst != 10 {
		t.Fatalf("expected qps=5 burst=10, got qps=%v burst=%v", qps, burst)
	}
}

func TestRRLDrops(t *testing.T) {
	t.Parallel()
	r := NewRRL(1, 0)
	r.Allow("tuple")
	r.Allow("tuple")

	drops := r.Drops()
	if drops != 1 {
		t.Fatalf("expected 1 drop, got %d", drops)
	}
}

func TestRRLUpdate(t *testing.T) {
	t.Parallel()
	r := NewRRL(1, 0)
	r.Allow("tuple")

	r.Update(10, 2)

	limit, slip := r.Config()
	if limit != 10 || slip != 2 {
		t.Fatalf("expected limit=10 slip=2, got limit=%v slip=%v", limit, slip)
	}
}

func TestRRLConfig(t *testing.T) {
	t.Parallel()
	r := NewRRL(5, 1)
	limit, slip := r.Config()
	if limit != 5 || slip != 1 {
		t.Fatalf("expected limit=5 slip=1, got limit=%v slip=%v", limit, slip)
	}
}
