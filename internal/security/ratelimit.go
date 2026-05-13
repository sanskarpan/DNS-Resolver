package security

import (
	"sort"
	"sync"
	"time"
)

type ipBucket struct {
	tokens   float64
	lastSeen time.Time
	drops    uint64
}

type BlockedIP struct {
	IP       string    `json:"ip"`
	Drops    uint64    `json:"drops"`
	LastSeen time.Time `json:"last_seen"`
}

type RateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*ipBucket
	rate       float64
	burst      float64
	gcInterval time.Duration
	lastGC     time.Time
	now        func() time.Time
}

func NewRateLimiter(rate float64, burst int) *RateLimiter {
	if rate <= 0 {
		rate = 100
	}
	if burst <= 0 {
		burst = 200
	}
	n := time.Now
	return &RateLimiter{
		buckets:    map[string]*ipBucket{},
		rate:       rate,
		burst:      float64(burst),
		gcInterval: time.Minute,
		lastGC:     n(),
		now:        n,
	}
}

func (r *RateLimiter) SetClock(now func() time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now = now
	r.lastGC = now()
}

func (r *RateLimiter) Allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if now.Sub(r.lastGC) >= r.gcInterval {
		r.gcLocked(now)
		r.lastGC = now
	}
	b, ok := r.buckets[ip]
	if !ok {
		r.buckets[ip] = &ipBucket{tokens: r.burst - 1, lastSeen: now}
		return true
	}
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * r.rate
	if b.tokens > r.burst {
		b.tokens = r.burst
	}
	b.lastSeen = now
	if b.tokens < 1 {
		b.drops++
		return false
	}
	b.tokens--
	return true
}

func (r *RateLimiter) gcLocked(now time.Time) {
	for k, b := range r.buckets {
		if now.Sub(b.lastSeen) > 2*time.Minute {
			delete(r.buckets, k)
		}
	}
}

func (r *RateLimiter) Size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buckets)
}

func (r *RateLimiter) Update(rate float64, burst int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rate > 0 {
		r.rate = rate
	}
	if burst > 0 {
		r.burst = float64(burst)
	}
}

func (r *RateLimiter) Config() (rate float64, burst int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rate, int(r.burst)
}

func (r *RateLimiter) BlockedIPs(limit int) []BlockedIP {
	r.mu.Lock()
	defer r.mu.Unlock()
	if limit <= 0 {
		limit = 50
	}
	out := make([]BlockedIP, 0, len(r.buckets))
	for ip, bucket := range r.buckets {
		if bucket.drops == 0 {
			continue
		}
		out = append(out, BlockedIP{
			IP:       ip,
			Drops:    bucket.drops,
			LastSeen: bucket.lastSeen.UTC(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Drops == out[j].Drops {
			return out[i].IP < out[j].IP
		}
		return out[i].Drops > out[j].Drops
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (r *RateLimiter) TotalDrops() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	var total uint64
	for _, bucket := range r.buckets {
		total += bucket.drops
	}
	return total
}
