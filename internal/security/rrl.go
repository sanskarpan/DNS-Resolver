package security

import (
	"sync"
	"time"
)

type rrlBucket struct {
	windowStart time.Time
	count       int
	slipped     int
	lastSeen    time.Time
}

type RRL struct {
	mu         sync.Mutex
	buckets    map[string]*rrlBucket
	limit      int
	slip       int
	gcInterval time.Duration
	lastGC     time.Time
	now        func() time.Time
	drops      uint64
}

func NewRRL(limitPerSec int, slip int) *RRL {
	if limitPerSec <= 0 {
		limitPerSec = 10
	}
	if slip <= 0 {
		slip = 2
	}
	n := time.Now
	return &RRL{
		buckets:    map[string]*rrlBucket{},
		limit:      limitPerSec,
		slip:       slip,
		gcInterval: time.Minute,
		lastGC:     n(),
		now:        n,
	}
}

func (r *RRL) SetClock(now func() time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now = now
	r.lastGC = now()
}

// Allow decides whether to send a response for a tuple key.
// true means send, false means drop due to RRL.
func (r *RRL) Allow(tuple string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if now.Sub(r.lastGC) >= r.gcInterval {
		r.gcLocked(now)
		r.lastGC = now
	}
	b, ok := r.buckets[tuple]
	if !ok {
		r.buckets[tuple] = &rrlBucket{windowStart: now, count: 1, lastSeen: now}
		return true
	}
	if now.Sub(b.windowStart) >= time.Second {
		b.windowStart = now
		b.count = 0
		b.slipped = 0
	}
	b.count++
	b.lastSeen = now
	if b.count <= r.limit {
		return true
	}
	b.slipped++
	if b.slipped%r.slip == 0 {
		return true
	}
	r.drops++
	return false
}

func (r *RRL) Drops() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.drops
}

func (r *RRL) gcLocked(now time.Time) {
	for k, v := range r.buckets {
		if now.Sub(v.lastSeen) > 2*time.Minute {
			delete(r.buckets, k)
		}
	}
}

func (r *RRL) Update(limitPerSec int, slip int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if limitPerSec > 0 {
		r.limit = limitPerSec
	}
	if slip > 0 {
		r.slip = slip
	}
}

func (r *RRL) Config() (limitPerSec int, slip int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.limit, r.slip
}

func (r *RRL) Size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buckets)
}
