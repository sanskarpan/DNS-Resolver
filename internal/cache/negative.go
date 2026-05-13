package cache

import (
	"time"

	"dnsresolver/internal/protocol"
)

type NegativeEntry struct {
	Key       string    `json:"key"`
	RCode     uint8     `json:"rcode"`
	ExpiresAt time.Time `json:"expires_at"`
	SOA       string    `json:"soa,omitempty"`
}

func (c *Cache) SetNegative(key string, rcode uint8, ttl time.Duration, soa string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ttl = c.clampTTL(ttl)
	now := c.now()
	c.negative[key] = NegativeEntry{
		Key:       key,
		RCode:     rcode,
		ExpiresAt: now.Add(ttl),
		SOA:       soa,
	}
}

func (c *Cache) GetNegative(key string) (NegativeEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.negative[key]
	if !ok {
		c.stats.Misses++
		return NegativeEntry{}, false
	}
	if c.now().After(entry.ExpiresAt) {
		delete(c.negative, key)
		c.stats.Expirations++
		c.stats.Misses++
		return NegativeEntry{}, false
	}
	c.stats.Hits++
	return entry, true
}

func TTLFromSOA(msg *protocol.Message) time.Duration {
	if msg == nil {
		return 0
	}
	for _, rr := range msg.Authorities {
		if rr.Type != protocol.TypeSOA {
			continue
		}
		if soa, ok := rr.Data.(protocol.SOAData); ok {
			return time.Duration(soa.Minimum) * time.Second
		}
	}
	return 0
}
