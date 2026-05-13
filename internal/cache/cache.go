package cache

import (
	"container/list"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"dnsresolver/internal/protocol"
)

type Options struct {
	MaxEntries  int
	MinTTL      time.Duration
	MaxTTL      time.Duration
	StaleWindow time.Duration
	StaleMaxAge time.Duration
	PersistPath string
	Now         func() time.Time
	Prefetch    func(string)
}

type entry struct {
	key         string
	value       *protocol.Message
	expiresAt   time.Time
	staleUntil  time.Time
	lastGood    *protocol.Message
	lastGoodAt  time.Time
	hits        int
	originalTTL time.Duration
	refreshing  bool
	expired     bool
	size        uint64
}

type Cache struct {
	mu sync.RWMutex

	maxEntries  int
	minTTL      time.Duration
	maxTTL      time.Duration
	staleWindow time.Duration
	staleMaxAge time.Duration
	persistPath string
	nowFn       func() time.Time
	prefetch    func(string)

	lru      *list.List
	items    map[string]*list.Element
	negative map[string]NegativeEntry
	stats    Stats
}

type RuntimeConfig struct {
	MaxEntries  int           `json:"cache_max_entries"`
	MinTTL      time.Duration `json:"cache_min_ttl"`
	MaxTTL      time.Duration `json:"cache_max_ttl"`
	StaleWindow time.Duration `json:"cache_stale_window"`
	StaleMaxAge time.Duration `json:"cache_stale_max_age"`
}

type RuntimeConfigUpdate struct {
	MaxEntries  *int
	MinTTL      *time.Duration
	MaxTTL      *time.Duration
	StaleWindow *time.Duration
	StaleMaxAge *time.Duration
}

func New(opts Options) *Cache {
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = 10000
	}
	if opts.MinTTL <= 0 {
		opts.MinTTL = 30 * time.Second
	}
	if opts.MaxTTL < opts.MinTTL {
		opts.MaxTTL = 24 * time.Hour
	}
	if opts.StaleWindow < 0 {
		opts.StaleWindow = 5 * time.Minute
	}
	if opts.StaleMaxAge < opts.StaleWindow {
		opts.StaleMaxAge = time.Hour
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Cache{
		maxEntries:  opts.MaxEntries,
		minTTL:      opts.MinTTL,
		maxTTL:      opts.MaxTTL,
		staleWindow: opts.StaleWindow,
		staleMaxAge: opts.StaleMaxAge,
		persistPath: opts.PersistPath,
		nowFn:       opts.Now,
		prefetch:    opts.Prefetch,
		lru:         list.New(),
		items:       make(map[string]*list.Element, opts.MaxEntries),
		negative:    make(map[string]NegativeEntry),
	}
}

type GetResult struct {
	Message      *protocol.Message
	Hit          bool
	Stale        bool
	StaleOnError bool
}

func (c *Cache) SetPrefetchCallback(cb func(string)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prefetch = cb
}

func (c *Cache) Set(key string, value *protocol.Message, ttl time.Duration) {
	if value == nil || key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	ttl = c.clampTTL(ttl)
	item := &entry{
		key:         key,
		value:       cloneMessage(value),
		expiresAt:   now.Add(ttl),
		staleUntil:  now.Add(ttl).Add(c.staleWindow),
		lastGood:    cloneMessage(value),
		lastGoodAt:  now,
		hits:        0,
		originalTTL: ttl,
	}
	item.size = uint64(len(key)) + messageSizeEstimate(item.value)

	if el, ok := c.items[key]; ok {
		existing := el.Value.(*entry)
		c.stats.MemoryBytes -= existing.size
		el.Value = item
		c.lru.MoveToFront(el)
		c.stats.MemoryBytes += item.size
		c.touchStatsLocked()
		return
	}

	el := c.lru.PushFront(item)
	c.items[key] = el
	c.stats.MemoryBytes += item.size

	if c.lru.Len() > c.maxEntries {
		c.evictOldestLocked()
	}
	c.touchStatsLocked()
}

func (c *Cache) Get(key string) GetResult {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	el, ok := c.items[key]
	if !ok {
		c.stats.Misses++
		c.touchStatsLocked()
		return GetResult{}
	}
	item := el.Value.(*entry)
	item.hits++
	c.lru.MoveToFront(el)

	if now.Before(item.expiresAt) {
		c.stats.Hits++
		c.maybePrefetchLocked(item, now)
		c.touchStatsLocked()
		return GetResult{Message: cloneMessage(item.value), Hit: true}
	}
	if !item.expired {
		item.expired = true
		c.stats.Expirations++
	}
	if now.Before(item.staleUntil) {
		c.stats.Hits++
		c.stats.StaleHits++
		c.maybePrefetchLocked(item, now)
		c.touchStatsLocked()
		return GetResult{Message: cloneMessage(item.value), Hit: true, Stale: true}
	}
	if item.lastGood != nil && !item.lastGoodAt.IsZero() && now.Sub(item.lastGoodAt) <= c.staleMaxAge {
		c.stats.Misses++
		c.touchStatsLocked()
		return GetResult{}
	}
	c.removeElementLocked(el)
	c.stats.Misses++
	c.touchStatsLocked()
	return GetResult{}
}

func (c *Cache) maybePrefetchLocked(item *entry, now time.Time) {
	if c.prefetch == nil || item.refreshing || item.hits < 3 || item.originalTTL <= 0 {
		return
	}
	remaining := item.expiresAt.Sub(now)
	if remaining > item.originalTTL/10 {
		return
	}
	item.refreshing = true
	key := item.key
	cb := c.prefetch
	c.stats.Prefetches++
	go func() {
		defer func() {
			c.mu.Lock()
			if el, ok := c.items[key]; ok {
				el.Value.(*entry).refreshing = false
			}
			c.mu.Unlock()
		}()
		cb(key)
	}()
}

func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.removeElementLocked(el)
	}
	delete(c.negative, key)
	c.touchStatsLocked()
}

func (c *Cache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lru = list.New()
	c.items = make(map[string]*list.Element, c.maxEntries)
	c.negative = make(map[string]NegativeEntry)
	c.stats.MemoryBytes = 0
	c.touchStatsLocked()
}

func (c *Cache) Stats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	copyStats := c.stats
	now := c.now()
	copyStats.Entries = len(c.items)
	copyStats.NegativeEntries = len(c.negative)
	copyStats.StaleEntries = 0
	copyStats.PositiveEntries = 0
	for _, el := range c.items {
		item := el.Value.(*entry)
		if now.After(item.expiresAt) && now.Before(item.staleUntil) {
			copyStats.StaleEntries++
			continue
		}
		copyStats.PositiveEntries++
	}
	copyStats.UpdatedAt = now
	return copyStats
}

func (c *Cache) RuntimeConfig() RuntimeConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return RuntimeConfig{
		MaxEntries:  c.maxEntries,
		MinTTL:      c.minTTL,
		MaxTTL:      c.maxTTL,
		StaleWindow: c.staleWindow,
		StaleMaxAge: c.staleMaxAge,
	}
}

func (c *Cache) ApplyRuntimeConfig(update RuntimeConfigUpdate) RuntimeConfig {
	c.mu.Lock()
	defer c.mu.Unlock()

	if update.MaxEntries != nil && *update.MaxEntries > 0 {
		c.maxEntries = *update.MaxEntries
		for c.lru.Len() > c.maxEntries {
			c.evictOldestLocked()
		}
	}
	if update.MinTTL != nil && *update.MinTTL > 0 {
		c.minTTL = *update.MinTTL
	}
	if update.MaxTTL != nil && *update.MaxTTL > 0 {
		c.maxTTL = *update.MaxTTL
	}
	if c.maxTTL < c.minTTL {
		c.maxTTL = c.minTTL
	}
	if update.StaleWindow != nil && *update.StaleWindow >= 0 {
		c.staleWindow = *update.StaleWindow
	}
	if update.StaleMaxAge != nil && *update.StaleMaxAge >= 0 {
		c.staleMaxAge = *update.StaleMaxAge
	}
	if c.staleMaxAge < c.staleWindow {
		c.staleMaxAge = c.staleWindow
	}
	c.touchStatsLocked()
	return RuntimeConfig{
		MaxEntries:  c.maxEntries,
		MinTTL:      c.minTTL,
		MaxTTL:      c.maxTTL,
		StaleWindow: c.staleWindow,
		StaleMaxAge: c.staleMaxAge,
	}
}

type ListItem struct {
	Key        string    `json:"key"`
	ExpiresAt  time.Time `json:"expires_at"`
	StaleUntil time.Time `json:"stale_until"`
	Hits       int       `json:"hits"`
	TTL        int64     `json:"ttl_seconds"`
}

func (c *Cache) List(page, limit int) []ListItem {
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	offset := (page - 1) * limit

	c.mu.RLock()
	defer c.mu.RUnlock()
	items := make([]ListItem, 0, limit)
	now := c.now()
	i := 0
	for el := c.lru.Front(); el != nil; el = el.Next() {
		if i < offset {
			i++
			continue
		}
		if len(items) == limit {
			break
		}
		e := el.Value.(*entry)
		ttl := int64(e.expiresAt.Sub(now).Seconds())
		items = append(items, ListItem{Key: e.key, ExpiresAt: e.expiresAt, StaleUntil: e.staleUntil, Hits: e.hits, TTL: ttl})
		i++
	}
	return items
}

func (c *Cache) Persist() error {
	if c.persistPath == "" {
		return nil
	}
	c.mu.RLock()
	snap := cacheSnapshot{
		SavedAt:  c.now(),
		Entries:  make([]snapshotEntry, 0, len(c.items)),
		Negative: make([]NegativeEntry, 0, len(c.negative)),
	}
	for _, el := range c.items {
		e := el.Value.(*entry)
		wire, err := protocol.Encode(e.value)
		if err != nil {
			continue
		}
		var lastGood []byte
		if e.lastGood != nil {
			lastGood, _ = protocol.Encode(e.lastGood)
		}
		snap.Entries = append(snap.Entries, snapshotEntry{
			Key:          e.key,
			Wire:         wire,
			ExpiresAt:    e.expiresAt,
			StaleUntil:   e.staleUntil,
			LastGoodWire: lastGood,
			LastGoodAt:   e.lastGoodAt,
			Hits:         e.hits,
			OriginalTTL:  e.originalTTL,
		})
	}
	for _, neg := range c.negative {
		snap.Negative = append(snap.Negative, neg)
	}
	c.mu.RUnlock()

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	tmp := c.persistPath + ".tmp"
	if err := os.MkdirAll(filepath.Dir(c.persistPath), 0o755); err != nil && filepath.Dir(c.persistPath) != "." {
		return fmt.Errorf("mkdir persist dir: %w", err)
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write snapshot tmp: %w", err)
	}
	if err := os.Rename(tmp, c.persistPath); err != nil {
		return fmt.Errorf("rename snapshot: %w", err)
	}
	return nil
}

func (c *Cache) Load() error {
	if c.persistPath == "" {
		return nil
	}
	data, err := os.ReadFile(c.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read snapshot: %w", err)
	}
	var snap cacheSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("unmarshal snapshot: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.lru = list.New()
	c.items = make(map[string]*list.Element, c.maxEntries)
	c.negative = make(map[string]NegativeEntry, len(snap.Negative))
	c.stats.MemoryBytes = 0

	now := c.now()
	for _, it := range snap.Entries {
		if now.After(it.StaleUntil) {
			continue
		}
		msg, err := protocol.Decode(it.Wire)
		if err != nil {
			continue
		}
		var lastGood *protocol.Message
		if len(it.LastGoodWire) > 0 {
			if lg, err := protocol.Decode(it.LastGoodWire); err == nil {
				lastGood = lg
			}
		}
		e := &entry{
			key:         it.Key,
			value:       msg,
			expiresAt:   it.ExpiresAt,
			staleUntil:  it.StaleUntil,
			lastGood:    lastGood,
			lastGoodAt:  it.LastGoodAt,
			hits:        it.Hits,
			originalTTL: it.OriginalTTL,
			expired:     now.After(it.ExpiresAt),
		}
		e.size = uint64(len(e.key)) + messageSizeEstimate(e.value)
		el := c.lru.PushBack(e)
		c.items[e.key] = el
		c.stats.MemoryBytes += e.size
	}
	for _, neg := range snap.Negative {
		if now.Before(neg.ExpiresAt) {
			c.negative[neg.Key] = neg
		}
	}
	for c.lru.Len() > c.maxEntries {
		c.evictOldestLocked()
	}
	c.touchStatsLocked()
	return nil
}

type cacheSnapshot struct {
	SavedAt  time.Time       `json:"saved_at"`
	Entries  []snapshotEntry `json:"entries"`
	Negative []NegativeEntry `json:"negative"`
}

type snapshotEntry struct {
	Key          string        `json:"key"`
	Wire         []byte        `json:"wire"`
	ExpiresAt    time.Time     `json:"expires_at"`
	StaleUntil   time.Time     `json:"stale_until"`
	LastGoodWire []byte        `json:"last_good_wire,omitempty"`
	LastGoodAt   time.Time     `json:"last_good_at"`
	Hits         int           `json:"hits"`
	OriginalTTL  time.Duration `json:"original_ttl"`
}

func (c *Cache) evictOldestLocked() {
	el := c.lru.Back()
	if el == nil {
		return
	}
	c.removeElementLocked(el)
	c.stats.Evictions++
}

func (c *Cache) removeElementLocked(el *list.Element) {
	item := el.Value.(*entry)
	delete(c.items, item.key)
	c.lru.Remove(el)
	if c.stats.MemoryBytes >= item.size {
		c.stats.MemoryBytes -= item.size
	} else {
		c.stats.MemoryBytes = 0
	}
}

func (c *Cache) clampTTL(ttl time.Duration) time.Duration {
	if ttl < c.minTTL {
		return c.minTTL
	}
	if ttl > c.maxTTL {
		return c.maxTTL
	}
	return ttl
}

func (c *Cache) now() time.Time {
	return c.nowFn().UTC()
}

func (c *Cache) touchStatsLocked() {
	c.stats.Entries = len(c.items)
	c.stats.NegativeEntries = len(c.negative)
	c.stats.UpdatedAt = c.now()
}

func cloneMessage(msg *protocol.Message) *protocol.Message {
	if msg == nil {
		return nil
	}
	wire, err := protocol.Encode(msg)
	if err != nil {
		return msg
	}
	cloned, err := protocol.Decode(wire)
	if err != nil {
		return msg
	}
	return cloned
}

func messageSizeEstimate(msg *protocol.Message) uint64 {
	if msg == nil {
		return 0
	}
	wire, err := protocol.Encode(msg)
	if err != nil {
		return 0
	}
	return uint64(len(wire))
}
