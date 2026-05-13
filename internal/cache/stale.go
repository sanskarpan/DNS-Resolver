package cache

import "dnsresolver/internal/protocol"

func (c *Cache) GetStaleOnError(key string) (*protocol.Message, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	item := el.Value.(*entry)
	if item.lastGood == nil || item.lastGoodAt.IsZero() {
		return nil, false
	}
	if c.now().Sub(item.lastGoodAt) > c.staleMaxAge {
		c.removeElementLocked(el)
		return nil, false
	}
	return cloneMessage(item.lastGood), true
}
