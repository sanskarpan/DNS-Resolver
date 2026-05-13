package cache

import "time"

type Stats struct {
	Hits            uint64    `json:"hits"`
	Misses          uint64    `json:"misses"`
	StaleHits       uint64    `json:"stale_hits"`
	Evictions       uint64    `json:"evictions"`
	Expirations     uint64    `json:"expirations"`
	Prefetches      uint64    `json:"prefetches"`
	Entries         int       `json:"entries"`
	PositiveEntries int       `json:"positive_entries"`
	StaleEntries    int       `json:"stale_entries"`
	NegativeEntries int       `json:"negative_entries"`
	MemoryBytes     uint64    `json:"memory_bytes"`
	UpdatedAt       time.Time `json:"updated_at"`
}
