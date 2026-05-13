package resolver

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type BlocklistStats struct {
	DomainsCount int       `json:"domains_count"`
	SessionHits  uint64    `json:"session_hits"`
	TotalHits    uint64    `json:"total_hits"`
	LastUpdated  time.Time `json:"last_updated"`
}

type Blocklist struct {
	mu       sync.RWMutex
	exact    map[string]struct{}
	wildcard []string // normalized suffixes (without leading *.) and trailing dot ensured.
	stats    BlocklistStats
}

func NewBlocklist() *Blocklist {
	return &Blocklist{
		exact:    make(map[string]struct{}),
		wildcard: make([]string, 0),
		stats: BlocklistStats{
			LastUpdated: time.Now().UTC(),
		},
	}
}

func (b *Blocklist) LoadFromFile(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open blocklist file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lines := make([]string, 0, 1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan blocklist: %w", err)
	}
	b.Replace(lines)
	return nil
}

func (b *Blocklist) ReplaceFromText(raw string) {
	lines := strings.Split(raw, "\n")
	b.Replace(lines)
}

func (b *Blocklist) Replace(lines []string) {
	exact := make(map[string]struct{})
	wild := make([]string, 0, len(lines))
	for _, line := range lines {
		for _, token := range tokensFromBlocklistLine(line) {
			norm := normalizeFQDN(token)
			if norm == "." {
				continue
			}
			if strings.HasPrefix(norm, "*.") {
				suffix := strings.TrimPrefix(norm, "*.")
				wild = append(wild, suffix)
				continue
			}
			exact[norm] = struct{}{}
		}
	}

	sort.Strings(wild)
	wild = dedupeStrings(wild)

	b.mu.Lock()
	b.exact = exact
	b.wildcard = wild
	b.stats.DomainsCount = len(exact) + len(wild)
	b.stats.LastUpdated = time.Now().UTC()
	b.mu.Unlock()
}

func (b *Blocklist) IsBlocked(domain string) bool {
	norm := normalizeFQDN(domain)
	if norm == "." {
		return false
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.exact[norm]; ok {
		b.stats.SessionHits++
		b.stats.TotalHits++
		return true
	}
	for _, suffix := range b.wildcard {
		if norm == suffix {
			continue
		}
		if strings.HasSuffix(norm, "."+strings.TrimSuffix(suffix, ".")+".") || strings.HasSuffix(norm, suffix) {
			b.stats.SessionHits++
			b.stats.TotalHits++
			return true
		}
	}
	return false
}

func (b *Blocklist) Stats() BlocklistStats {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.stats
}

func (b *Blocklist) Domains() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, 0, len(b.exact)+len(b.wildcard))
	for d := range b.exact {
		out = append(out, d)
	}
	for _, w := range b.wildcard {
		out = append(out, "*."+strings.TrimSuffix(w, "."))
	}
	sort.Strings(out)
	return out
}

func tokensFromBlocklistLine(line string) []string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return nil
	}
	if idx := strings.Index(trimmed, "#"); idx >= 0 {
		trimmed = strings.TrimSpace(trimmed[:idx])
	}
	if trimmed == "" {
		return nil
	}
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return nil
	}

	// hosts-file format: "0.0.0.0 domain" or "127.0.0.1 domain".
	if isIPv4Like(fields[0]) || fields[0] == "::1" || fields[0] == "0:0:0:0:0:0:0:1" {
		if len(fields) < 2 {
			return nil
		}
		return fields[1:]
	}
	return fields
}

func dedupeStrings(in []string) []string {
	if len(in) <= 1 {
		return in
	}
	out := in[:1]
	for i := 1; i < len(in); i++ {
		if in[i] != in[i-1] {
			out = append(out, in[i])
		}
	}
	return out
}

func isIPv4Like(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}
	return true
}
