package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"dnsresolver/internal/protocol"
	"dnsresolver/internal/resolver"
)

type compareResult struct {
	Server       string            `json:"server"`
	Error        string            `json:"error,omitempty"`
	RCode        string            `json:"rcode,omitempty"`
	DNSSECStatus string            `json:"dnssec_status,omitempty"`
	Message      *protocol.Message `json:"message,omitempty"`
	Answer       *protocol.Message `json:"answer,omitempty"`
}

type compareDiff struct {
	Available       bool                 `json:"available"`
	BaseServer      string               `json:"base_server,omitempty"`
	BaseRCode       string               `json:"base_rcode,omitempty"`
	RCodeMismatches []compareRCodeDiff   `json:"rcode_mismatches,omitempty"`
	AnswerDiffs     []compareAnswerDiff  `json:"answer_mismatches,omitempty"`
	TTLDiffs        []compareTTLDiffItem `json:"ttl_differences,omitempty"`
}

type compareRCodeDiff struct {
	Server   string `json:"server"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
}

type compareAnswerDiff struct {
	Server  string   `json:"server"`
	Missing []string `json:"missing,omitempty"`
	Extra   []string `json:"extra,omitempty"`
}

type compareTTLDiffItem struct {
	Server   string `json:"server"`
	Record   string `json:"record"`
	Expected uint32 `json:"expected"`
	Actual   uint32 `json:"actual"`
}

type historyItem struct {
	resolver.HistoryEntry
	ClientIP       string `json:"client_ip,omitempty"`
	ClientHostname string `json:"client_hostname,omitempty"`
	Type           string `json:"type"`
}

const (
	maxCompareServers   = 8
	maxBulkQueries      = 100
	maxBulkConcurrency  = 20
	externalDNSDeadline = 5 * time.Second
)

func (a *API) resolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing q"})
		return
	}
	if a.deps.Resolver == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "resolver unavailable"})
		return
	}
	qtype := parseQType(r.URL.Query().Get("type"))
	res, err := a.deps.Resolver.Resolve(r.Context(), q, qtype)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	payload := map[string]any{
		"query":          q,
		"query_type":     protocol.TypeToString(qtype),
		"query_id":       res.QueryID,
		"rcode":          protocol.RCodeToString(res.Message.Header.RCode),
		"cached":         res.Cached,
		"stale":          res.Stale,
		"stale_on_error": res.StaleOnError,
		"dnssec_status":  res.DNSSECStatus,
		"duration_ms":    res.Duration.Milliseconds(),
		"steps":          len(res.Events),
		"blocked":        res.Blocked,
		"message":        res.Message,
	}
	if res.Stale {
		w.Header().Set("X-DNS-Stale", "true")
	}
	if res.StaleOnError {
		w.Header().Set("X-DNS-Stale-On-Error", "true")
	}
	if r.URL.Query().Get("trace") == "1" || strings.EqualFold(r.URL.Query().Get("trace"), "true") {
		payload["trace"] = res.Events
	}
	writeJSON(w, http.StatusOK, payload)
}

func (a *API) index(w http.ResponseWriter, r *http.Request) {
	if a.serveFrontend(w, r) {
		return
	}
	http.NotFound(w, r)
}

func (a *API) cache(w http.ResponseWriter, r *http.Request) {
	if a.deps.Cache == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "cache unavailable"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		rawItems := a.deps.Cache.List(page, limit)
		items := make([]map[string]any, 0, len(rawItems))
		now := time.Now().UTC()
		for _, item := range rawItems {
			recordType := ""
			if parts := strings.Split(item.Key, "|"); len(parts) == 2 {
				recordType = parts[1]
			}
			ttlRemaining := int64(item.ExpiresAt.Sub(now).Seconds())
			if ttlRemaining < 0 {
				ttlRemaining = 0
			}
			stale := now.After(item.ExpiresAt) && now.Before(item.StaleUntil)
			items = append(items, map[string]any{
				"key":           item.Key,
				"type":          recordType,
				"expires_at":    item.ExpiresAt,
				"stale_until":   item.StaleUntil,
				"hits":          item.Hits,
				"ttl":           item.TTL,
				"ttl_remaining": ttlRemaining,
				"stale":         stale,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"entries": items})
	case http.MethodDelete:
		a.deps.Cache.Flush()
		writeJSON(w, http.StatusOK, map[string]any{"status": "flushed"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

func (a *API) cacheKey(w http.ResponseWriter, r *http.Request) {
	if a.deps.Cache == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "cache unavailable"})
		return
	}
	if r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/api/v1/cache/")
	if key == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing key"})
		return
	}
	a.deps.Cache.Delete(key)
	writeJSON(w, http.StatusOK, map[string]any{"status": "evicted", "key": key})
}

func (a *API) cacheStats(w http.ResponseWriter, r *http.Request) {
	if a.deps.Cache == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "cache unavailable"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	stats := a.deps.Cache.Stats()
	total := stats.Hits + stats.Misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(stats.Hits) / float64(total)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"hits":             stats.Hits,
		"misses":           stats.Misses,
		"stale_hits":       stats.StaleHits,
		"evictions":        stats.Evictions,
		"expirations":      stats.Expirations,
		"prefetches":       stats.Prefetches,
		"entries":          stats.Entries,
		"positive_entries": stats.PositiveEntries,
		"stale_entries":    stats.StaleEntries,
		"negative_entries": stats.NegativeEntries,
		"memory_bytes":     stats.MemoryBytes,
		"updated_at":       stats.UpdatedAt,
		"hit_rate":         hitRate,
		"stale":            stats.StaleEntries,
	})
}

func (a *API) metrics(w http.ResponseWriter, r *http.Request) {
	if a.deps.Metrics == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "metrics unavailable"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, a.deps.Metrics.Snapshot())
}

func (a *API) prometheus(w http.ResponseWriter, r *http.Request) {
	if a.deps.Prometheus == nil {
		http.NotFound(w, r)
		return
	}
	a.deps.Prometheus.Handler().ServeHTTP(w, r)
}

func (a *API) history(w http.ResponseWriter, r *http.Request) {
	if a.deps.Resolver == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "resolver unavailable"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items := a.deps.Resolver.History(page, limit)
	out := make([]historyItem, 0, len(items))
	for _, item := range items {
		entry := historyItem{HistoryEntry: item, Type: item.QType}
		if a.deps.DNSHandler != nil {
			if ip, ok := a.deps.DNSHandler.ClientIPForQuery(item.QueryID); ok {
				entry.ClientIP = ip
				entry.ClientHostname = a.deps.DNSHandler.ReverseHostname(ip)
			}
		}
		out = append(out, entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out, "queries": out})
}

func (a *API) historyByID(w http.ResponseWriter, r *http.Request) {
	if a.deps.Resolver == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "resolver unavailable"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, "/api/v1/history/")
	if raw == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing id"})
		return
	}
	if strings.HasSuffix(raw, "/replay") {
		id := strings.TrimSuffix(raw, "/replay")
		id = strings.TrimSuffix(id, "/")
		if id == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing id"})
			return
		}
		a.historyReplay(w, r, id)
		return
	}
	id := strings.TrimSuffix(raw, "/")
	trace := a.deps.Resolver.Trace(id)
	entry, ok := a.deps.Resolver.HistoryEntry(id)
	if len(trace) == 0 && !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "history entry not found"})
		return
	}
	payload := map[string]any{
		"events": trace,
		"trace":  trace,
	}
	if ok {
		payload["query_id"] = entry.QueryID
		payload["query"] = entry.Domain
		payload["domain"] = entry.Domain
		payload["query_type"] = entry.QType
		payload["type"] = entry.QType
		payload["rcode"] = entry.RCode
		payload["duration_ms"] = entry.Duration
		payload["cached"] = entry.Cached
		payload["stale"] = entry.Stale
	}
	writeJSON(w, http.StatusOK, payload)
}

func (a *API) historyReplay(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	events := a.deps.Resolver.Trace(id)
	if len(events) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "history trace not found"})
		return
	}
	seed := events[len(events)-1]
	if strings.TrimSpace(seed.Query) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "history trace missing query"})
		return
	}
	qtype := parseQType(seed.QueryType)
	replayed, err := a.deps.Resolver.Resolve(r.Context(), seed.Query, qtype)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	prev := lastParsedMessage(events)
	diff := compareDiff{Available: false}
	if prev != nil {
		diff = buildCompareDiff([]compareResult{
			{Server: "history", RCode: protocol.RCodeToString(prev.Header.RCode), DNSSECStatus: compareDNSSECStatus(prev), Answer: prev},
			{Server: "replay", RCode: protocol.RCodeToString(replayed.Message.Header.RCode), DNSSECStatus: replayed.DNSSECStatus, Answer: replayed.Message, Message: replayed.Message},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"history_id":       id,
		"query":            seed.Query,
		"query_type":       seed.QueryType,
		"original":         map[string]any{"query": seed.Query, "type": seed.QueryType},
		"previous_message": prev,
		"replay": map[string]any{
			"query":          seed.Query,
			"query_type":     seed.QueryType,
			"query_id":       replayed.QueryID,
			"rcode":          protocol.RCodeToString(replayed.Message.Header.RCode),
			"dnssec_status":  replayed.DNSSECStatus,
			"cached":         replayed.Cached,
			"stale":          replayed.Stale,
			"stale_on_error": replayed.StaleOnError,
			"duration_ms":    replayed.Duration.Milliseconds(),
			"steps":          len(replayed.Events),
			"message":        replayed.Message,
		},
		"diff": diff,
	})
}

func (a *API) reverseLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	ipText := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ipText == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing ip"})
		return
	}
	ip := net.ParseIP(ipText)
	if ip == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid ip"})
		return
	}
	if a.deps.Resolver == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "resolver unavailable"})
		return
	}
	ptrName, ok := reverseNameFromIP(ip)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported ip"})
		return
	}

	res, err := a.deps.Resolver.Resolve(r.Context(), ptrName, protocol.TypePTR)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ip":             ipText,
		"reverse_name":   ptrName,
		"query_id":       res.QueryID,
		"cached":         res.Cached,
		"stale":          res.Stale,
		"stale_on_error": res.StaleOnError,
		"dnssec_status":  res.DNSSECStatus,
		"duration_ms":    res.Duration.Milliseconds(),
		"message":        res.Message,
	})
}

func (a *API) compare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing q"})
		return
	}
	qtype := parseQType(r.URL.Query().Get("type"))
	serversParam := strings.TrimSpace(r.URL.Query().Get("servers"))
	if serversParam == "" {
		serversParam = strings.TrimSpace(r.URL.Query().Get("server"))
	}
	if serversParam == "" {
		serversParam = "1.1.1.1,8.8.8.8,9.9.9.9,208.67.222.222"
	}
	servers := normalizeServers(splitCSV(serversParam))
	if len(servers) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "no valid servers"})
		return
	}
	serverLimitApplied := false
	if len(servers) > maxCompareServers {
		servers = servers[:maxCompareServers]
		serverLimitApplied = true
	}
	out := make([]compareResult, len(servers))
	var wg sync.WaitGroup
	for i, s := range servers {
		wg.Add(1)
		go func(i int, s string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(r.Context(), externalDNSDeadline)
			defer cancel()
			msg, err := resolveViaServer(ctx, s, q, qtype)
			if err != nil {
				out[i] = compareResult{Server: s, Error: err.Error()}
				return
			}
			out[i] = compareResult{Server: s, RCode: protocol.RCodeToString(msg.Header.RCode), DNSSECStatus: compareDNSSECStatus(msg), Message: msg, Answer: msg}
		}(i, s)
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, map[string]any{
		"results":              out,
		"diff":                 buildCompareDiff(out),
		"server_limit_applied": serverLimitApplied,
	})
}

func (a *API) bulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if a.deps.Resolver == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "resolver unavailable"})
		return
	}
	queriesParam := strings.TrimSpace(r.URL.Query().Get("queries"))
	if queriesParam == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing queries"})
		return
	}
	queries := splitBulkQueries(queriesParam)
	if len(queries) > maxBulkQueries {
		queries = queries[:maxBulkQueries]
	}
	qtype := parseQType(r.URL.Query().Get("type"))
	concurrency, _ := strconv.Atoi(r.URL.Query().Get("concurrency"))
	if concurrency <= 0 {
		concurrency = 10
	}
	if concurrency > maxBulkConcurrency {
		concurrency = maxBulkConcurrency
	}
	if concurrency > len(queries) && len(queries) > 0 {
		concurrency = len(queries)
	}

	type item struct {
		Query      string `json:"query"`
		RCode      string `json:"rcode,omitempty"`
		Error      string `json:"error,omitempty"`
		DurationMS int64  `json:"duration_ms"`
	}
	results := make([]item, len(queries))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, q := range queries {
		wg.Add(1)
		go func(i int, q string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			start := time.Now()
			res, err := a.deps.Resolver.Resolve(r.Context(), q, qtype)
			if err != nil {
				results[i] = item{Query: q, Error: err.Error(), DurationMS: time.Since(start).Milliseconds()}
				return
			}
			results[i] = item{Query: q, RCode: protocol.RCodeToString(res.Message.Header.RCode), DurationMS: time.Since(start).Milliseconds()}
		}(i, q)
	}
	wg.Wait()

	if strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("format")), "csv") {
		var buf bytes.Buffer
		cw := csv.NewWriter(&buf)
		_ = cw.Write([]string{"query", "rcode", "error", "duration_ms"})
		for _, result := range results {
			_ = cw.Write([]string{
				result.Query,
				result.RCode,
				result.Error,
				strconv.FormatInt(result.DurationMS, 10),
			})
		}
		cw.Flush()
		if err := cw.Error(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="bulk-results.csv"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (a *API) rootservers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if a.deps.Resolver == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "resolver unavailable"})
		return
	}
	servers := a.deps.Resolver.RootServers()
	writeJSON(w, http.StatusOK, map[string]any{
		"servers":   servers,
		"upstreams": a.deps.Resolver.UpstreamStatuses(),
		"count":     len(servers),
	})
}

func (a *API) settings(w http.ResponseWriter, r *http.Request) {
	if a.deps.Resolver == nil || a.deps.DNSHandler == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "runtime settings unavailable"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		current := a.deps.Settings.Get()
		for k, v := range a.deps.DNSHandler.RuntimeConfig() {
			current[k] = v
		}
		current["blocklist"] = a.deps.Resolver.BlocklistDomains()
		current["blocklist_stats"] = a.deps.Resolver.BlocklistStats()
		writeJSON(w, http.StatusOK, current)
	case http.MethodPost:
		var m map[string]any
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
			return
		}
		if raw, ok := m["blocklist"]; ok {
			switch v := raw.(type) {
			case string:
				a.deps.Resolver.ReplaceBlocklist(v)
			case []any:
				lines := make([]string, 0, len(v))
				for _, item := range v {
					s, ok := item.(string)
					if !ok {
						writeJSON(w, http.StatusBadRequest, map[string]any{"error": "blocklist array must contain only strings"})
						return
					}
					lines = append(lines, s)
				}
				a.deps.Resolver.ReplaceBlocklist(strings.Join(lines, "\n"))
			default:
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "blocklist must be a string or string array"})
				return
			}
		}
		applied := a.deps.DNSHandler.ApplyRuntimeSettings(m)
		merged := make(map[string]any, len(m)+len(applied))
		for k, v := range m {
			merged[k] = v
		}
		for k, v := range applied {
			merged[k] = v
		}
		a.deps.Settings.Update(merged)
		current := a.deps.Settings.Get()
		for k, v := range a.deps.DNSHandler.RuntimeConfig() {
			current[k] = v
		}
		current["blocklist"] = a.deps.Resolver.BlocklistDomains()
		current["blocklist_stats"] = a.deps.Resolver.BlocklistStats()
		writeJSON(w, http.StatusOK, current)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

func (a *API) securityStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if a.deps.Resolver == nil || a.deps.DNSHandler == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "security stats unavailable"})
		return
	}
	resolverSec := a.deps.Resolver.SecurityStats()
	poisoningTotal := resolverSec["poisoning_source_mismatch"] + resolverSec["poisoning_id_mismatch"] + resolverSec["poisoning_case_mismatch"]
	runtimeCfg := a.deps.DNSHandler.RuntimeConfig()
	rrlLimit, _ := runtimeCfg["rrl_responses_per_sec"]
	rrlSlip, _ := runtimeCfg["rrl_slip"]
	rrlEnabled, _ := runtimeCfg["rrl_enabled"]
	writeJSON(w, http.StatusOK, map[string]any{
		"drops": map[string]any{
			"reasons":          a.deps.DNSHandler.SecurityStats(),
			"rate_limit_total": a.deps.DNSHandler.RateLimiterDrops(),
			"rrl_total":        a.deps.DNSHandler.RRLDrops(),
			"blocklist_total":  resolverSec["blocklist"],
		},
		"rate_limiter": map[string]any{
			"tracked_ips": a.deps.DNSHandler.RateLimiterTrackedIPs(),
			"blocked_ips": a.deps.DNSHandler.RateLimiterBlocked(100),
			"total_drops": a.deps.DNSHandler.RateLimiterDrops(),
		},
		"rrl": map[string]any{
			"enabled":        rrlEnabled,
			"drops":          a.deps.DNSHandler.RRLDrops(),
			"tracked_tuples": a.deps.DNSHandler.RRLTrackedTuples(),
			"limit_per_sec":  rrlLimit,
			"slip":           rrlSlip,
		},
		"poisoning_attempts": map[string]any{
			"total":           poisoningTotal,
			"source_mismatch": resolverSec["poisoning_source_mismatch"],
			"id_mismatch":     resolverSec["poisoning_id_mismatch"],
			"case_mismatch":   resolverSec["poisoning_case_mismatch"],
		},
		"blocklist":       a.deps.Resolver.BlocklistStats(),
		"resolver_sec":    resolverSec,
		"blocklist_rules": a.deps.Resolver.BlocklistDomains(),
		"upstream_security": map[string]any{
			"bailiwick_rejected": resolverSec["bailiwick_rejected"],
		},
	})
}

func (a *API) doh(w http.ResponseWriter, r *http.Request) {
	var payload []byte
	switch r.Method {
	case http.MethodGet:
		enc := r.URL.Query().Get("dns")
		if enc == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "missing dns query parameter"})
			return
		}
		decoded, err := base64.RawURLEncoding.DecodeString(enc)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid base64 query"})
			return
		}
		payload = decoded
	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "application/dns-message") {
			writeJSON(w, http.StatusUnsupportedMediaType, map[string]any{"error": "content-type must be application/dns-message"})
			return
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, 65535))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		payload = b
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if a.deps.DNSHandler == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "dns handler unavailable"})
		return
	}

	resp, drop, err := a.deps.DNSHandler.HandlePacket(r.Context(), payload, parseRemoteAddr(r.RemoteAddr), "doh")
	if err != nil || drop || len(resp) == 0 {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": fmt.Sprintf("doh resolve failed: %v", err)})
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

func parseRemoteAddr(addr string) net.Addr {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
	}
	return tcpAddr
}

func resolveViaServer(ctx context.Context, serverIP string, qname string, qtype uint16) (*protocol.Message, error) {
	qname = normalizedName(qname)
	q := &protocol.Message{
		Header:    protocol.Header{ID: uint16(time.Now().UnixNano()), RD: true},
		Questions: []protocol.Question{{Name: qname, Type: qtype, Class: protocol.ClassIN}},
	}
	wire, err := protocol.Encode(q)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(serverIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid server ip: %s", serverIP)
	}
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(ip.String(), "53"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadlineFromContext(ctx, externalDNSDeadline)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}
	buf := make([]byte, protocol.MaxUDPPacketLen)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	decoded, err := protocol.Decode(buf[:n])
	if err != nil {
		return nil, err
	}
	if err := validateExternalResponse(q, decoded); err != nil {
		return nil, err
	}
	if decoded.Header.TC {
		return resolveViaServerTCP(ctx, ip, wire, q)
	}
	return decoded, nil
}

func resolveViaServerTCP(ctx context.Context, ip net.IP, wire []byte, query *protocol.Message) (*protocol.Message, error) {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), "53"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadlineFromContext(ctx, externalDNSDeadline)); err != nil {
		return nil, err
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(wire)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(lenBuf[:]))
	if size <= 0 || size > protocol.MaxDNSPacketLen {
		return nil, fmt.Errorf("invalid tcp response size: %d", size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	decoded, err := protocol.Decode(payload)
	if err != nil {
		return nil, err
	}
	if err := validateExternalResponse(query, decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

func validateExternalResponse(query *protocol.Message, decoded *protocol.Message) error {
	if query == nil || decoded == nil {
		return fmt.Errorf("nil dns message")
	}
	if decoded.Header.ID != query.Header.ID {
		return fmt.Errorf("query id mismatch: want=%d got=%d", query.Header.ID, decoded.Header.ID)
	}
	if len(query.Questions) == 0 || len(decoded.Questions) == 0 {
		return fmt.Errorf("missing response question")
	}
	sent := query.Questions[0]
	got := decoded.Questions[0]
	if normalizedName(sent.Name) != normalizedName(got.Name) {
		return fmt.Errorf("response question name mismatch: want=%s got=%s", sent.Name, got.Name)
	}
	if sent.Type != got.Type || got.Class != protocol.ClassIN {
		return fmt.Errorf("response question mismatch: type=%d class=%d", got.Type, got.Class)
	}
	return nil
}

func normalizeServers(servers []string) []string {
	seen := make(map[string]struct{}, len(servers))
	out := make([]string, 0, len(servers))
	for _, server := range servers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		if ip := net.ParseIP(server); ip == nil {
			continue
		}
		if _, ok := seen[server]; ok {
			continue
		}
		seen[server] = struct{}{}
		out = append(out, server)
	}
	return out
}

func deadlineFromContext(ctx context.Context, fallback time.Duration) time.Time {
	deadline := time.Now().Add(fallback)
	if ctx == nil {
		return deadline
	}
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		return ctxDeadline
	}
	return deadline
}

func buildCompareDiff(results []compareResult) compareDiff {
	baseIdx := -1
	for i := range results {
		if results[i].Error == "" && results[i].Answer != nil {
			baseIdx = i
			break
		}
	}
	if baseIdx == -1 {
		return compareDiff{Available: false}
	}

	base := results[baseIdx]
	baseRecords := answerFingerprint(base.Answer)
	diff := compareDiff{
		Available:  true,
		BaseServer: base.Server,
		BaseRCode:  base.RCode,
	}
	for i := range results {
		if i == baseIdx || results[i].Error != "" || results[i].Answer == nil {
			continue
		}
		current := results[i]
		if current.RCode != base.RCode {
			diff.RCodeMismatches = append(diff.RCodeMismatches, compareRCodeDiff{
				Server:   current.Server,
				Expected: base.RCode,
				Actual:   current.RCode,
			})
			continue
		}
		currentRecords := answerFingerprint(current.Answer)
		missing, extra := diffRecordKeys(baseRecords, currentRecords)
		if len(missing) > 0 || len(extra) > 0 {
			diff.AnswerDiffs = append(diff.AnswerDiffs, compareAnswerDiff{
				Server:  current.Server,
				Missing: missing,
				Extra:   extra,
			})
		}
		for record, expectedTTL := range baseRecords {
			actualTTL, ok := currentRecords[record]
			if !ok || actualTTL == expectedTTL {
				continue
			}
			diff.TTLDiffs = append(diff.TTLDiffs, compareTTLDiffItem{
				Server:   current.Server,
				Record:   record,
				Expected: expectedTTL,
				Actual:   actualTTL,
			})
		}
	}
	return diff
}

func answerFingerprint(msg *protocol.Message) map[string]uint32 {
	out := make(map[string]uint32)
	if msg == nil {
		return out
	}
	for _, rr := range msg.Answers {
		out[recordFingerprint(rr)] = rr.TTL
	}
	return out
}

func diffRecordKeys(base, current map[string]uint32) ([]string, []string) {
	missing := make([]string, 0)
	extra := make([]string, 0)
	for k := range base {
		if _, ok := current[k]; !ok {
			missing = append(missing, k)
		}
	}
	for k := range current {
		if _, ok := base[k]; !ok {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}

func recordFingerprint(rr protocol.ResourceRecord) string {
	data, _ := json.Marshal(rr.Data)
	return fmt.Sprintf("%s|%s|%s", normalizedName(rr.Name), protocol.TypeToString(rr.Type), string(data))
}

func normalizedName(name string) string {
	n := strings.TrimSpace(strings.ToLower(name))
	if n == "" || n == "." {
		return "."
	}
	if !strings.HasSuffix(n, ".") {
		n += "."
	}
	return n
}

func compareDNSSECStatus(msg *protocol.Message) string {
	if msg == nil {
		return "bogus"
	}
	if msg.Header.RCode == protocol.RCodeServerFailure {
		return "bogus"
	}
	hasRRSIG := false
	hasKeyMaterial := false
	all := append(append([]protocol.ResourceRecord{}, msg.Answers...), msg.Authorities...)
	all = append(all, msg.Additionals...)
	for _, rr := range all {
		switch rr.Type {
		case protocol.TypeRRSIG:
			hasRRSIG = true
		case protocol.TypeDNSKEY, protocol.TypeDS:
			hasKeyMaterial = true
		}
	}
	if hasRRSIG && hasKeyMaterial {
		return "secure"
	}
	if hasRRSIG {
		return "indeterminate"
	}
	if msg.Header.RCode == protocol.RCodeNoError || msg.Header.RCode == protocol.RCodeNameError {
		return "insecure"
	}
	return "indeterminate"
}

func reverseNameFromIP(ip net.IP) (string, bool) {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", v4[3], v4[2], v4[1], v4[0]), true
	}
	v6 := ip.To16()
	if v6 == nil {
		return "", false
	}
	const hexDigits = "0123456789abcdef"
	parts := make([]byte, 0, 4*32+9)
	for i := len(v6) - 1; i >= 0; i-- {
		parts = append(parts, hexDigits[v6[i]&0x0f], '.', hexDigits[(v6[i]>>4)&0x0f], '.')
	}
	parts = append(parts, []byte("ip6.arpa.")...)
	return string(parts), true
}

func lastParsedMessage(events []resolver.ResolutionEvent) *protocol.Message {
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].ParsedMsg != nil {
			return events[i].ParsedMsg
		}
	}
	return nil
}

func parseQType(v string) uint16 {
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 && n <= 65535 {
		return uint16(n)
	}
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "AAAA":
		return protocol.TypeAAAA
	case "MX":
		return protocol.TypeMX
	case "NS":
		return protocol.TypeNS
	case "TXT":
		return protocol.TypeTXT
	case "PTR":
		return protocol.TypePTR
	case "SRV":
		return protocol.TypeSRV
	case "CAA":
		return protocol.TypeCAA
	case "CNAME":
		return protocol.TypeCNAME
	case "SOA":
		return protocol.TypeSOA
	case "DS":
		return protocol.TypeDS
	case "RRSIG":
		return protocol.TypeRRSIG
	case "DNSKEY":
		return protocol.TypeDNSKEY
	case "NSEC":
		return protocol.TypeNSEC
	case "NSEC3":
		return protocol.TypeNSEC3
	case "ANY":
		return protocol.TypeANY
	default:
		return protocol.TypeA
	}
}

func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitBulkQueries(v string) []string {
	v = strings.ReplaceAll(v, ",", "\n")
	lines := strings.Split(v, "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		out = append(out, l)
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
