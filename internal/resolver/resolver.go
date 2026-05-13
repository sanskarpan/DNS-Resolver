package resolver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"dnsresolver/internal/cache"
	"dnsresolver/internal/protocol"
	"dnsresolver/internal/security"
	"dnsresolver/internal/telemetry"
)

type Config struct {
	UpstreamTimeout    time.Duration
	Retries            int
	MaxCNAMEDepth      int
	MaxRecursionDepth  int
	QNAMEMinimization  bool
	CaseRandomization  bool
	EDNSEnabled        bool
	MaxUDPSize         int
	CBFailureThreshold int
	CBSuccessThreshold int
	CBOpenTimeout      time.Duration
}

func DefaultConfig() Config {
	return Config{
		UpstreamTimeout:    5 * time.Second,
		Retries:            3,
		MaxCNAMEDepth:      10,
		MaxRecursionDepth:  10,
		QNAMEMinimization:  true,
		CaseRandomization:  true,
		EDNSEnabled:        true,
		MaxUDPSize:         4096,
		CBFailureThreshold: 5,
		CBSuccessThreshold: 2,
		CBOpenTimeout:      30 * time.Second,
	}
}

type ResolveResult struct {
	QueryID      string
	Message      *protocol.Message
	Events       []ResolutionEvent
	Cached       bool
	Stale        bool
	StaleOnError bool
	DNSSECStatus string
	Blocked      bool
	Duration     time.Duration
}

type HistoryEntry struct {
	QueryID      string    `json:"query_id"`
	Timestamp    time.Time `json:"timestamp"`
	Domain       string    `json:"domain"`
	QType        string    `json:"qtype"`
	RCode        string    `json:"rcode"`
	DNSSECStatus string    `json:"dnssec_status"`
	Duration     int64     `json:"duration_ms"`
	Cached       bool      `json:"cached"`
	Stale        bool      `json:"stale"`
}

type Resolver struct {
	cfg   Config
	cfgMu sync.RWMutex
	cache *cache.Cache
	hub   *EventHub
	qid   *security.QueryIDRandomizer
	ports *security.PortRandomizer
	cases *security.CaseRandomizer

	breakerMu sync.Mutex
	breakers  map[string]*CircuitBreaker
	rootHints []RootServer

	historyMu sync.RWMutex
	history   []HistoryEntry
	traces    map[string][]ResolutionEvent

	queryFunc    func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []ResolutionEvent, error)
	blocklist    *Blocklist
	securityMu   sync.Mutex
	security     map[string]uint64
	secHooks     []func(reason string)
	upstreamMu   sync.RWMutex
	upstream     map[string]UpstreamStatus
	lookupIPs    func(ctx context.Context, host string) ([]net.IP, error)
	upstreamPort int
}

func New(cfg Config, c *cache.Cache) *Resolver {
	if cfg.UpstreamTimeout <= 0 {
		cfg = DefaultConfig()
	}
	if cfg.Retries <= 0 {
		cfg.Retries = 3
	}
	if cfg.MaxRecursionDepth <= 0 {
		cfg.MaxRecursionDepth = 10
	}
	if cfg.MaxCNAMEDepth <= 0 {
		cfg.MaxCNAMEDepth = 10
	}
	if cfg.MaxUDPSize <= 0 {
		cfg.MaxUDPSize = protocol.MaxUDPPacketLen
	}
	if c == nil {
		c = cache.New(cache.Options{})
	}

	r := &Resolver{
		cfg:          cfg,
		cache:        c,
		hub:          NewEventHub(),
		qid:          security.NewQueryIDRandomizer(),
		ports:        security.NewPortRandomizer(),
		cases:        security.NewCaseRandomizer(),
		breakers:     make(map[string]*CircuitBreaker),
		rootHints:    DefaultRootHints(),
		history:      make([]HistoryEntry, 0, 1000),
		traces:       make(map[string][]ResolutionEvent),
		blocklist:    NewBlocklist(),
		security:     map[string]uint64{},
		secHooks:     make([]func(string), 0, 2),
		upstream:     map[string]UpstreamStatus{},
		upstreamPort: 53,
		lookupIPs: func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", strings.TrimSuffix(host, "."))
		},
	}
	r.cache.SetPrefetchCallback(func(key string) {
		parts := strings.Split(key, "|")
		if len(parts) != 2 {
			return
		}
		qname := parts[0]
		qtype := protocol.TypeA
		switch parts[1] {
		case "AAAA":
			qtype = protocol.TypeAAAA
		case "MX":
			qtype = protocol.TypeMX
		}
		_, _ = r.Resolve(context.Background(), qname, qtype)
	})
	return r
}

// SetQueryFunc overrides upstream querying logic, primarily for tests.
func (r *Resolver) SetQueryFunc(fn func(ctx context.Context, queryID string, step int, qname string, qtype uint16, servers []string) (*protocol.Message, []ResolutionEvent, error)) {
	r.queryFunc = fn
}

func (r *Resolver) SetLookupIPsFunc(fn func(ctx context.Context, host string) ([]net.IP, error)) {
	if fn == nil {
		return
	}
	r.lookupIPs = fn
}

func (r *Resolver) SetUpstreamPort(port int) {
	if port < 1 || port > 65535 {
		return
	}
	r.upstreamPort = port
}

func (r *Resolver) Subscribe(buffer int) chan ResolutionEvent {
	return r.hub.Subscribe(buffer)
}

func (r *Resolver) Unsubscribe(ch chan ResolutionEvent) {
	r.hub.Unsubscribe(ch)
}

func (r *Resolver) Resolve(ctx context.Context, qname string, qtype uint16) (*ResolveResult, error) {
	started := time.Now()
	ctx, span := telemetry.StartResolveSpan(ctx, qname, protocol.TypeToString(qtype))
	defer span.End()
	qname = normalizeFQDN(qname)
	key := cacheKey(qname, qtype)
	queryID := newQueryID()
	events := make([]ResolutionEvent, 0, 16)
	cfg := r.configSnapshot()

	if r.blocklist != nil && r.blocklist.IsBlocked(qname) {
		r.incSecurityCounter("blocklist")
		telemetry.AddStepAttributes(span, "blocked", "")
		msg := nxdomainMessage(qname, qtype)
		events = append(events, ResolutionEvent{
			QueryID:   queryID,
			Timestamp: time.Now().UTC(),
			Step:      1,
			StepType:  "blocked",
			Query:     qname,
			QueryType: protocol.TypeToString(qtype),
			Success:   true,
			ErrorMsg:  "blocked by local blocklist",
		})
		r.publishTrace(queryID, qname, qtype, msg, events, false, false, started)
		return &ResolveResult{
			QueryID:      queryID,
			Message:      msg,
			Events:       events,
			DNSSECStatus: dnssecStatus(msg),
			Blocked:      true,
			Duration:     time.Since(started),
		}, nil
	}

	if neg, ok := r.cache.GetNegative(key); ok {
		telemetry.AddStepAttributes(span, "cache_hit", "")
		msg := negativeCacheMessage(qname, qtype, neg.RCode)
		e := ResolutionEvent{QueryID: queryID, Timestamp: time.Now().UTC(), Step: 1, StepType: "cache_hit", Query: qname, QueryType: protocol.TypeToString(qtype), Success: true}
		events = append(events, e)
		r.publishTrace(queryID, qname, qtype, msg, events, true, false, started)
		return &ResolveResult{QueryID: queryID, Message: msg, Events: events, Cached: true, DNSSECStatus: dnssecStatus(msg), Duration: time.Since(started)}, nil
	}

	cached := r.cache.Get(key)
	if cached.Hit {
		stepType := "cache_hit"
		if cached.Stale {
			stepType = "stale_cache_hit"
		}
		telemetry.AddStepAttributes(span, stepType, "")
		e := ResolutionEvent{QueryID: queryID, Timestamp: time.Now().UTC(), Step: 1, StepType: "cache_hit", Query: qname, QueryType: protocol.TypeToString(qtype), Success: true}
		events = append(events, e)
		r.publishTrace(queryID, qname, qtype, cached.Message, events, true, cached.Stale, started)
		return &ResolveResult{QueryID: queryID, Message: cached.Message, Events: events, Cached: true, Stale: cached.Stale, DNSSECStatus: dnssecStatus(cached.Message), Duration: time.Since(started)}, nil
	}

	msg, resolutionEvents, err := r.resolveRecursive(ctx, queryID, qname, qtype, cfg)
	events = append(events, resolutionEvents...)
	for _, ev := range resolutionEvents {
		telemetry.AddStepAttributes(span, ev.StepType, ev.Server)
	}
	if err != nil {
		if stale, ok := r.cache.GetStaleOnError(key); ok {
			telemetry.AddStepAttributes(span, "serve_stale_on_error", "")
			events = append(events, ResolutionEvent{QueryID: queryID, Timestamp: time.Now().UTC(), Step: len(events) + 1, StepType: "serve_stale_on_error", Query: qname, QueryType: protocol.TypeToString(qtype), Success: true})
			r.publishTrace(queryID, qname, qtype, stale, events, true, true, started)
			return &ResolveResult{QueryID: queryID, Message: stale, Events: events, Cached: true, Stale: true, StaleOnError: true, DNSSECStatus: dnssecStatus(stale), Duration: time.Since(started)}, nil
		}
		fail := servfailMessage(qname, qtype)
		r.publishTrace(queryID, qname, qtype, fail, events, false, false, started)
		return nil, fmt.Errorf("resolve %s %s: %w", qname, protocol.TypeToString(qtype), err)
	}

	if msg != nil {
		if msg.Header.RCode == protocol.RCodeNameError {
			r.cache.SetNegative(key, msg.Header.RCode, cache.TTLFromSOA(msg), authoritySOAName(msg))
		} else if msg.Header.RCode == protocol.RCodeNoError {
			if shouldCacheAsNODATA(msg, qname, qtype) {
				r.cache.SetNegative(key, protocol.RCodeNoError, cache.TTLFromSOA(msg), authoritySOAName(msg))
			} else if len(msg.Answers) > 0 {
				r.cache.Set(key, msg, minTTL(msg))
			}
		}
	}

	r.publishTrace(queryID, qname, qtype, msg, events, false, false, started)
	return &ResolveResult{QueryID: queryID, Message: msg, Events: events, DNSSECStatus: dnssecStatus(msg), Duration: time.Since(started)}, nil
}

func (r *Resolver) LoadBlocklist(path string) error {
	if r.blocklist == nil {
		r.blocklist = NewBlocklist()
	}
	return r.blocklist.LoadFromFile(path)
}

func (r *Resolver) ReplaceBlocklist(raw string) {
	if r.blocklist == nil {
		r.blocklist = NewBlocklist()
	}
	r.blocklist.ReplaceFromText(raw)
}

func (r *Resolver) BlocklistStats() BlocklistStats {
	if r.blocklist == nil {
		return BlocklistStats{}
	}
	return r.blocklist.Stats()
}

func (r *Resolver) BlocklistDomains() []string {
	if r.blocklist == nil {
		return nil
	}
	return r.blocklist.Domains()
}

func (r *Resolver) SecurityStats() map[string]uint64 {
	r.securityMu.Lock()
	defer r.securityMu.Unlock()
	out := make(map[string]uint64, len(r.security))
	for k, v := range r.security {
		out[k] = v
	}
	return out
}

func (r *Resolver) CacheStats() cache.Stats {
	if r.cache == nil {
		return cache.Stats{}
	}
	return r.cache.Stats()
}

func (r *Resolver) incSecurityCounter(reason string) {
	if strings.TrimSpace(reason) == "" {
		return
	}
	r.securityMu.Lock()
	r.security[reason]++
	hooks := append([]func(string){}, r.secHooks...)
	r.securityMu.Unlock()
	for _, h := range hooks {
		h(reason)
	}
}

func (r *Resolver) AddSecurityHook(fn func(reason string)) {
	if fn == nil {
		return
	}
	r.securityMu.Lock()
	r.secHooks = append(r.secHooks, fn)
	r.securityMu.Unlock()
}

func (r *Resolver) ApplyRuntimeSettings(settings map[string]any) map[string]any {
	applied := map[string]any{}
	if settings == nil {
		return applied
	}

	r.cfgMu.Lock()
	cfg := r.cfg
	if v, ok := boolSetting(settings["qname_minimization"]); ok {
		cfg.QNAMEMinimization = v
		applied["qname_minimization"] = v
	}
	if v, ok := boolSetting(settings["case_randomization"]); ok {
		cfg.CaseRandomization = v
		applied["case_randomization"] = v
	}
	if v, ok := boolSetting(settings["edns_enabled"]); ok {
		cfg.EDNSEnabled = v
		applied["edns_enabled"] = v
	}
	if v, ok := intSetting(settings["max_udp_size"]); ok && v >= 512 && v <= 4096 {
		cfg.MaxUDPSize = v
		applied["max_udp_size"] = v
	}
	if v, ok := durationSetting(settings["upstream_timeout"]); ok && v > 0 {
		cfg.UpstreamTimeout = v
		applied["upstream_timeout"] = v.String()
	}
	if v, ok := intSetting(settings["max_cname_depth"]); ok && v >= 1 {
		cfg.MaxCNAMEDepth = v
		applied["max_cname_depth"] = v
	}
	if v, ok := intSetting(settings["max_recursion_depth"]); ok && v >= 1 {
		cfg.MaxRecursionDepth = v
		applied["max_recursion_depth"] = v
	}
	if v, ok := intSetting(settings["retries"]); ok && v >= 1 {
		cfg.Retries = v
		applied["retries"] = v
	}

	cbChanged := false
	if v, ok := intSetting(settings["cb_failure_threshold"]); ok && v >= 1 {
		cfg.CBFailureThreshold = v
		applied["cb_failure_threshold"] = v
		cbChanged = true
	}
	if v, ok := intSetting(settings["cb_success_threshold"]); ok && v >= 1 {
		cfg.CBSuccessThreshold = v
		applied["cb_success_threshold"] = v
		cbChanged = true
	}
	if v, ok := durationSetting(settings["cb_open_timeout"]); ok && v > 0 {
		cfg.CBOpenTimeout = v
		applied["cb_open_timeout"] = v.String()
		cbChanged = true
	}
	r.cfg = cfg
	r.cfgMu.Unlock()

	if cbChanged {
		r.breakerMu.Lock()
		for _, cb := range r.breakers {
			cb.UpdateConfig(cfg.CBFailureThreshold, cfg.CBSuccessThreshold, cfg.CBOpenTimeout)
		}
		r.breakerMu.Unlock()
	}

	if r.cache != nil {
		update := cache.RuntimeConfigUpdate{}
		cacheChanged := false
		if v, ok := intSetting(settings["cache_max_entries"]); ok && v > 0 {
			update.MaxEntries = &v
			cacheChanged = true
		}
		if v, ok := durationSetting(settings["cache_min_ttl"]); ok && v > 0 {
			update.MinTTL = &v
			cacheChanged = true
		}
		if v, ok := durationSetting(settings["cache_max_ttl"]); ok && v > 0 {
			update.MaxTTL = &v
			cacheChanged = true
		}
		if v, ok := durationSetting(settings["cache_stale_window"]); ok && v >= 0 {
			update.StaleWindow = &v
			cacheChanged = true
		}
		if v, ok := durationSetting(settings["cache_stale_max_age"]); ok && v >= 0 {
			update.StaleMaxAge = &v
			cacheChanged = true
		}
		if cacheChanged {
			current := r.cache.ApplyRuntimeConfig(update)
			applied["cache_max_entries"] = current.MaxEntries
			applied["cache_min_ttl"] = int(current.MinTTL / time.Second)
			applied["cache_max_ttl"] = int(current.MaxTTL / time.Second)
			applied["cache_stale_window"] = int(current.StaleWindow / time.Second)
			applied["cache_stale_max_age"] = int(current.StaleMaxAge / time.Second)
		}
	}
	return applied
}

func (r *Resolver) RuntimeConfig() map[string]any {
	cfg := r.configSnapshot()
	out := map[string]any{
		"qname_minimization":   cfg.QNAMEMinimization,
		"case_randomization":   cfg.CaseRandomization,
		"edns_enabled":         cfg.EDNSEnabled,
		"max_udp_size":         cfg.MaxUDPSize,
		"upstream_timeout":     cfg.UpstreamTimeout.String(),
		"max_cname_depth":      cfg.MaxCNAMEDepth,
		"max_recursion_depth":  cfg.MaxRecursionDepth,
		"retries":              cfg.Retries,
		"cb_failure_threshold": cfg.CBFailureThreshold,
		"cb_success_threshold": cfg.CBSuccessThreshold,
		"cb_open_timeout":      cfg.CBOpenTimeout.String(),
	}
	if r.cache != nil {
		cc := r.cache.RuntimeConfig()
		out["cache_max_entries"] = cc.MaxEntries
		out["cache_min_ttl"] = int(cc.MinTTL / time.Second)
		out["cache_max_ttl"] = int(cc.MaxTTL / time.Second)
		out["cache_stale_window"] = int(cc.StaleWindow / time.Second)
		out["cache_stale_max_age"] = int(cc.StaleMaxAge / time.Second)
	}
	return out
}

func cacheKey(qname string, qtype uint16) string {
	return strings.ToLower(normalizeFQDN(qname)) + "|" + protocol.TypeToString(qtype)
}

func minTTL(msg *protocol.Message) time.Duration {
	if msg == nil {
		return 30 * time.Second
	}
	min := uint32(0)
	all := append(append([]protocol.ResourceRecord{}, msg.Answers...), msg.Authorities...)
	all = append(all, msg.Additionals...)
	for _, rr := range all {
		if rr.TTL == 0 {
			continue
		}
		if min == 0 || rr.TTL < min {
			min = rr.TTL
		}
	}
	if min == 0 {
		min = 30
	}
	return time.Duration(min) * time.Second
}

func authoritySOAName(msg *protocol.Message) string {
	for _, rr := range msg.Authorities {
		if rr.Type == protocol.TypeSOA {
			return rr.Name
		}
	}
	return ""
}

func (r *Resolver) publishTrace(queryID, qname string, qtype uint16, msg *protocol.Message, events []ResolutionEvent, cached bool, stale bool, started time.Time) {
	duration := time.Since(started)
	r.historyMu.Lock()
	for _, ev := range events {
		r.hub.Publish(ev)
	}
	if len(r.history) >= 1000 {
		delete(r.traces, r.history[0].QueryID)
		r.history = r.history[1:]
	}
	rcode := "SERVFAIL"
	if msg != nil {
		rcode = protocol.RCodeToString(msg.Header.RCode)
	}
	r.history = append(r.history, HistoryEntry{
		QueryID:      queryID,
		Timestamp:    time.Now().UTC(),
		Domain:       qname,
		QType:        protocol.TypeToString(qtype),
		RCode:        rcode,
		DNSSECStatus: dnssecStatus(msg),
		Duration:     duration.Milliseconds(),
		Cached:       cached,
		Stale:        stale,
	})
	r.traces[queryID] = append([]ResolutionEvent(nil), events...)
	r.historyMu.Unlock()
}

func (r *Resolver) History(page, limit int) []HistoryEntry {
	if page < 1 {
		page = 1
	}
	if limit <= 0 {
		limit = 50
	}
	offset := (page - 1) * limit
	r.historyMu.RLock()
	defer r.historyMu.RUnlock()
	if offset >= len(r.history) {
		return nil
	}
	end := offset + limit
	if end > len(r.history) {
		end = len(r.history)
	}
	items := make([]HistoryEntry, end-offset)
	copy(items, r.history[offset:end])
	return items
}

func (r *Resolver) Trace(id string) []ResolutionEvent {
	r.historyMu.RLock()
	defer r.historyMu.RUnlock()
	trace := r.traces[id]
	out := make([]ResolutionEvent, len(trace))
	copy(out, trace)
	return out
}

func (r *Resolver) HistoryEntry(id string) (HistoryEntry, bool) {
	r.historyMu.RLock()
	defer r.historyMu.RUnlock()
	for _, entry := range r.history {
		if entry.QueryID == id {
			return entry, true
		}
	}
	return HistoryEntry{}, false
}

func (r *Resolver) RootServers() []RootServer {
	r.breakerMu.Lock()
	defer r.breakerMu.Unlock()
	upstream := r.upstreamMap()
	cfg := r.configSnapshot()
	out := make([]RootServer, 0, len(r.rootHints))
	for _, hint := range r.rootHints {
		cb := r.getBreakerLocked(hint.IPv4, cfg)
		snap := cb.Snapshot()
		hint.State = snap.State.String()
		hint.StateCode = stateCode(snap.State)
		hint.ConsecutiveFailures = snap.Failures
		hint.LastFailure = snap.LastFailureTime
		if status, ok := upstream[hint.IPv4]; ok {
			hint.LastLatency = status.LastLatency
			hint.LastSeen = status.LastSeen
			hint.LastError = status.LastError
			hint.TotalSuccesses = status.TotalSuccesses
			hint.TotalFailures = status.TotalFailures
		}
		out = append(out, hint)
	}
	return out
}

func (r *Resolver) UpstreamStatuses() []UpstreamStatus {
	r.breakerMu.Lock()
	defer r.breakerMu.Unlock()
	cfg := r.configSnapshot()

	outMap := r.upstreamMap()
	for server, cb := range r.breakers {
		snap := cb.Snapshot()
		status := outMap[server]
		status.Server = server
		status.State = snap.State.String()
		status.StateCode = stateCode(snap.State)
		status.ConsecutiveFailures = snap.Failures
		status.LastFailure = snap.LastFailureTime
		outMap[server] = status
	}

	rootNames := make(map[string]string, len(r.rootHints))
	for _, hint := range r.rootHints {
		rootNames[hint.IPv4] = hint.Name
		if _, ok := outMap[hint.IPv4]; !ok {
			cb := r.getBreakerLocked(hint.IPv4, cfg)
			snap := cb.Snapshot()
			outMap[hint.IPv4] = UpstreamStatus{
				Server:              hint.IPv4,
				ServerName:          hint.Name,
				State:               snap.State.String(),
				StateCode:           stateCode(snap.State),
				ConsecutiveFailures: snap.Failures,
				LastFailure:         snap.LastFailureTime,
			}
		}
	}

	out := make([]UpstreamStatus, 0, len(outMap))
	for server, status := range outMap {
		if status.ServerName == "" {
			status.ServerName = rootNames[server]
		}
		out = append(out, status)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ServerName == out[j].ServerName {
			return out[i].Server < out[j].Server
		}
		if out[i].ServerName == "" {
			return false
		}
		if out[j].ServerName == "" {
			return true
		}
		return out[i].ServerName < out[j].ServerName
	})
	return out
}

func (r *Resolver) getBreaker(server string, cfg Config) *CircuitBreaker {
	r.breakerMu.Lock()
	defer r.breakerMu.Unlock()
	return r.getBreakerLocked(server, cfg)
}

func (r *Resolver) getBreakerLocked(server string, cfg Config) *CircuitBreaker {
	if cb, ok := r.breakers[server]; ok {
		return cb
	}
	cb := NewCircuitBreaker(cfg.CBFailureThreshold, cfg.CBSuccessThreshold, cfg.CBOpenTimeout)
	r.breakers[server] = cb
	return cb
}

func (r *Resolver) observeUpstreamResult(server string, serverName string, latency time.Duration, err error) {
	if strings.TrimSpace(server) == "" {
		return
	}
	r.upstreamMu.Lock()
	defer r.upstreamMu.Unlock()
	status := r.upstream[server]
	status.Server = server
	if strings.TrimSpace(serverName) != "" && serverName != server {
		status.ServerName = serverName
	}
	if latency > 0 {
		status.LastLatency = latency.Milliseconds()
	}
	status.LastSeen = time.Now().UTC()
	if err != nil {
		status.LastError = err.Error()
		status.TotalFailures++
	} else {
		status.LastError = ""
		status.TotalSuccesses++
	}
	r.upstream[server] = status
}

func (r *Resolver) upstreamMap() map[string]UpstreamStatus {
	r.upstreamMu.RLock()
	defer r.upstreamMu.RUnlock()
	out := make(map[string]UpstreamStatus, len(r.upstream))
	for k, v := range r.upstream {
		out[k] = v
	}
	return out
}

func stateCode(s State) int {
	switch s {
	case StateClosed:
		return 0
	case StateHalfOpen:
		return 1
	case StateOpen:
		return 2
	default:
		return -1
	}
}

func (r *Resolver) configSnapshot() Config {
	r.cfgMu.RLock()
	defer r.cfgMu.RUnlock()
	return r.cfg
}

func boolSetting(v any) (bool, bool) {
	b, ok := v.(bool)
	return b, ok
}

func intSetting(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int32:
		return int(n), true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case float32:
		return int(n), true
	default:
		return 0, false
	}
}

func durationSetting(v any) (time.Duration, bool) {
	switch d := v.(type) {
	case string:
		parsed, err := time.ParseDuration(strings.TrimSpace(d))
		if err != nil {
			return 0, false
		}
		return parsed, true
	case float64:
		return time.Duration(d * float64(time.Second)), true
	case float32:
		return time.Duration(float64(d) * float64(time.Second)), true
	case int:
		return time.Duration(d) * time.Second, true
	case int64:
		return time.Duration(d) * time.Second, true
	default:
		return 0, false
	}
}

func nxdomainMessage(name string, qtype uint16) *protocol.Message {
	return &protocol.Message{
		Header:    protocol.Header{QR: true, RD: true, RA: true, RCode: protocol.RCodeNameError},
		Questions: []protocol.Question{{Name: name, Type: qtype, Class: protocol.ClassIN}},
	}
}

func negativeCacheMessage(name string, qtype uint16, rcode uint8) *protocol.Message {
	msg := nxdomainMessage(name, qtype)
	msg.Header.RCode = rcode
	return msg
}

func shouldCacheAsNODATA(msg *protocol.Message, qname string, qtype uint16) bool {
	if msg == nil || msg.Header.RCode != protocol.RCodeNoError {
		return false
	}
	if hasAnswer(msg, qname, qtype) {
		return false
	}
	// Cache NODATA only when authoritative SOA is present.
	return cache.TTLFromSOA(msg) > 0
}

func servfailMessage(name string, qtype uint16) *protocol.Message {
	return &protocol.Message{
		Header:    protocol.Header{QR: true, RD: true, RA: true, RCode: protocol.RCodeServerFailure},
		Questions: []protocol.Question{{Name: name, Type: qtype, Class: protocol.ClassIN}},
	}
}

func dnssecStatus(msg *protocol.Message) string {
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

func newQueryID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("q-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
