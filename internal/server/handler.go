package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	ilogger "dnsresolver/internal/logger"
	"dnsresolver/internal/metrics"
	"dnsresolver/internal/protocol"
	"dnsresolver/internal/resolver"
	"dnsresolver/internal/security"
)

type QueryEvent struct {
	ID         string    `json:"id"`
	QueryID    string    `json:"query_id,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
	Domain     string    `json:"domain"`
	Type       string    `json:"type"`
	QueryType  string    `json:"query_type,omitempty"`
	ClientIP   string    `json:"client_ip"`
	Protocol   string    `json:"protocol,omitempty"`
	LatencyMS  int64     `json:"latency_ms"`
	DurationMS int64     `json:"duration_ms,omitempty"`
	Steps      int       `json:"steps"`
	RCode      string    `json:"rcode"`
	Cached     bool      `json:"cached"`
	Stale      bool      `json:"stale"`
}

type Options struct {
	Resolver       *resolver.Resolver
	RateLimiter    *security.RateLimiter
	RRL            *security.RRL
	MaxUDPSize     int
	Metrics        *metrics.Metrics
	Prometheus     *metrics.PromMetrics
	RRLEnabled     bool
	AllowRecursive *bool
	Logger         *slog.Logger
}

type Handler struct {
	resolver       *resolver.Resolver
	limiter        *security.RateLimiter
	rrl            *security.RRL
	maxUDPSize     int
	metrics        *metrics.Metrics
	prom           *metrics.PromMetrics
	rrlEnabled     bool
	allowRecursive bool
	cfgMu          sync.RWMutex

	queryMu      sync.RWMutex
	querySubs    map[chan QueryEvent]struct{}
	securityMu   sync.Mutex
	securityDrop map[string]uint64
	logger       *slog.Logger
	rateLogMu    sync.Mutex
	rateLogAt    map[string]time.Time
	secLogMu     sync.Mutex
	secLogAt     map[string]time.Time
	now          func() time.Time

	queryClientMu sync.RWMutex
	queryClientIP map[string]string
	rdnsMu        sync.RWMutex
	rdnsCache     map[string]string
	lookupAddr    func(ctx context.Context, addr string) ([]string, error)
}

func NewHandler(opts Options) *Handler {
	if opts.MaxUDPSize <= 0 {
		opts.MaxUDPSize = protocol.MaxUDPPacketLen
	}
	if opts.Metrics == nil {
		opts.Metrics = metrics.New()
	}
	allowRecursive := true
	if opts.AllowRecursive != nil {
		allowRecursive = *opts.AllowRecursive
	}
	h := &Handler{
		resolver:       opts.Resolver,
		limiter:        opts.RateLimiter,
		rrl:            opts.RRL,
		maxUDPSize:     opts.MaxUDPSize,
		metrics:        opts.Metrics,
		prom:           opts.Prometheus,
		rrlEnabled:     opts.RRLEnabled,
		allowRecursive: allowRecursive,
		querySubs:      make(map[chan QueryEvent]struct{}),
		securityDrop:   map[string]uint64{},
		logger:         opts.Logger,
		rateLogAt:      map[string]time.Time{},
		secLogAt:       map[string]time.Time{},
		now:            time.Now,
		queryClientIP:  map[string]string{},
		rdnsCache:      map[string]string{},
		lookupAddr:     net.DefaultResolver.LookupAddr,
	}
	if opts.Resolver != nil {
		opts.Resolver.AddSecurityHook(func(reason string) {
			h.incSecurityDrop(reason)
			if h.prom != nil {
				h.prom.IncSecurityDrop(reason)
			}
			h.logSecurityReason(reason)
		})
	}
	return h
}

func (h *Handler) HandlePacket(ctx context.Context, raw []byte, clientAddr net.Addr, protocolName string) ([]byte, bool, error) {
	started := time.Now()
	clientIP := clientIPString(clientAddr)

	if protocolName == "udp" && len(raw) > h.maxUDPSize {
		h.incSecurityDrop("format")
		h.logMalformedPacket("udp_size_exceeded", raw, nil, protocolName, clientIP)
		return h.formerrFromPacket(raw), false, nil
	}

	if protocolName == "udp" && h.limiter != nil && !h.limiter.Allow(clientIP) {
		h.incSecurityDrop("rate_limit")
		if h.prom != nil {
			h.prom.IncSecurityDrop("rate_limit")
		}
		h.logRateLimit(clientIP)
		return nil, true, nil
	}

	request, err := protocol.Decode(raw)
	if err != nil {
		h.incSecurityDrop("format")
		h.logMalformedPacket("decode_error", raw, err, protocolName, clientIP)
		return h.formerrFromPacket(raw), false, nil
	}
	if len(request.Questions) == 0 {
		h.incSecurityDrop("format")
		h.logMalformedPacket("missing_question", raw, nil, protocolName, clientIP)
		return h.formerrFromID(request.Header.ID), false, nil
	}
	allowRecursive := true
	h.cfgMu.RLock()
	allowRecursive = h.allowRecursive
	h.cfgMu.RUnlock()
	if !allowRecursive {
		response := &protocol.Message{
			Header: protocol.Header{
				ID:     request.Header.ID,
				QR:     true,
				RD:     request.Header.RD,
				RA:     false,
				Opcode: request.Header.Opcode,
				RCode:  protocol.RCodeRefused,
			},
			Questions: request.Questions,
		}
		wire, encErr := protocol.Encode(response)
		if encErr != nil {
			return nil, false, fmt.Errorf("encode refused response: %w", encErr)
		}
		return wire, false, nil
	}

	q := request.Questions[0]
	res, err := h.resolver.Resolve(ctx, q.Name, q.Type)
	var response *protocol.Message
	cached := false
	stale := false
	if err != nil || res == nil || res.Message == nil {
		response = &protocol.Message{
			Header:    protocol.Header{ID: request.Header.ID, QR: true, RD: request.Header.RD, RA: true, RCode: protocol.RCodeServerFailure},
			Questions: []protocol.Question{q},
		}
	} else {
		response = res.Message
		cached = res.Cached
		stale = res.Stale
		response.Header.ID = request.Header.ID
		response.Header.QR = true
		response.Header.RD = request.Header.RD
		response.Header.RA = true
		if len(response.Questions) == 0 {
			response.Questions = []protocol.Question{q}
		}
	}

	respWire, err := protocol.Encode(response)
	if err != nil {
		return nil, false, fmt.Errorf("encode response: %w", err)
	}

	clientSupportsEDNS := hasEDNS(request)
	if protocolName == "udp" && !clientSupportsEDNS && len(respWire) > 512 {
		response.Header.TC = true
		response.Answers = nil
		response.Authorities = nil
		response.Additionals = nil
		respWire, err = protocol.Encode(response)
		if err != nil {
			return nil, false, fmt.Errorf("encode truncated response: %w", err)
		}
	}

	h.cfgMu.RLock()
	rrlEnabled := h.rrlEnabled
	h.cfgMu.RUnlock()
	if rrlEnabled && h.rrl != nil {
		tuple := strings.Join([]string{clientIP, strings.ToLower(q.Name), protocol.TypeToString(q.Type), protocol.RCodeToString(response.Header.RCode)}, "|")
		if !h.rrl.Allow(tuple) {
			h.incSecurityDrop("rrl")
			if h.prom != nil {
				h.prom.IncSecurityDrop("rrl")
			}
			return nil, true, nil
		}
	}

	dur := time.Since(started)
	if h.metrics != nil {
		h.metrics.ObserveQuery(protocol.TypeToString(q.Type), protocolName, protocol.RCodeToString(response.Header.RCode), cached, stale, dur)
	}
	if h.prom != nil {
		h.prom.ObserveQuery(protocol.TypeToString(q.Type), protocolName, protocol.RCodeToString(response.Header.RCode), cached)
	}
	h.observeResolutionEvents(protocol.TypeToString(q.Type), res)
	h.publishQueryEvent(QueryEvent{
		ID:         resID(res),
		QueryID:    resID(res),
		Timestamp:  time.Now().UTC(),
		Domain:     q.Name,
		Type:       protocol.TypeToString(q.Type),
		QueryType:  protocol.TypeToString(q.Type),
		ClientIP:   clientIP,
		Protocol:   protocolName,
		LatencyMS:  dur.Milliseconds(),
		DurationMS: dur.Milliseconds(),
		Steps:      eventCount(res),
		RCode:      protocol.RCodeToString(response.Header.RCode),
		Cached:     cached,
		Stale:      stale,
	})
	h.recordQueryClient(resID(res), clientIP)
	h.logQuery(ctx, q, response, protocolName, clientIP, dur, cached, stale, res, err)
	h.updateObservabilityGauges()
	return respWire, false, nil
}

func (h *Handler) recordQueryClient(queryID, clientIP string) {
	if strings.TrimSpace(queryID) == "" || strings.TrimSpace(clientIP) == "" {
		return
	}
	h.queryClientMu.Lock()
	if len(h.queryClientIP) >= 2000 {
		for k := range h.queryClientIP {
			delete(h.queryClientIP, k)
			break
		}
	}
	h.queryClientIP[queryID] = clientIP
	h.queryClientMu.Unlock()
}

func (h *Handler) ClientIPForQuery(queryID string) (string, bool) {
	id := strings.TrimSpace(queryID)
	if id == "" {
		return "", false
	}
	h.queryClientMu.RLock()
	ip, ok := h.queryClientIP[id]
	h.queryClientMu.RUnlock()
	return ip, ok
}

func (h *Handler) ReverseHostname(clientIP string) string {
	clientIP = strings.TrimSpace(clientIP)
	if net.ParseIP(clientIP) == nil {
		return ""
	}
	h.rdnsMu.RLock()
	if host, ok := h.rdnsCache[clientIP]; ok {
		h.rdnsMu.RUnlock()
		return host
	}
	h.rdnsMu.RUnlock()

	lookup := h.lookupAddr
	if lookup == nil {
		lookup = net.DefaultResolver.LookupAddr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	host := ""
	if names, err := lookup(ctx, clientIP); err == nil && len(names) > 0 {
		host = strings.TrimSuffix(strings.TrimSpace(names[0]), ".")
	}

	h.rdnsMu.Lock()
	if len(h.rdnsCache) >= 1024 {
		for k := range h.rdnsCache {
			delete(h.rdnsCache, k)
			break
		}
	}
	h.rdnsCache[clientIP] = host
	h.rdnsMu.Unlock()
	return host
}

func (h *Handler) SetLookupAddrFunc(fn func(ctx context.Context, addr string) ([]string, error)) {
	if fn == nil {
		return
	}
	h.rdnsMu.Lock()
	h.lookupAddr = fn
	h.rdnsMu.Unlock()
}

func resID(res *resolver.ResolveResult) string {
	if res == nil {
		return ""
	}
	return res.QueryID
}

func eventCount(res *resolver.ResolveResult) int {
	if res == nil {
		return 0
	}
	return len(res.Events)
}

func (h *Handler) formerrFromPacket(raw []byte) []byte {
	id := uint16(0)
	if len(raw) >= 2 {
		id = uint16(raw[0])<<8 | uint16(raw[1])
	}
	return h.formerrFromID(id)
}

func (h *Handler) formerrFromID(id uint16) []byte {
	msg := &protocol.Message{Header: protocol.Header{ID: id, QR: true, RCode: protocol.RCodeFormatError}}
	wire, _ := protocol.Encode(msg)
	return wire
}

func hasEDNS(msg *protocol.Message) bool {
	for _, rr := range msg.Additionals {
		if rr.Type == protocol.TypeOPT {
			return true
		}
	}
	return false
}

func clientIPString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP.String()
	case *net.TCPAddr:
		return a.IP.String()
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return addr.String()
		}
		return host
	}
}

func (h *Handler) SubscribeQueries(buffer int) chan QueryEvent {
	if buffer <= 0 {
		buffer = 128
	}
	ch := make(chan QueryEvent, buffer)
	h.queryMu.Lock()
	h.querySubs[ch] = struct{}{}
	h.queryMu.Unlock()
	return ch
}

func (h *Handler) UnsubscribeQueries(ch chan QueryEvent) {
	h.queryMu.Lock()
	defer h.queryMu.Unlock()
	if _, ok := h.querySubs[ch]; ok {
		delete(h.querySubs, ch)
		close(ch)
	}
}

func (h *Handler) publishQueryEvent(ev QueryEvent) {
	h.queryMu.RLock()
	defer h.queryMu.RUnlock()
	for ch := range h.querySubs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (h *Handler) SecurityStatsJSON() []byte {
	data := h.SecurityStats()
	b, _ := json.Marshal(data)
	return b
}

func (h *Handler) SecurityStats() map[string]uint64 {
	h.securityMu.Lock()
	defer h.securityMu.Unlock()
	out := make(map[string]uint64, len(h.securityDrop))
	for k, v := range h.securityDrop {
		out[k] = v
	}
	return out
}

func (h *Handler) incSecurityDrop(reason string) {
	h.securityMu.Lock()
	h.securityDrop[reason]++
	h.securityMu.Unlock()
	if h.metrics != nil {
		h.metrics.IncSecurityDrop(reason)
	}
}

func (h *Handler) Metrics() *metrics.Metrics {
	return h.metrics
}

func (h *Handler) Prometheus() *metrics.PromMetrics {
	return h.prom
}

func (h *Handler) RRLDrops() uint64 {
	if h.rrl == nil {
		return 0
	}
	return h.rrl.Drops()
}

func (h *Handler) RateLimiterTrackedIPs() int {
	if h.limiter == nil {
		return 0
	}
	return h.limiter.Size()
}

func (h *Handler) RateLimiterBlocked(limit int) []security.BlockedIP {
	if h.limiter == nil {
		return nil
	}
	return h.limiter.BlockedIPs(limit)
}

func (h *Handler) RateLimiterDrops() uint64 {
	if h.limiter == nil {
		return 0
	}
	return h.limiter.TotalDrops()
}

func (h *Handler) RRLTrackedTuples() int {
	if h.rrl == nil {
		return 0
	}
	return h.rrl.Size()
}

func (h *Handler) ApplyRuntimeSettings(settings map[string]any) map[string]any {
	applied := map[string]any{}
	if settings == nil {
		return applied
	}
	if h.resolver != nil {
		for k, v := range h.resolver.ApplyRuntimeSettings(settings) {
			applied[k] = v
		}
	}
	if v, ok := boolFromAny(settings["rrl_enabled"]); ok {
		h.cfgMu.Lock()
		h.rrlEnabled = v
		h.cfgMu.Unlock()
		applied["rrl_enabled"] = v
	}
	if v, ok := boolFromAny(settings["allow_recursive"]); ok {
		h.cfgMu.Lock()
		h.allowRecursive = v
		h.cfgMu.Unlock()
		applied["allow_recursive"] = v
	}
	if h.limiter != nil {
		qps, hasQPS := floatFromAny(settings["rate_limit_qps"])
		burst, hasBurst := intFromAny(settings["rate_limit_burst"])
		if hasQPS || hasBurst {
			h.limiter.Update(qps, burst)
			rate, b := h.limiter.Config()
			applied["rate_limit_qps"] = rate
			applied["rate_limit_burst"] = b
		}
	}
	if h.rrl != nil {
		limit, hasLimit := intFromAny(settings["rrl_responses_per_sec"])
		slip, hasSlip := intFromAny(settings["rrl_slip"])
		if hasLimit || hasSlip {
			h.rrl.Update(limit, slip)
			l, s := h.rrl.Config()
			applied["rrl_responses_per_sec"] = l
			applied["rrl_slip"] = s
		}
	}
	return applied
}

func (h *Handler) RuntimeConfig() map[string]any {
	h.cfgMu.RLock()
	rrlEnabled := h.rrlEnabled
	allowRecursive := h.allowRecursive
	h.cfgMu.RUnlock()
	out := map[string]any{}
	if h.resolver != nil {
		for k, v := range h.resolver.RuntimeConfig() {
			out[k] = v
		}
	}
	out["rrl_enabled"] = rrlEnabled
	out["allow_recursive"] = allowRecursive
	if h.limiter != nil {
		rate, burst := h.limiter.Config()
		out["rate_limit_qps"] = rate
		out["rate_limit_burst"] = burst
	}
	if h.rrl != nil {
		limit, slip := h.rrl.Config()
		out["rrl_responses_per_sec"] = limit
		out["rrl_slip"] = slip
	}
	return out
}

func boolFromAny(v any) (bool, bool) {
	b, ok := v.(bool)
	return b, ok
}

func floatFromAny(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}

func intFromAny(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
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

func (h *Handler) logRateLimit(ip string) {
	if h.logger == nil || strings.TrimSpace(ip) == "" {
		return
	}
	now := time.Now()
	if h.now != nil {
		now = h.now()
	}
	level := slog.LevelDebug
	h.rateLogMu.Lock()
	last, ok := h.rateLogAt[ip]
	if !ok || now.Sub(last) > 60*time.Second {
		level = slog.LevelWarn
		h.rateLogAt[ip] = now
	}
	h.rateLogMu.Unlock()
	h.logger.Log(context.Background(), level, "rate limit drop", slog.String("client_ip", ip))
}

func (h *Handler) logMalformedPacket(reason string, raw []byte, decodeErr error, protocolName string, clientIP string) {
	if h.logger == nil {
		return
	}
	hexPayload := hex.EncodeToString(raw)
	if len(hexPayload) > 4096 {
		hexPayload = hexPayload[:4096]
	}
	attrs := []any{
		slog.String("reason", reason),
		slog.String("protocol", protocolName),
		slog.String("client_ip", clientIP),
		slog.String("raw_hex", hexPayload),
	}
	if decodeErr != nil {
		attrs = append(attrs, slog.Any("error", decodeErr))
	}
	h.logger.Debug("malformed dns packet", attrs...)
}

func (h *Handler) logSecurityReason(reason string) {
	if h.logger == nil || strings.TrimSpace(reason) == "" {
		return
	}
	now := time.Now()
	if h.now != nil {
		now = h.now()
	}
	level := slog.LevelDebug
	h.secLogMu.Lock()
	last, ok := h.secLogAt[reason]
	if !ok || now.Sub(last) > 60*time.Second {
		level = slog.LevelWarn
		h.secLogAt[reason] = now
	}
	h.secLogMu.Unlock()
	h.logger.Log(context.Background(), level, "security event", slog.String("reason", reason))
}

func (h *Handler) logQuery(ctx context.Context, q protocol.Question, response *protocol.Message, protocolName string, clientIP string, dur time.Duration, cached bool, stale bool, res *resolver.ResolveResult, resolveErr error) {
	if h.logger == nil {
		return
	}
	rcode := uint8(protocol.RCodeServerFailure)
	if response != nil {
		rcode = response.Header.RCode
	}
	level := slog.LevelInfo
	if resolveErr != nil {
		level = slog.LevelError
	}
	ilogger.LogQuery(h.logger, level, ilogger.QueryLogFields{
		RequestID:  ilogger.RequestIDFromContext(ctx),
		QueryID:    resID(res),
		TraceID:    ilogger.TraceIDFromContext(ctx),
		Domain:     q.Name,
		QType:      protocol.TypeToString(q.Type),
		RCode:      protocol.RCodeToString(rcode),
		DurationMS: dur.Milliseconds(),
		Cached:     cached,
		Stale:      stale,
		ClientIP:   clientIP,
		Protocol:   protocolName,
		Steps:      eventCount(res),
		Err:        resolveErr,
	})
}

func (h *Handler) updateObservabilityGauges() {
	if h.resolver == nil {
		return
	}
	if h.prom != nil {
		cs := h.resolver.CacheStats()
		h.prom.SetCacheEntries("positive", float64(cs.PositiveEntries))
		h.prom.SetCacheEntries("negative", float64(cs.NegativeEntries))
		h.prom.SetCacheEntries("stale", float64(cs.StaleEntries))
		h.prom.SetGoroutines(runtime.NumGoroutine())
	}
	if h.metrics != nil || h.prom != nil {
		for _, up := range h.resolver.UpstreamStatuses() {
			if h.metrics != nil {
				h.metrics.SetCircuitState(up.Server, up.StateCode)
			}
			if h.prom != nil {
				h.prom.SetCircuitState(up.Server, up.StateCode)
			}
		}
	}
}

func (h *Handler) observeResolutionEvents(qtype string, res *resolver.ResolveResult) {
	if res == nil {
		return
	}
	for _, ev := range res.Events {
		if ev.Server == "" || ev.Latency <= 0 {
			continue
		}
		dur := time.Duration(ev.Latency) * time.Millisecond
		zone := zoneLabelForStep(ev.StepType)
		if h.metrics != nil {
			h.metrics.ObserveUpstream(ev.Server, dur)
		}
		if h.prom != nil {
			h.prom.ObserveResolutionStep(qtype, ev.StepType, dur)
			h.prom.ObserveUpstream(ev.Server, zone, dur)
		}
	}
}

func zoneLabelForStep(stepType string) string {
	switch stepType {
	case "root_query":
		return "root"
	case "tld_query":
		return "tld"
	default:
		return "auth"
	}
}
