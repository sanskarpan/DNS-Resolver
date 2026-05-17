package api

import (
	"context"
	"log/slog"
	"net/http"
	"sync"

	"dnsresolver/internal/cache"
	"dnsresolver/internal/metrics"
	"dnsresolver/internal/resolver"
	"dnsresolver/internal/server"
)

type RuntimeSettings struct {
	mu   sync.RWMutex
	data map[string]any
}

func NewRuntimeSettings(initial map[string]any) *RuntimeSettings {
	if initial == nil {
		initial = map[string]any{}
	}
	return &RuntimeSettings{data: initial}
}

func (s *RuntimeSettings) Get() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]any, len(s.data))
	for k, v := range s.data {
		out[k] = v
	}
	return out
}

func (s *RuntimeSettings) Update(next map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range next {
		s.data[k] = v
	}
}

type Deps struct {
	Resolver          *resolver.Resolver
	Cache             *cache.Cache
	DNSHandler        *server.Handler
	Metrics           *metrics.Metrics
	Prometheus        *metrics.PromMetrics
	ReadyCheck        func() bool
	Settings          *RuntimeSettings
	Logger            *slog.Logger
	PPROFEnabled      bool
	ControlPlaneToken string
}

type API struct {
	deps Deps
}

func New(deps Deps) *API {
	if deps.Settings == nil {
		deps.Settings = NewRuntimeSettings(nil)
	}
	if deps.ReadyCheck == nil {
		deps.ReadyCheck = func() bool { return true }
	}
	return &API{deps: deps}
}

func (a *API) Router(ctx context.Context) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health/live", a.live)
	mux.HandleFunc("/api/v1/health/ready", a.ready)
	mux.HandleFunc("/api/v1/resolve", a.resolve)
	mux.HandleFunc("/api/v1/cache/stats", a.cacheStats)
	mux.HandleFunc("/api/v1/cache", a.cache)
	mux.HandleFunc("/api/v1/cache/", a.cacheKey)
	mux.HandleFunc("/api/v1/metrics", a.metrics)
	if a.deps.Prometheus != nil {
		mux.HandleFunc("/metrics", a.prometheus)
	}
	mux.HandleFunc("/api/v1/history", a.history)
	mux.HandleFunc("/api/v1/history/", a.historyByID)
	mux.HandleFunc("/api/v1/reverse", a.reverseLookup)
	mux.HandleFunc("/api/v1/compare", a.compare)
	mux.HandleFunc("/api/v1/bulk", a.bulk)
	mux.HandleFunc("/api/v1/rootservers", a.rootservers)
	mux.HandleFunc("/api/v1/settings", a.settings)
	mux.HandleFunc("/api/v1/security/stats", a.securityStats)
	mux.HandleFunc("/dns-query", a.doh)
	mux.HandleFunc("/ws/trace", a.wsTrace(ctx))
	mux.HandleFunc("/ws/metrics", a.wsMetrics(ctx))
	mux.HandleFunc("/ws/queries", a.wsQueries(ctx))
	mux.HandleFunc("/", a.index)

	if a.deps.PPROFEnabled {
		a.mountPProf(mux)
	}

	return a.withMiddleware(mux)
}
