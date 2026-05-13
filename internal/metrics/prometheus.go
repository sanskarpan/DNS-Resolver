package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var durationBuckets = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type promHistogram struct {
	counts []uint64
	sum    float64
	count  uint64
}

func newPromHistogram() *promHistogram {
	return &promHistogram{counts: make([]uint64, len(durationBuckets)+1)}
}

func (h *promHistogram) Observe(value float64) {
	idx := len(durationBuckets)
	for i, bucket := range durationBuckets {
		if value <= bucket {
			idx = i
			break
		}
	}
	h.counts[idx]++
	h.sum += value
	h.count++
}

type PromMetrics struct {
	mu                 sync.Mutex
	queryTotal         map[string]float64
	resolutionDuration map[string]*promHistogram
	upstreamDuration   map[string]*promHistogram
	cacheEntries       map[string]float64
	circuitState       map[string]float64
	securityDrops      map[string]float64
	goroutines         float64
}

func NewPrometheus() *PromMetrics {
	return &PromMetrics{
		queryTotal:         map[string]float64{},
		resolutionDuration: map[string]*promHistogram{},
		upstreamDuration:   map[string]*promHistogram{},
		cacheEntries:       map[string]float64{},
		circuitState:       map[string]float64{},
		securityDrops:      map[string]float64{},
	}
}

func (p *PromMetrics) ObserveQuery(qtype, protocol, rcode string, cached bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := fmt.Sprintf("type=%s,protocol=%s,rcode=%s,cached=%t", qtype, protocol, rcode, cached)
	p.queryTotal[key]++
}

func (p *PromMetrics) ObserveResolutionStep(qtype, step string, dur time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := fmt.Sprintf("type=%s,step=%s", qtype, step)
	hist := p.resolutionDuration[key]
	if hist == nil {
		hist = newPromHistogram()
		p.resolutionDuration[key] = hist
	}
	hist.Observe(dur.Seconds())
}

func (p *PromMetrics) ObserveUpstream(server, zone string, dur time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := fmt.Sprintf("server=%s,zone=%s", server, zone)
	hist := p.upstreamDuration[key]
	if hist == nil {
		hist = newPromHistogram()
		p.upstreamDuration[key] = hist
	}
	hist.Observe(dur.Seconds())
}

func (p *PromMetrics) SetCacheEntries(kind string, value float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cacheEntries[kind] = value
}

func (p *PromMetrics) SetCircuitState(server string, state int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.circuitState[server] = float64(state)
}

func (p *PromMetrics) IncSecurityDrop(reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.securityDrops[reason]++
}

func (p *PromMetrics) SetGoroutines(count int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.goroutines = float64(count)
}

func (p *PromMetrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		p.mu.Lock()
		defer p.mu.Unlock()

		var lines []string
		for k, v := range p.queryTotal {
			lines = append(lines, fmt.Sprintf("dns_query_total{%s} %v", promLabels(k), v))
		}
		for k, hist := range p.resolutionDuration {
			lines = append(lines, histogramLines("dns_resolution_duration_seconds", k, hist)...)
		}
		for k, hist := range p.upstreamDuration {
			lines = append(lines, histogramLines("dns_upstream_query_duration_seconds", k, hist)...)
		}
		for kind, v := range p.cacheEntries {
			lines = append(lines, fmt.Sprintf("dns_cache_entries{kind=%q} %v", kind, v))
		}
		for server, v := range p.circuitState {
			lines = append(lines, fmt.Sprintf("dns_circuit_breaker_state{server=%q} %v", server, v))
		}
		for reason, v := range p.securityDrops {
			lines = append(lines, fmt.Sprintf("dns_security_drops_total{reason=%q} %v", reason, v))
		}
		lines = append(lines, fmt.Sprintf("dns_goroutine_count %v", p.goroutines))

		sort.Strings(lines)
		_, _ = w.Write([]byte(strings.Join(lines, "\n") + "\n"))
	})
}

func histogramLines(metric string, labelKey string, hist *promHistogram) []string {
	if hist == nil {
		return nil
	}
	baseLabels := promLabels(labelKey)
	lines := make([]string, 0, len(durationBuckets)+3)
	cumulative := uint64(0)
	for i, bucket := range durationBuckets {
		cumulative += hist.counts[i]
		lines = append(lines, fmt.Sprintf("%s_bucket{%s,le=%q} %d", metric, baseLabels, strconv.FormatFloat(bucket, 'f', -1, 64), cumulative))
	}
	cumulative += hist.counts[len(hist.counts)-1]
	lines = append(lines, fmt.Sprintf("%s_bucket{%s,le=%q} %d", metric, baseLabels, "+Inf", cumulative))
	lines = append(lines, fmt.Sprintf("%s_sum{%s} %v", metric, baseLabels, hist.sum))
	lines = append(lines, fmt.Sprintf("%s_count{%s} %d", metric, baseLabels, hist.count))
	return lines
}

func promLabels(k string) string {
	parts := strings.Split(k, ",")
	labels := make([]string, 0, len(parts))
	for _, p := range parts {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			continue
		}
		labels = append(labels, fmt.Sprintf("%s=%q", kv[0], kv[1]))
	}
	return strings.Join(labels, ",")
}
