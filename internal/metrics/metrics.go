package metrics

import (
	"runtime"
	runtimemetrics "runtime/metrics"
	"sort"
	"sync"
	"time"
)

type Snapshot struct {
	TotalQueries      uint64             `json:"total_queries"`
	QPS1m             float64            `json:"qps_1m"`
	QPS5m             float64            `json:"qps_5m"`
	QPS15m            float64            `json:"qps_15m"`
	CacheHitRate      float64            `json:"cache_hit_rate"`
	StaleHitRate      float64            `json:"stale_hit_rate"`
	LatencyP50        float64            `json:"latency_p50"`
	LatencyP95        float64            `json:"latency_p95"`
	LatencyP99        float64            `json:"latency_p99"`
	LatencyP50MS      float64            `json:"latency_p50_ms"`
	LatencyP95MS      float64            `json:"latency_p95_ms"`
	LatencyP99MS      float64            `json:"latency_p99_ms"`
	LatencyMaxMS      float64            `json:"latency_max_ms"`
	TypeDistribution  map[string]uint64  `json:"type_distribution"`
	RCodeDistribution map[string]uint64  `json:"rcode_distribution"`
	ActiveConnTotal   int64              `json:"active_connections_total"`
	RuntimeHeapBytes  uint64             `json:"runtime_heap_bytes"`
	RuntimeGCPauseSec float64            `json:"runtime_gc_pause_seconds"`
	RuntimeGoRoutines uint64             `json:"runtime_goroutines"`
	ByType            map[string]uint64  `json:"by_type"`
	ByRCode           map[string]uint64  `json:"by_rcode"`
	ByProtocol        map[string]uint64  `json:"by_protocol"`
	SecurityDrops     map[string]uint64  `json:"security_drops"`
	CircuitState      map[string]int     `json:"circuit_state"`
	ActiveConnections map[string]int64   `json:"active_connections"`
	Goroutines        int                `json:"goroutines"`
	UpstreamLatencyMS map[string]float64 `json:"upstream_avg_latency_ms"`
	Timestamp         time.Time          `json:"timestamp"`
}

type Metrics struct {
	mu              sync.RWMutex
	total           uint64
	hits            uint64
	staleHits       uint64
	latencies       []float64
	byType          map[string]uint64
	byRCode         map[string]uint64
	byProtocol      map[string]uint64
	securityDrops   map[string]uint64
	circuitState    map[string]int
	active          map[string]int64
	upstreamSamples map[string][]float64
	queryTimes      []time.Time
	now             func() time.Time
}

func New() *Metrics {
	return &Metrics{
		latencies:       make([]float64, 0, 4096),
		byType:          map[string]uint64{},
		byRCode:         map[string]uint64{},
		byProtocol:      map[string]uint64{},
		securityDrops:   map[string]uint64{},
		circuitState:    map[string]int{},
		active:          map[string]int64{},
		upstreamSamples: map[string][]float64{},
		queryTimes:      make([]time.Time, 0, 4096),
		now:             time.Now,
	}
}

func (m *Metrics) ObserveQuery(qtype, protocol, rcode string, cached bool, stale bool, dur time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now().UTC()
	m.total++
	if cached {
		m.hits++
	}
	if stale {
		m.staleHits++
	}
	m.byType[qtype]++
	m.byRCode[rcode]++
	m.byProtocol[protocol]++
	m.latencies = append(m.latencies, float64(dur.Milliseconds()))
	m.queryTimes = append(m.queryTimes, now)
	if len(m.latencies) > 10000 {
		m.latencies = m.latencies[len(m.latencies)-10000:]
	}
	cutoff := now.Add(-15 * time.Minute)
	trimIdx := 0
	for trimIdx < len(m.queryTimes) && m.queryTimes[trimIdx].Before(cutoff) {
		trimIdx++
	}
	if trimIdx > 0 {
		m.queryTimes = append([]time.Time(nil), m.queryTimes[trimIdx:]...)
	}
}

func (m *Metrics) ObserveUpstream(server string, dur time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.upstreamSamples[server]
	s = append(s, float64(dur.Milliseconds()))
	if len(s) > 512 {
		s = s[len(s)-512:]
	}
	m.upstreamSamples[server] = s
}

func (m *Metrics) SetCircuitState(server string, state int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.circuitState[server] = state
}

func (m *Metrics) IncSecurityDrop(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.securityDrops[reason]++
}

func (m *Metrics) SetActiveConnections(protocol string, n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active[protocol] = n
}

func (m *Metrics) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := m.now().UTC()

	latCopy := append([]float64(nil), m.latencies...)
	sort.Float64s(latCopy)
	p := func(q float64) float64 {
		if len(latCopy) == 0 {
			return 0
		}
		i := int(float64(len(latCopy)-1) * q)
		if i < 0 {
			i = 0
		}
		if i >= len(latCopy) {
			i = len(latCopy) - 1
		}
		return latCopy[i]
	}
	max := 0.0
	if len(latCopy) > 0 {
		max = latCopy[len(latCopy)-1]
	}

	upAvg := make(map[string]float64, len(m.upstreamSamples))
	for server, samples := range m.upstreamSamples {
		if len(samples) == 0 {
			continue
		}
		sum := 0.0
		for _, v := range samples {
			sum += v
		}
		upAvg[server] = sum / float64(len(samples))
	}

	hitRate := 0.0
	staleRate := 0.0
	if m.total > 0 {
		hitRate = float64(m.hits) / float64(m.total)
		staleRate = float64(m.staleHits) / float64(m.total)
	}
	q1m, q5m, q15m := qpsWindows(m.queryTimes, now)
	activeTotal := int64(0)
	for _, n := range m.active {
		activeTotal += n
	}
	heapBytes, gcPause, runtimeGoRoutines := runtimeSnapshot()

	return Snapshot{
		TotalQueries:      m.total,
		QPS1m:             q1m,
		QPS5m:             q5m,
		QPS15m:            q15m,
		CacheHitRate:      hitRate,
		StaleHitRate:      staleRate,
		LatencyP50:        p(0.50),
		LatencyP95:        p(0.95),
		LatencyP99:        p(0.99),
		LatencyP50MS:      p(0.50),
		LatencyP95MS:      p(0.95),
		LatencyP99MS:      p(0.99),
		LatencyMaxMS:      max,
		TypeDistribution:  copyMap(m.byType),
		RCodeDistribution: copyMap(m.byRCode),
		ActiveConnTotal:   activeTotal,
		RuntimeHeapBytes:  heapBytes,
		RuntimeGCPauseSec: gcPause,
		RuntimeGoRoutines: runtimeGoRoutines,
		ByType:            copyMap(m.byType),
		ByRCode:           copyMap(m.byRCode),
		ByProtocol:        copyMap(m.byProtocol),
		SecurityDrops:     copyMap(m.securityDrops),
		CircuitState:      copyMapInt(m.circuitState),
		ActiveConnections: copyMapInt64(m.active),
		Goroutines:        runtime.NumGoroutine(),
		UpstreamLatencyMS: upAvg,
		Timestamp:         now,
	}
}

func qpsWindows(times []time.Time, now time.Time) (float64, float64, float64) {
	c1m := 0
	c5m := 0
	c15m := 0
	w1m := now.Add(-1 * time.Minute)
	w5m := now.Add(-5 * time.Minute)
	w15m := now.Add(-15 * time.Minute)
	for _, t := range times {
		if !t.Before(w1m) {
			c1m++
		}
		if !t.Before(w5m) {
			c5m++
		}
		if !t.Before(w15m) {
			c15m++
		}
	}
	return float64(c1m) / 60.0, float64(c5m) / 300.0, float64(c15m) / 900.0
}

func runtimeSnapshot() (heapBytes uint64, gcPauseSeconds float64, goroutines uint64) {
	samples := []runtimemetrics.Sample{
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/gc/pauses:seconds"},
		{Name: "/sched/goroutines:goroutines"},
	}
	runtimemetrics.Read(samples)
	if samples[0].Value.Kind() == runtimemetrics.KindUint64 {
		heapBytes = samples[0].Value.Uint64()
	}
	if samples[2].Value.Kind() == runtimemetrics.KindUint64 {
		goroutines = samples[2].Value.Uint64()
	}
	if samples[1].Value.Kind() == runtimemetrics.KindFloat64Histogram {
		h := samples[1].Value.Float64Histogram()
		var total uint64
		var weighted float64
		for i, c := range h.Counts {
			if c == 0 || i+1 >= len(h.Buckets) {
				continue
			}
			mid := (h.Buckets[i] + h.Buckets[i+1]) / 2
			weighted += mid * float64(c)
			total += c
		}
		if total > 0 {
			gcPauseSeconds = weighted / float64(total)
		}
	}
	return heapBytes, gcPauseSeconds, goroutines
}

func copyMap(in map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func copyMapInt(in map[string]int) map[string]int {
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func copyMapInt64(in map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
