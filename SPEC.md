# Claude Code Prompt — Full-Stack DNS Resolver (Go + SvelteKit)

---

## PROJECT OVERVIEW

Build a **production-grade, in-depth DNS Resolver** from scratch — no shortcuts, no DNS libraries doing the heavy lifting. This is an educational + functional tool that exposes every layer of the DNS protocol visually.

**Stack:**
- **Backend:** Go (Golang) — raw UDP/TCP socket server, manual RFC 1035 wire format parsing, recursive resolution engine, HTTP + WebSocket API
- **Frontend:** SvelteKit + TypeScript + Tailwind CSS + shadcn-svelte — real-time dashboard, packet inspector, cache viewer, query tracer

The goal is a developer tool that looks and feels like a polished internal tool (think: Insomnia, Tauri apps, Linear's aesthetic — dark, dense, precise). It must be **fully functional as an actual DNS resolver** (you can point your OS's DNS to it) AND have a rich visual frontend.

---

## TECHNICAL REQUIREMENTS — BACKEND (Go)

### Project Structure

```
DNS-Resolver/
├── cmd/
│   └── server/
│       └── main.go                  # entrypoint, flags, signal handling, graceful drain
├── internal/
│   ├── protocol/
│   │   ├── message.go               # DNS Message struct
│   │   ├── header.go                # DNS Header parsing/serialization
│   │   ├── question.go              # Question section
│   │   ├── resource_record.go       # Answer/Authority/Additional RR
│   │   ├── rdata.go                 # RDATA parsers per record type
│   │   ├── encoder.go               # Wire format serializer
│   │   ├── decoder.go               # Wire format deserializer (with pointer compression)
│   │   ├── types.go                 # All DNS constants (QType, QClass, RCode, Opcode enums)
│   │   ├── decoder_fuzz_test.go     # go test -fuzz targets for malformed packet fuzzing
│   │   └── encoder_test.go          # Round-trip unit + benchmark tests
│   ├── resolver/
│   │   ├── resolver.go              # Core resolution logic entry
│   │   ├── recursive.go             # Recursive resolution walking root→TLD→auth
│   │   ├── iterative.go             # Iterative query logic
│   │   ├── hints.go                 # Root server hints (hardcoded + refreshable)
│   │   ├── pipeline.go              # Resolution pipeline with event emission
│   │   ├── qname_minimization.go    # RFC 7816 QNAME minimization
│   │   ├── bailiwick.go             # Bailiwick checking — reject out-of-zone glue
│   │   └── circuit_breaker.go       # Per-upstream circuit breaker (closed/open/half-open)
│   ├── cache/
│   │   ├── cache.go                 # TTL-aware LRU cache
│   │   ├── negative.go              # Negative caching (NXDOMAIN, NODATA)
│   │   ├── stale.go                 # Stale-while-revalidate logic
│   │   └── stats.go                 # Cache hit/miss/eviction stats
│   ├── security/
│   │   ├── ratelimit.go             # Per-source-IP rate limiter (token bucket)
│   │   ├── rrl.go                   # Response Rate Limiting (RRL) — anti-amplification
│   │   ├── qid_randomizer.go        # Cryptographically random query ID generation
│   │   ├── port_randomizer.go       # Source port randomization (RFC 5452)
│   │   └── case_randomizer.go       # 0x20 mixed-case query encoding (anti-poisoning)
│   ├── server/
│   │   ├── udp.go                   # UDP listener on port 53
│   │   ├── tcp.go                   # TCP listener on port 53 (messages >512 bytes)
│   │   ├── dot.go                   # DNS over TLS (port 853)
│   │   └── handler.go               # Request routing, timeout handling, drain tracking
│   ├── api/
│   │   ├── router.go                # HTTP router (chi)
│   │   ├── handlers.go              # REST endpoints
│   │   ├── websocket.go             # WebSocket hub + broadcast
│   │   ├── middleware.go            # CORS, structured logging, rate limiting, request-id
│   │   └── health.go                # /health/live + /health/ready split endpoints
│   ├── metrics/
│   │   ├── metrics.go               # In-memory metrics store
│   │   └── prometheus.go            # Prometheus /metrics exporter
│   ├── telemetry/
│   │   ├── tracer.go                # OpenTelemetry tracer setup (OTLP exporter)
│   │   └── spans.go                 # Span helpers for resolution pipeline
│   └── logger/
│       └── logger.go                # Structured logger (slog) with mandatory fields
├── frontend/                        # SvelteKit app (separate)
├── deploy/
│   ├── kubernetes/
│   │   ├── deployment.yaml          # Kubernetes Deployment with resource limits
│   │   ├── service.yaml             # ClusterIP + LoadBalancer services
│   │   ├── configmap.yaml           # Config as ConfigMap
│   │   ├── hpa.yaml                 # HorizontalPodAutoscaler
│   │   └── pdb.yaml                 # PodDisruptionBudget
│   └── prometheus/
│       ├── prometheus.yml           # Scrape config
│       └── grafana-dashboard.json   # Pre-built Grafana dashboard
├── .github/
│   └── workflows/
│       ├── ci.yml                   # Test + lint + fuzz on every PR
│       └── release.yml              # Build + Docker push on tag
├── config/
│   └── config.go                    # Config struct, env vars, flags, validation
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
├── .dockerignore
└── docker-compose.yml
```

### Protocol Layer — Manual Wire Format (NO miekg/dns for core logic)

Implement **full RFC 1035 DNS wire format** parsing and serialization from scratch:

**Header (12 bytes):**
- ID (16 bits), QR, Opcode, AA, TC, RD, RA, Z, RCODE flags
- QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT

**Name Compression:**
- Implement pointer following (0xC0 prefix) for decompression
- Implement name compression for encoding outgoing messages
- Cycle detection to prevent infinite loops on malformed packets

**Record Types to Support (parse RDATA fully):**
- A (IPv4)
- AAAA (IPv6)
- CNAME (canonical name — must follow chains)
- MX (mail exchange + priority)
- NS (nameserver)
- SOA (start of authority — all 7 fields)
- TXT (multiple strings)
- PTR (reverse DNS)
- SRV (service locator)
- CAA (certification authority authorization)
- ANY (meta-query)

**Wire Format:**
- All integers big-endian (network byte order)
- Labels: length-prefixed segments
- RData: type-specific binary layouts per RFC

### Resolver Engine

Implement **full recursive resolution** walking the DNS hierarchy:

1. Check local cache first (with TTL validation)
2. If not cached, start from root servers (`a.root-servers.net` through `m.root-servers.net` — hardcode the 13 IP addresses as hints)
3. Send iterative query to root → get NS referral for TLD
4. Query TLD nameserver → get NS referral for domain
5. Query authoritative nameserver → get answer
6. Follow CNAME chains (max 10 hops, detect loops)
7. Store result in cache with TTL from answer
8. Emit resolution events at each hop for real-time tracing

**Features:**
- Configurable timeout per hop (default 5s)
- Retry logic with exponential backoff (3 retries, jitter added)
- Parallel queries to multiple nameservers, take fastest response
- EDNS0 support (OPT record, UDP payload size negotiation up to 4096 bytes)
- DNSSEC-aware (parse RRSIG, DNSKEY, DS records — validation optional but parse them)
- Negative caching: cache NXDOMAIN with SOA minimum TTL
- Minimum TTL enforcement (floor at 30s, configurable)
- Maximum TTL cap (configurable, default 86400s)
- **Stale-while-revalidate**: serve a stale (expired <300s ago) cache entry immediately while triggering background refresh — prevents latency spikes on cache expiry
- **Serve-stale-on-error**: if all upstream servers fail, serve the last known cached value with a warning rather than returning SERVFAIL — last-resort resilience fallback

**Resolution Events (emitted for each step):**
```go
type ResolutionEvent struct {
    QueryID     string        `json:"query_id"`
    Timestamp   time.Time     `json:"timestamp"`
    Step        int           `json:"step"`
    StepType    string        `json:"step_type"`   // "cache_hit", "root_query", "tld_query", "auth_query", "cname_follow", "answer"
    Server      string        `json:"server"`      // IP queried
    ServerName  string        `json:"server_name"` // hostname if known
    Query       string        `json:"query"`
    QueryType   string        `json:"query_type"`
    Latency     int64         `json:"latency_ms"`
    Success     bool          `json:"success"`
    RawRequest  []byte        `json:"raw_request"`   // hex-encoded wire bytes
    RawResponse []byte        `json:"raw_response"`  // hex-encoded wire bytes
    ParsedMsg   *DNSMessage   `json:"parsed_message"` // structured parsed form
    ErrorMsg    string        `json:"error,omitempty"`
}
```

### Cache Layer

- **LRU eviction** with configurable max entries (default 10,000)
- **TTL-aware**: entries expire automatically, check on read
- **Negative cache** separate store: NXDOMAIN entries with SOA-derived TTL
- **Thread-safe**: `sync.RWMutex` throughout
- **Cache stats**: hits, misses, evictions, expirations, total entries, memory estimate
- **Persistence**: optional JSON dump to disk on shutdown, reload on startup — use atomic file write (write to `.tmp` then `os.Rename`) to prevent corruption
- **Prefetching**: when TTL < 10% remaining and entry has been accessed 3+ times, refresh in background goroutine
- **Stale-while-revalidate**: track `stale_until = expired_at + 300s`. If a request arrives for an expired entry within the stale window, return it immediately with a `X-DNS-Stale: true` indicator and kick off background re-resolution
- **Serve-stale-on-error**: separate field `last_good_value` — if upstream resolution fully fails (all retries exhausted), serve last good cached value with RCODE=NOERROR and `X-DNS-Stale-On-Error: true`. Never serve stale data older than `STALE_MAX_AGE` (default 3600s)
- **Memory estimate**: calculate approximate memory usage: sum of all key sizes + serialized RData sizes. Expose via stats endpoint

### Server Layer

**UDP Server (port 53 default, configurable):**
- Goroutine pool — fixed worker pool size (default 1000), queue incoming UDP datagrams, never spawn unbounded goroutines
- 512-byte response truncation with TC bit set → triggers TCP retry from client
- Context-based cancellation per request
- **Max UDP request size**: reject any datagram >4096 bytes with FORMERR — malformed packet guard
- **Graceful drain**: on SIGTERM, stop accepting new UDP packets, wait up to 30s for in-flight goroutines to complete using a `sync.WaitGroup` before exit

**TCP Server (port 53 default, configurable):**
- 2-byte length prefix per message (RFC 1035 §4.2.2)
- Per-connection read/write deadline: 30s idle timeout
- Max concurrent TCP connections: configurable (default 500), reject with REFUSED when at limit
- TLS support (DoT — DNS over TLS) on port 853 with self-signed cert auto-generation on first run
- **Graceful drain**: `net.Listener.Close()` stops accepting, existing connections served until deadline

**HTTP/WS API Server (port 8080 default):**
- REST API for the frontend
- WebSocket for real-time event streaming
- Serve the built SvelteKit frontend as static files from `//go:embed`
- `http.Server.Shutdown(ctx)` with 15s drain timeout on SIGTERM
- `/debug/pprof` endpoint (behind a `PPROF_ENABLED=true` env flag) — never expose in production without auth

### REST API Endpoints

```
GET  /api/v1/health/live               → liveness: is the process running? (always 200 if process is alive)
GET  /api/v1/health/ready              → readiness: is port 53 bound? cache loaded? (200 = ready, 503 = not ready)
GET  /api/v1/resolve?q=&type=&trace=  → resolve a domain, optionally stream trace
GET  /api/v1/cache                     → list all cache entries (paginated, default page=1&limit=50)
GET  /api/v1/cache/stats               → cache hit/miss/size/stale stats
DELETE /api/v1/cache                   → flush entire cache
DELETE /api/v1/cache/:key              → evict specific entry
GET  /api/v1/metrics                   → server metrics (queries/sec, latency p50/p95/p99, etc.)
GET  /metrics                          → Prometheus scrape endpoint (text/plain exposition format)
GET  /api/v1/history                   → recent query history (last 1000, paginated)
GET  /api/v1/history/:id               → full trace for a specific query
GET  /api/v1/compare?q=&type=&servers= → resolve same query via multiple servers, compare
GET  /api/v1/bulk?queries=             → resolve multiple domains in parallel
GET  /api/v1/rootservers               → list root server hints + last response time + circuit breaker state
GET  /api/v1/settings                  → current runtime config
POST /api/v1/settings                  → update config at runtime (block list, TTL limits, etc.)
GET  /api/v1/security/stats            → rate limit hits, blocked IPs, RRL drops, poisoning attempts detected

WS   /ws/trace                         → stream real-time resolution events
WS   /ws/metrics                       → stream live metrics every second
WS   /ws/queries                       → stream every incoming query in real-time

GET  /debug/pprof/                     → pprof index (PPROF_ENABLED=true only)
GET  /debug/pprof/goroutine            → goroutine dump
GET  /debug/pprof/heap                 → heap profile
```

### Metrics Collection

Collect and expose (in-memory + Prometheus):
- Total queries served (UDP + TCP + DoH + DoT) — labelled by protocol
- Queries per second (rolling 1m, 5m, 15m averages)
- Cache hit rate (rolling) + stale-hit rate separately
- Resolution latency: p50, p95, p99, max (per query type, per protocol)
- Active connections (UDP goroutines, TCP connections, WebSocket connections)
- Error rates by RCODE type
- Per-record-type query distribution (A, AAAA, MX, etc.)
- Upstream server response times (per nameserver IP) — labelled histograms
- Circuit breaker state per upstream (0=closed, 1=half-open, 2=open)
- Memory usage (cache size estimate in bytes)
- **Security metrics**: rate-limit drops/sec, RRL drops/sec, blocked queries/sec (blocklist), suspected poisoning attempts (case mismatch on 0x20 response)
- **Goroutine count** — exposed as gauge, alert if > 5000
- **Go runtime metrics**: GC pause time, heap alloc, goroutine count via `runtime/metrics`

**Prometheus labels** (all metrics must have these dimensions):
```
dns_query_total{type="A", protocol="udp", rcode="NOERROR", cached="false"}
dns_resolution_duration_seconds{type="A", step="auth_query"}
dns_cache_entries{kind="positive|negative|stale"}
dns_upstream_query_duration_seconds{server="198.41.0.4", zone="root"}
dns_circuit_breaker_state{server="198.41.0.4"}
dns_security_drops_total{reason="rate_limit|rrl|blocklist|bailiwick"}
```

**Mandatory structured log fields** on every log line:
```json
{
  "timestamp": "2025-02-20T10:00:00.000Z",
  "level": "info",
  "request_id": "uuid-v4",
  "query_id": "uuid-v4",
  "domain": "example.com",
  "type": "A",
  "rcode": "NOERROR",
  "duration_ms": 42,
  "cached": false,
  "stale": false,
  "client_ip": "192.168.1.1",
  "protocol": "udp",
  "steps": 3,
  "error": null
}
```
Use Go's `log/slog` package (stdlib, Go 1.21+). Never use `fmt.Println` or `log.Printf` for operational logging.

### Configuration (env vars + flags + validation)

```
# Network
DNS_PORT=53                    # DNS server port
HTTP_PORT=8080                 # HTTP API + frontend port
DOT_PORT=853                   # DNS over TLS port

# Cache
CACHE_MAX_ENTRIES=10000        # Max cache entries
CACHE_MIN_TTL=30               # Minimum TTL floor (seconds)
CACHE_MAX_TTL=86400            # Maximum TTL cap (seconds)
CACHE_STALE_WINDOW=300         # Stale-while-revalidate window (seconds)
CACHE_STALE_MAX_AGE=3600       # Maximum age to serve stale-on-error (seconds)
CACHE_PERSIST_PATH=./cache.json

# Logging
LOG_LEVEL=info                 # debug|info|warn|error
LOG_FORMAT=json                # json|text (use json in prod, text in dev)

# Security
BLOCKLIST_PATH=./blocklist.txt # Newline-separated domains to block
RATE_LIMIT_QPS=100             # Max queries/sec per source IP (token bucket)
RATE_LIMIT_BURST=200           # Burst allowance per source IP
RRL_ENABLED=true               # Response Rate Limiting (anti-amplification)
RRL_RESPONSES_PER_SEC=10       # Max identical responses/sec per client
QNAME_MINIMIZATION=true        # RFC 7816 QNAME minimization
CASE_RANDOMIZATION=true        # 0x20 encoding for anti-poisoning

# Resolution
UPSTREAM_TIMEOUT=5s            # Per-hop query timeout
MAX_CNAME_DEPTH=10             # CNAME chain limit
EDNS_ENABLED=true
MAX_UDP_SIZE=4096              # EDNS0 UDP payload size

# Circuit Breaker
CB_FAILURE_THRESHOLD=5         # failures before opening circuit
CB_SUCCESS_THRESHOLD=2         # successes in half-open before closing
CB_OPEN_TIMEOUT=30s            # how long to stay open before half-open

# TLS / DoT
TLS_ENABLED=false
TLS_CERT_PATH=./cert.pem
TLS_KEY_PATH=./key.pem
TLS_AUTO_GENERATE=true         # generate self-signed cert on first run if no cert found

# Recursion
ALLOW_RECURSIVE=true           # Accept RD=1 queries
MAX_RECURSION_DEPTH=10         # Max recursive resolution depth

# Observability
PPROF_ENABLED=false            # NEVER true in production without auth proxy in front
OTEL_ENABLED=false             # OpenTelemetry tracing
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
OTEL_SERVICE_NAME=dns-resolver
PROMETHEUS_ENABLED=true        # /metrics endpoint

# Operational
SHUTDOWN_DRAIN_TIMEOUT=30s     # max time to drain in-flight queries on SIGTERM
GOROUTINE_POOL_SIZE=1000       # UDP worker pool size
MAX_TCP_CONNECTIONS=500        # concurrent TCP connection limit
```

**Config validation on startup:** validate all numeric ranges, file paths exist, ports are not already in use. Exit with a clear error message listing all validation failures at once — never start partially configured.

---

## SECURITY — PRODUCTION DNS HARDENING

This section is **non-negotiable**. Every item must be implemented. DNS resolvers are high-value attack targets.

### DNS Cache Poisoning Prevention

**1. Query ID Randomization (RFC 5452)**
- Generate query IDs using `crypto/rand`, NOT `math/rand`
- Never reuse a query ID for concurrent in-flight queries
- Maintain a set of in-flight IDs; collision retry with new random ID

**2. Source Port Randomization (RFC 5452)**
- Use ephemeral random source ports (1024–65535) for each outbound query — do not use a fixed source port
- Open a new UDP socket per outbound query if necessary to guarantee port randomness
- This is the single most important Kaminsky attack mitigation

**3. 0x20 Mixed-Case Encoding (Kaminsky/Birthday attack mitigation)**
- Before sending a query to an upstream server, randomly capitalize letters in the QNAME (e.g., `GoOGlE.cOm`)
- Verify the response QNAME exactly matches the case you sent — drop responses that don't preserve it
- This adds ~15 bits of effective entropy to query matching beyond just query ID
- Implement in `internal/security/case_randomizer.go`

**4. Bailiwick Checking**
- For every NS referral and glue record received, verify the nameserver is authoritative for the zone being delegated
- Example: a response for `.com` queries cannot include glue for `.net` domains — reject and log
- For additional records (glue A/AAAA records), only accept them if the hostname is within the delegated zone
- Implement in `internal/resolver/bailiwick.go` — called on every referral before adding to the resolution path

**5. Response Validation**
- Always match response query ID AND source IP AND source port to the outbound query
- Drop responses that don't match all three — log as suspected poisoning attempt and increment `dns_security_poisoning_attempts_total` counter
- Enforce maximum name label count (127 labels max per RFC 1035) and max label length (63 bytes) — return FORMERR for violations

**6. QNAME Minimization (RFC 7816)**
- When querying root servers, send only `com.` not `google.com.`
- When querying TLD servers, send only `google.com.` not `subdomain.google.com.`
- This prevents upstream servers from learning the full query, improving privacy and reducing information leakage
- Implement in `internal/resolver/qname_minimization.go`
- Fall back to full QNAME if minimized query returns NXDOMAIN (some nameservers require full name)

### Anti-Amplification / DoS Protection

**Response Rate Limiting (RRL):**
- Track response rate per `(client_IP, QNAME, QTYPE, RCODE)` tuple using a sliding window
- If rate exceeds `RRL_RESPONSES_PER_SEC` (default: 10/s), switch to "slip" mode: send 1 in every N responses (N configurable, default 2) — don't drop entirely, allows legitimate clients to retry
- Implement token bucket per tuple in `internal/security/rrl.go` using `sync.Map` for concurrent access
- Garbage collect expired buckets every 60s

**Per-Source-IP Rate Limiting:**
- Token bucket per source IP: max `RATE_LIMIT_QPS` queries/second, burst of `RATE_LIMIT_BURST`
- When limit exceeded: drop UDP query silently (don't respond at all — prevents amplification)
- Log at `warn` level with source IP on first limit hit, then at `debug` for subsequent hits from same IP within 60s (don't flood your own logs)
- Implement in `internal/security/ratelimit.go`

**Max Response Size without EDNS:**
- If client sends no OPT record (no EDNS0), cap response at 512 bytes
- Truncate with TC bit if needed — client must retry over TCP
- Never send a 4096-byte response to a client that didn't negotiate EDNS

### Circuit Breaker (Upstream Resilience)

Implement a **per-upstream-server circuit breaker** in `internal/resolver/circuit_breaker.go`:

```go
type CircuitBreaker struct {
    state           State  // Closed, Open, HalfOpen
    failures        int
    successes       int
    lastFailureTime time.Time
    mu              sync.Mutex
}

type State int
const (
    StateClosed   State = iota  // Normal — let requests through
    StateOpen                    // Tripped — fast-fail all requests
    StateHalfOpen               // Testing — let one request through to probe
)
```

**State transitions:**
- `Closed → Open`: after `CB_FAILURE_THRESHOLD` consecutive failures (timeout or error response)
- `Open → HalfOpen`: after `CB_OPEN_TIMEOUT` has elapsed
- `HalfOpen → Closed`: after `CB_SUCCESS_THRESHOLD` consecutive successes
- `HalfOpen → Open`: on any failure

**Behavior when Open:**
- Return error immediately without making network call
- The resolver selects next available nameserver from the NS set
- If ALL nameservers for a zone are open: use stale cache or return SERVFAIL

**Expose circuit state** in `/api/v1/rootservers` and `/api/v1/metrics` responses.

---

## OBSERVABILITY — OPENTELEMETRY + STRUCTURED LOGGING

### OpenTelemetry Distributed Tracing

Implement OTel tracing in `internal/telemetry/`:

**Tracer setup** (`tracer.go`):
- Initialize `go.opentelemetry.io/otel` with OTLP gRPC exporter pointing to `OTEL_EXPORTER_OTLP_ENDPOINT`
- If `OTEL_ENABLED=false`, install a no-op tracer — zero runtime overhead when disabled
- Set resource attributes: `service.name=dns-resolver`, `service.version`, `host.name`

**Spans per resolution** — create a child span for each phase:
```
dns.resolve (root span — one per client query)
  ├── dns.cache.lookup                  {cache.hit: bool}
  ├── dns.query.root                    {server.address, dns.question.name, net.transport: "udp"}
  ├── dns.query.tld                     {server.address, dns.question.name}
  ├── dns.query.auth                    {server.address, dns.question.name}
  └── dns.cname.follow                  {dns.cname.target, dns.cname.depth}
```

Span attributes follow OpenTelemetry semantic conventions for DNS:
`dns.question.name`, `dns.question.type`, `dns.response.rcode`, `dns.response.answer_count`, `server.address`, `server.port`, `net.transport`, `error.type`.

**Trace ID in logs:** propagate the OTel trace ID into every `slog` log line as `trace_id` field, enabling log→trace correlation in any observability backend.

### Structured Logging (slog)

Use `log/slog` (Go 1.21+ stdlib) with JSON handler in production, text handler in dev (auto-detect via `LOG_FORMAT`).

`internal/logger/logger.go` must:
- Wrap `slog.Logger` with `FromCtx(ctx) *slog.Logger` — retrieves a request-scoped logger that automatically includes `request_id`, `query_id`, `trace_id` from context
- Define mandatory log field constants: `FieldRequestID = "request_id"`, `FieldQueryID = "query_id"`, `FieldDomain = "domain"`, etc. — prevents typos
- Rate-limit repetitive log lines: a repeated warning from the same source IP gets logged once per 60s at WARN, then silently counted — prevents log flooding during attack scenarios
- On `ERROR` level, always include `stack_trace` field using `runtime.Callers`

**Log levels:**
- `DEBUG` — every DNS packet bytes in/out as hex dump (only useful for development, very noisy)
- `INFO` — every resolved query with full mandatory field set
- `WARN` — rate limit events, circuit breaker state transitions, stale cache served, bailiwick violation detected
- `ERROR` — port bind failure, cache persistence failure, upstream permanently unreachable

---

## TECHNICAL REQUIREMENTS — FRONTEND (SvelteKit)

### Project Structure

```
frontend/
├── src/
│   ├── lib/
│   │   ├── components/
│   │   │   ├── ui/                     # shadcn-svelte base components
│   │   │   ├── QueryInput.svelte        # Domain + type selector + resolve button
│   │   │   ├── TraceTimeline.svelte     # Step-by-step resolution trace
│   │   │   ├── PacketInspector.svelte   # Raw wire format byte viewer + annotations
│   │   │   ├── CacheViewer.svelte       # Live cache table with TTL countdown
│   │   │   ├── MetricsDashboard.svelte  # Live charts and stat cards
│   │   │   ├── QueryHistory.svelte      # Searchable/filterable query log
│   │   │   ├── CompareView.svelte       # Side-by-side multi-server comparison
│   │   │   ├── RootServers.svelte       # Root server map + status
│   │   │   ├── HexViewer.svelte         # Hex + ASCII dump with field highlighting
│   │   │   ├── DNSRecord.svelte         # Single record renderer (type-aware)
│   │   │   ├── LiveQueryFeed.svelte     # Real-time query stream ticker
│   │   │   ├── LatencyChart.svelte      # Latency per hop visualization
│   │   │   ├── RecordTypeChart.svelte   # Query type distribution pie/donut
│   │   │   ├── ServerSettings.svelte    # Runtime config editor
│   │   │   ├── BlocklistEditor.svelte   # Domain blocklist manager
│   │   │   └── NavSidebar.svelte        # Navigation sidebar
│   │   ├── stores/
│   │   │   ├── websocket.ts             # WebSocket connection + reconnect logic
│   │   │   ├── queries.ts               # Query history store
│   │   │   ├── cache.ts                 # Cache entries store
│   │   │   ├── metrics.ts               # Live metrics store
│   │   │   └── settings.ts              # App settings store
│   │   ├── api/
│   │   │   └── client.ts                # Typed API client
│   │   └── utils/
│   │       ├── dns.ts                   # DNS type names, RCODE descriptions
│   │       ├── hex.ts                   # Binary → hex formatting utilities
│   │       ├── time.ts                  # TTL countdown, duration formatting
│   │       └── wire.ts                  # Wire format field offset calculator
│   ├── routes/
│   │   ├── +layout.svelte               # App shell, sidebar, theme
│   │   ├── +page.svelte                 # Main resolver / query page
│   │   ├── trace/[id]/+page.svelte      # Full trace detail page
│   │   ├── cache/+page.svelte           # Cache browser page
│   │   ├── metrics/+page.svelte         # Metrics dashboard page
│   │   ├── history/+page.svelte         # Query history page
│   │   ├── compare/+page.svelte         # Server comparison page
│   │   └── settings/+page.svelte        # Settings page
│   └── app.css                          # Global styles + CSS variables
├── static/
├── svelte.config.js
├── vite.config.ts
├── tailwind.config.ts
└── package.json
```

### UI/UX Design System

**Theme:** Dark-first developer tool aesthetic. Think VS Code + Linear + Warp terminal.

**Color Palette:**
```css
--bg-base: #0d0d0f        /* near black */
--bg-surface: #141416      /* card surfaces */
--bg-elevated: #1a1a1d     /* modals, popovers */
--border: #2a2a2e           /* subtle borders */
--text-primary: #f0f0f2    /* primary text */
--text-secondary: #8b8b96  /* muted text */
--text-accent: #7c6af7     /* purple accent — primary brand */
--success: #22c55e
--warning: #f59e0b
--error: #ef4444
--info: #3b82f6
/* Record type color coding: */
--type-a: #3b82f6
--type-aaaa: #8b5cf6
--type-cname: #f59e0b
--type-mx: #10b981
--type-ns: #6366f1
--type-txt: #ec4899
--type-soa: #f97316
--type-ptr: #14b8a6
```

**Typography:** JetBrains Mono for all DNS data, hex, IPs, record values. Inter/Geist for UI chrome.

**Layout:** Fixed left sidebar (240px) + main content area. No top navbar. Sidebar has icon + label navigation. Collapsible to icon-only mode.

### Page Specifications

#### Page 1: Main Resolver (`/`)

The hero page. Split layout:

**Top section — Query Bar:**
- Domain input (large, autofocus, monospace)
- Record type dropdown (A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, SRV, CAA, ANY)
- Options: `[x] Trace` `[x] Bypass Cache` `[x] DNSSEC`
- Resolve button with keyboard shortcut (Cmd+Enter)
- Recent queries quick-access dropdown

**Middle section — Answer Panel:**
When a result comes in, show:
- Answer records (type-color-coded cards)
- Authority records (collapsible)
- Additional records (collapsible)
- RCODE badge (NOERROR/NXDOMAIN/SERVFAIL etc.)
- Total resolution time, whether it was cached

**Bottom section — Trace Timeline** (when trace=true):
- Horizontal step-by-step timeline
- Each step: icon (cache/root/tld/auth), server name+IP, latency badge, expand to see full packet
- Steps appear progressively via WebSocket as they complete
- Clicking a step opens the Packet Inspector panel (slide-in from right)

#### Page 2: Trace Detail (`/trace/[id]`)

Full-page deep dive into a single resolution:

**Left panel — Resolution Path:**
- Vertical timeline with all steps
- Each step expandable with: query sent, response received, latency, server info
- CNAME chain visualization (graph-style arrows between nodes)
- TTL bar showing how long until cached value expires

**Right panel — Packet Inspector:**
- Tab between Request / Response for each hop
- HEX VIEWER: full raw bytes in hex dump format (16 bytes per row, offset + hex + ASCII)
- PARSED VIEW: color-coded field breakdown showing exactly which bytes map to which fields:
  - Header bytes highlighted in one color
  - Question section in another
  - Each RR section distinctly colored
  - Hover a field → highlight the bytes, show field name, description, value
- WIRE DIAGRAM: visual breakdown like Wireshark's packet detail pane

#### Page 3: Cache Browser (`/cache`)

**Stats bar:** Total entries, hit rate (24h), miss rate, eviction count, memory estimate

**Cache table:**
- Columns: Domain, Type, Value(s), TTL (live countdown ticking every second), Created, Hits, Source (recursive/authoritative/negative)
- Filter by: type, domain substring, TTL range
- Sort by any column
- Inline expand to see full record details
- Delete button per entry
- Flush all button (with confirmation)
- Export as JSON/CSV

**TTL Countdown:** Each row shows a live progress bar depleting as TTL counts down. Near-expiry entries turn amber then red.

#### Page 4: Metrics Dashboard (`/metrics`)

Grid of live-updating charts and stat cards:

**Stat Cards (top row):**
- Queries/second (live)
- Cache hit rate %
- p95 latency ms
- Active connections
- Total queries (session)
- Error rate %

**Charts:**
- Queries/sec over time (line chart, last 5 minutes, updates every second via WS)
- Latency percentiles (p50/p95/p99) over time (multi-line chart)
- Record type distribution (donut chart)
- RCODE distribution (bar chart — NOERROR vs NXDOMAIN vs SERVFAIL etc.)
- Cache hit/miss over time (stacked area chart)
- Top 10 most-queried domains (horizontal bar chart, live)
- Top nameservers by response time (table)

All charts use **layerchart** (Svelte-native charting) or fallback to **Chart.js with Svelte wrappers**.

#### Page 5: Query History (`/history`)

**Full query log:**
- Table: Timestamp, Domain, Type, RCODE, Latency, Cache (HIT/MISS), Source IP, Steps
- Live feed toggle: new queries appear at top in real-time
- Pause/resume live feed
- Search: full-text search across domain names
- Filter: by type, RCODE, latency range, date range, cache hit/miss
- Click any row → opens full trace detail
- Export: JSON, CSV, PCAP-like format

#### Page 6: Server Comparison (`/compare`)

Side-by-side comparison of resolution results from different servers:

- Input: domain + type
- Select servers: your resolver, 8.8.8.8 (Google), 1.1.1.1 (Cloudflare), 9.9.9.9 (Quad9), 208.67.222.222 (OpenDNS), custom
- Resolve all simultaneously
- Results table: per-server answers side by side
- Diff highlighting: highlight discrepancies in answers, TTL differences
- Latency comparison bar chart per server
- DNSSEC status comparison

#### Page 7: Settings (`/settings`)

**Server Configuration:**
- DNS port, HTTP port
- Cache max entries, min/max TTL sliders
- EDNS toggle
- Recursion toggle
- TLS/DoT toggle + cert upload

**Blocklist Manager:**
- Textarea for paste/edit
- Upload from file
- Preview: test a domain against current blocklist
- Stats: how many domains, last updated

**Root Servers:**
- Table of all 13 root servers (A through M)
- Last query time, last latency, status (green/red)
- Force refresh hints button

**Security Panel:**
- Live counters: rate-limit drops/sec, RRL drops/sec, suspected poisoning attempts (session)
- Blocked queries count + top 10 blocked domains
- Per-IP rate limit status: table of IPs currently being rate-limited with counts
- Toggle QNAME minimization, 0x20 case randomization, RRL at runtime
- Circuit breaker status board: all known upstream servers, their state (closed/open/half-open), failure counts, last error

**Export / Import:**
- Export full config as JSON
- Import config
- Export cache snapshot
- Import cache snapshot

### WebSocket Integration

Three WebSocket connections:

**`/ws/trace`** — Resolution trace events:
```typescript
interface TraceEvent {
  query_id: string
  step: number
  step_type: 'cache_hit' | 'root_query' | 'tld_query' | 'auth_query' | 'cname_follow' | 'answer'
  server: string
  server_name: string
  query: string
  query_type: string
  latency_ms: number
  success: boolean
  raw_request: string   // hex string
  raw_response: string  // hex string
  parsed_message: DNSMessage
  error?: string
}
```

**`/ws/metrics`** — Live metrics every 1 second:
```typescript
interface MetricsSnapshot {
  timestamp: string
  qps_1m: number
  qps_5m: number
  cache_hit_rate: number
  latency_p50: number
  latency_p95: number
  latency_p99: number
  active_connections: number
  total_queries: number
  rcode_distribution: Record<string, number>
  type_distribution: Record<string, number>
}
```

**`/ws/queries`** — Live query feed:
```typescript
interface QueryEvent {
  id: string
  timestamp: string
  domain: string
  type: string
  rcode: string
  latency_ms: number
  cached: boolean
  client_ip: string
  steps: number
}
```

**WebSocket store** handles: auto-reconnect (exponential backoff), connection state (connecting/connected/disconnected), message buffering during reconnect, typed event dispatch.

### SvelteKit Specifics

- SvelteKit in **SPA mode** (`adapter-static` or `adapter-node` — use adapter-node so Go can optionally serve it, or build static and serve from Go's embed)
- All API calls go through a typed `client.ts` using `fetch` with base URL from environment
- **Svelte stores** for all shared state (don't use heavy state management — Svelte stores are sufficient)
- **Reactive TTL countdown**: use `setInterval` in a custom store that ticks all TTLs down every second
- **`$effect` runes** (Svelte 5 if available, else `$: reactive` and `onMount`/`onDestroy` lifecycle)
- **Dark mode only** — no light mode toggle (this is a dev tool)
- **Keyboard shortcuts**:
  - `Cmd/Ctrl + K` → focus query input
  - `Cmd/Ctrl + Enter` → resolve
  - `G then H` → go to history
  - `G then C` → go to cache
  - `G then M` → go to metrics
  - `Escape` → close panels

### Error Handling & Loading States (per component — non-negotiable)

Every async operation in the UI must have three explicitly designed states — never leave the user staring at a blank div:

**Loading state:** Skeleton loaders (not spinners) that match the shape of real content. Implement a `<Skeleton>` component that pulses. Use it in every table row, every chart, every stat card while data loads.

**Error state:** Each component that fetches data must catch errors and render an inline error card with: the error message, a retry button, and the timestamp of the last failure. Never let an error in one component crash the whole page.

**Empty state:** When data exists but is empty (no history yet, empty cache), show a meaningful empty state illustration with a helpful call-to-action. Not just a blank table.

**Specific states to handle:**
- WebSocket disconnect → show a non-blocking banner "Live data paused — reconnecting..." with a pulsing indicator. All existing data stays visible. Auto-retry with exponential backoff (1s, 2s, 4s, max 30s).
- API call timeout (>5s) → show inline timeout message with retry
- Partial data (some servers in compare view failed) → show which servers failed inline, show results for successful ones
- Cache flush confirmation → modal with item count about to be deleted, not just a basic confirm()
- Resolution in progress → animate each trace step appearing sequentially as WS events arrive, with a progress indicator showing "step 3 of ~5"

### Accessibility (a11y)

Every interactive element must meet WCAG 2.1 AA:
- All buttons, inputs, and links have descriptive `aria-label` or visible label
- Focus management: when a slide-in panel opens, focus moves to it; when it closes, focus returns to the trigger
- All tables have `<caption>`, `scope` on `<th>` elements, proper `role` attributes
- Color is never the only indicator of meaning — RCODE badges use both color AND text/icon
- Keyboard-navigable: tab order is logical, no keyboard traps
- `prefers-reduced-motion`: all CSS transitions wrapped in `@media (prefers-reduced-motion: no-preference)` — users who opt out get instant state changes
- Screen reader announcements for live regions: when new queries arrive in the live feed, announce count with `aria-live="polite"`

### Security Headers (served by Go)

When Go serves the SvelteKit static files, it must set these response headers:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws://localhost:8080 wss://localhost:8080; img-src 'self' data:; font-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### Bundle Size Budget

- Use `vite-bundle-visualizer` (run as part of `make build`)
- Total JS bundle must be under **300KB gzipped**
- Individual route chunks must be under **100KB gzipped**
- If a chart library pushes over budget, lazy-load it: `const Chart = await import('chart.js')`
- Run `svelte-check` as part of CI — zero TypeScript errors allowed, zero unused CSS warnings

---

## TESTING — PRODUCTION TEST COVERAGE

### Unit Tests (required coverage: >80%)

**Protocol layer** (`internal/protocol/*_test.go`):
- Round-trip encode→decode for every supported record type (A, AAAA, CNAME, MX, NS, SOA, TXT, PTR, SRV, CAA)
- Name compression: test pointer following, multi-level pointer chains, pointer to pointer
- Malformed packet handling: truncated header, invalid pointer offset, circular pointer reference, label length overflow, zero-length name
- Big-endian integer encoding: verify byte order for all 16-bit and 32-bit fields
- Maximum label length (63), maximum name length (255), exceed both and verify FORMERR

**Cache layer** (`internal/cache/*_test.go`):
- TTL expiration: set entry, advance mock clock past TTL, verify expired
- LRU eviction: fill to max, add one more, verify oldest evicted
- Stale-while-revalidate: set entry, advance past TTL but within stale window, verify stale returned
- Concurrent access: 100 goroutines reading/writing simultaneously, no races (run with `-race`)
- Negative cache: NXDOMAIN entries, SOA TTL derivation
- Persistence: dump to disk, reload, verify entries intact

**Security layer** (`internal/security/*_test.go`):
- Rate limiter: exceed threshold, verify drop; wait for token refill, verify pass
- 0x20 case randomization: verify response case matches sent case; verify mismatch detection
- RRL: same client same qname exceeds rate, verify slip mode

**Resolver** (`internal/resolver/*_test.go`):
- Bailiwick violation: craft a response with out-of-zone glue, verify rejected
- CNAME chain: 3-hop chain, verify fully followed; 11-hop chain, verify SERVFAIL (exceeds depth limit)
- Circuit breaker: simulate failures, verify state transitions
- QNAME minimization: verify queries sent with minimized names at each level

### Fuzz Tests (Go native fuzzing — `go test -fuzz`)

**`internal/protocol/decoder_fuzz_test.go`:**
```go
func FuzzDecode(f *testing.F) {
    // Seed corpus: valid A record response, valid MX response, known malformed packets
    f.Add(validARecordBytes)
    f.Add(malformedPointerBytes)
    f.Fuzz(func(t *testing.T, data []byte) {
        // Must never panic, never infinite loop, never hang
        // All errors must be returned, not panicked
        msg, err := protocol.Decode(data)
        if err != nil {
            return // errors are fine
        }
        // If decode succeeds, re-encode must not panic
        _, _ = protocol.Encode(msg)
    })
}
```

This is critical — malicious UDP packets with crafted pointer loops, oversized names, and truncated records will arrive in production. The decoder must never panic regardless of input.

Run fuzz tests in CI for 30 seconds on every PR: `go test -fuzz=FuzzDecode -fuzztime=30s ./internal/protocol/`

### Benchmark Tests

**`internal/protocol/encoder_test.go`:**
```go
func BenchmarkDecodeARecord(b *testing.B) { ... }          // target: <1μs/op
func BenchmarkEncodeARecord(b *testing.B) { ... }          // target: <1μs/op
func BenchmarkDecodeWithCompression(b *testing.B) { ... }  // target: <2μs/op
```

**`internal/cache/cache_test.go`:**
```go
func BenchmarkCacheGet(b *testing.B) { ... }      // target: <200ns/op
func BenchmarkCacheSet(b *testing.B) { ... }      // target: <500ns/op
func BenchmarkCacheParallel(b *testing.B) { ... } // parallel read/write mix
```

**`internal/resolver/resolver_test.go`:**
```go
func BenchmarkResolveFromCache(b *testing.B) { ... }  // target: <1ms/op (cache hit)
```

Run benchmarks and fail CI if regression >20% vs baseline: `go test -bench=. -benchmem ./...`

### Integration Tests

**`test/integration/`:**
- Start the full server on a random port using `net.Listen("udp", "127.0.0.1:0")`
- Send real DNS wire format queries using `net.DialUDP`
- Verify responses for: A record, AAAA record, NXDOMAIN, blocked domain, truncated response → TCP retry
- Test cache: resolve domain, verify cache populated, resolve again, verify latency much lower
- Test DoH endpoint: send base64-encoded query, verify response
- Use `testcontainers-go` or a mock authoritative server for deterministic responses

---

## ADDITIONAL FEATURES

### DNS over HTTPS (DoH) Server
Implement a DoH endpoint:
```
POST /dns-query (Content-Type: application/dns-message)
GET  /dns-query?dns=<base64url-encoded-query>
```
Per RFC 8484. This lets browsers use your resolver as DoH.

### DNSSEC Validation (Basic)
- Parse RRSIG, DNSKEY, DS, NSEC, NSEC3 record types
- Validate signatures for A/AAAA/MX/NS records when DO bit set
- Report validation status: `secure`, `insecure`, `bogus`, `indeterminate`
- Show DNSSEC chain of trust in the trace UI

### Domain Blocklist
- Load blocklist from file on startup (one domain per line, supports `*.example.com` wildcards)
- Return NXDOMAIN for blocked domains
- Blocklist can be updated at runtime via API without restart
- Popular blocklist format support: hosts file format, domains-only format
- Blocklist stats: how many queries blocked (session + total)

### Reverse DNS Lookup
- PTR record resolution UI (enter IP, get hostname)
- Automatic reverse DNS enrichment in query history (show hostname for client IPs)

### Bulk Resolution
- Input: textarea of domains (one per line, up to 100)
- Resolve all in parallel with configurable concurrency
- Results table with per-domain status, answers, latency
- Export results

### Query Replay
- From history, replay any past query
- Compare new result vs cached/historical result
- Useful for testing "what changed" after a DNS update

---

## IMPLEMENTATION RULES FOR CLAUDE CODE

1. **No DNS libraries for core logic.** Do not use `miekg/dns` for parsing or resolution. Implement wire format manually. You may use it only in test files for verification.

2. **No placeholder/stub implementations.** Every endpoint, every handler, every protocol function must be fully implemented. No `// TODO` left behind. If a feature is listed, it is built.

3. **Wire format first.** Build and test the protocol layer before the resolver. Write unit tests for encoding/decoding round-trips for each record type. Run fuzz tests from day one.

4. **Error handling everywhere.** Use Go's idiomatic error wrapping (`fmt.Errorf("context: %w", err)`). Never swallow errors silently. Malformed packets must log a hex dump at DEBUG level and return FORMERR — never crash.

5. **Goroutine discipline.** Every goroutine must have a clear owner, a clear shutdown path, and a `sync.WaitGroup` tracking it. Use `context.Context` cancellation everywhere. Run `go test -race ./...` — zero races allowed.

6. **Crypto randomness only.** Use `crypto/rand` for all security-relevant randomness (query IDs, port selection, 0x20 case randomization). Never use `math/rand` for anything security-related.

7. **The frontend must be beautiful.** Not just functional — the packet inspector, the trace timeline, the hex viewer must be genuinely polished. Every component has a loading state, an error state, and an empty state. No blank screens.

8. **TypeScript strict mode.** `tsconfig.json` must have `"strict": true`. Zero `any` types. Zero `@ts-ignore`. Define proper interfaces for all DNS structures, all API responses, all WebSocket events.

9. **Real data, not mocks.** The frontend connects to the real backend. Do not seed fake data. Resolve real domains and show real wire-format results.

10. **Security is not optional.** Every item in the SECURITY section is required. Cache poisoning mitigations, RRL, bailiwick checking, and rate limiting must all be implemented before the server is considered functional.

11. **Observability from day one.** Every request gets a `request_id` UUID. Every log line has the mandatory structured fields. OTel spans wrap every resolution phase. Prometheus metrics are exported for every listed metric.

12. **`make` targets:**
    ```makefile
    make dev          # start Go backend + SvelteKit dev server concurrently (uses air for Go hot-reload)
    make build        # build SvelteKit → embed into Go binary (single artifact)
    make test         # go test ./... + svelte-check
    make test-race    # go test -race ./...
    make fuzz         # go test -fuzz=FuzzDecode -fuzztime=30s ./internal/protocol/
    make bench        # go test -bench=. -benchmem ./...
    make lint         # golangci-lint run + svelte-check --threshold error
    make docker       # docker build -t dns-resolver:latest .
    make k8s-apply    # kubectl apply -f deploy/kubernetes/
    make run          # ./bin/dns-resolver
    ```

---

## INFRASTRUCTURE — DOCKER & KUBERNETES

### Dockerfile (multi-stage, minimal image)

```dockerfile
# Stage 1: Build SvelteKit frontend
FROM node:22-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci --frozen-lockfile
COPY frontend/ ./
RUN npm run build

# Stage 2: Build Go binary
FROM golang:1.23-alpine AS go-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend-builder /app/frontend/build ./frontend/build
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.version=$(git describe --tags)" -o bin/dns-resolver ./cmd/server

# Stage 3: Minimal runtime image
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=go-builder /app/bin/dns-resolver /dns-resolver
EXPOSE 53/udp 53/tcp 853/tcp 8080/tcp
USER nonroot:nonroot
ENTRYPOINT ["/dns-resolver"]
```

Note: `distroless/static` — no shell, no package manager, minimal attack surface. Binary is statically compiled (CGO_ENABLED=0).

### docker-compose.yml (development + local prod)

```yaml
version: "3.9"
services:
  dns-resolver:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "853:853/tcp"
      - "8080:8080/tcp"
    environment:
      - LOG_LEVEL=info
      - LOG_FORMAT=json
      - CACHE_MAX_ENTRIES=10000
      - RATE_LIMIT_QPS=100
      - RRL_ENABLED=true
      - QNAME_MINIMIZATION=true
      - CASE_RANDOMIZATION=true
      - OTEL_ENABLED=false
      - PROMETHEUS_ENABLED=true
    volumes:
      - dns-cache:/data
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: "2.0"
          memory: 512M
        reservations:
          cpus: "0.5"
          memory: 128M
    healthcheck:
      test: ["CMD", "/dns-resolver", "--healthcheck"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 5s

  prometheus:
    image: prom/prometheus:v2.50.0
    ports:
      - "9090:9090"
    volumes:
      - ./deploy/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
    command: ["--config.file=/etc/prometheus/prometheus.yml"]

  grafana:
    image: grafana/grafana:10.3.0
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-data:/var/lib/grafana
      - ./deploy/prometheus/grafana-dashboard.json:/etc/grafana/provisioning/dashboards/dns.json:ro

volumes:
  dns-cache:
  grafana-data:
```

### Kubernetes Manifests (`deploy/kubernetes/`)

**`deployment.yaml`:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dns-resolver
  labels:
    app: dns-resolver
spec:
  replicas: 2
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 0       # zero-downtime rolling deploy
      maxSurge: 1
  selector:
    matchLabels:
      app: dns-resolver
  template:
    metadata:
      labels:
        app: dns-resolver
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/metrics"
    spec:
      terminationGracePeriodSeconds: 40   # > SHUTDOWN_DRAIN_TIMEOUT (30s)
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        readOnlyRootFilesystem: true
      containers:
        - name: dns-resolver
          image: dns-resolver:latest
          ports:
            - containerPort: 53
              protocol: UDP
              name: dns-udp
            - containerPort: 53
              protocol: TCP
              name: dns-tcp
            - containerPort: 8080
              protocol: TCP
              name: http
          envFrom:
            - configMapRef:
                name: dns-resolver-config
          resources:
            requests:
              cpu: "250m"
              memory: "128Mi"
            limits:
              cpu: "2000m"
              memory: "512Mi"
          livenessProbe:
            httpGet:
              path: /api/v1/health/live
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /api/v1/health/ready
              port: 8080
            initialDelaySeconds: 3
            periodSeconds: 5
            failureThreshold: 2
          volumeMounts:
            - name: cache-storage
              mountPath: /data
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: cache-storage
          emptyDir: {}     # replace with PVC in production
        - name: tmp
          emptyDir: {}
```

**`hpa.yaml`:**
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: dns-resolver-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: dns-resolver
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Pods
      pods:
        metric:
          name: dns_queries_per_second   # custom metric from Prometheus adapter
        target:
          type: AverageValue
          averageValue: "5000"           # scale up when any pod handles >5k QPS
```

**`pdb.yaml`:**
```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: dns-resolver-pdb
spec:
  minAvailable: 1   # always keep at least 1 pod running during node drain
  selector:
    matchLabels:
      app: dns-resolver
```

---

## CI/CD — GITHUB ACTIONS

### `.github/workflows/ci.yml` (runs on every PR and push to main)

```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:

jobs:
  test-backend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.23"
          cache: true
      - name: Download deps
        run: go mod download
      - name: Vet
        run: go vet ./...
      - name: Test with race detector
        run: go test -race -coverprofile=coverage.out ./...
      - name: Check coverage threshold (>80%)
        run: |
          COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
          if (( $(echo "$COVERAGE < 80" | bc -l) )); then
            echo "Coverage $COVERAGE% is below 80% threshold"
            exit 1
          fi
      - name: Fuzz protocol decoder (30s)
        run: go test -fuzz=FuzzDecode -fuzztime=30s ./internal/protocol/
      - name: Benchmark (detect regressions)
        run: go test -bench=. -benchmem ./... | tee bench.txt
      - name: Lint
        uses: golangci/golangci-lint-action@v6
        with:
          version: latest
          args: --timeout=5m

  test-frontend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "22"
          cache: "npm"
          cache-dependency-path: frontend/package-lock.json
      - run: cd frontend && npm ci --frozen-lockfile
      - run: cd frontend && npm run check          # svelte-check
      - run: cd frontend && npm run lint           # eslint
      - run: cd frontend && npm run build          # ensure it builds
      - name: Check bundle size
        run: |
          BUNDLE_SIZE=$(du -sk frontend/build | awk '{print $1}')
          echo "Bundle size: ${BUNDLE_SIZE}KB"
          if [ "$BUNDLE_SIZE" -gt 1024 ]; then
            echo "Bundle size ${BUNDLE_SIZE}KB exceeds 1MB budget"
            exit 1
          fi

  build-docker:
    needs: [test-backend, test-frontend]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - name: Build Docker image
        run: docker build -t dns-resolver:${{ github.sha }} .
      - name: Smoke test
        run: |
          docker run -d --name test -p 8080:8080 -p 5353:53/udp dns-resolver:${{ github.sha }}
          sleep 5
          curl -f http://localhost:8080/api/v1/health/ready
          dig @127.0.0.1 -p 5353 google.com A +time=5
          docker stop test
```

### `.github/workflows/release.yml` (runs on git tag push)

```yaml
name: Release
on:
  push:
    tags: ["v*"]

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Log in to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          push: true
          tags: |
            ghcr.io/${{ github.repository }}:${{ github.ref_name }}
            ghcr.io/${{ github.repository }}:latest
      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          generate_release_notes: true
```

---

---

## STARTING SEQUENCE FOR CLAUDE CODE

Build in this exact order to avoid circular dependencies:

1. `internal/protocol/types.go` — all constants and enums
2. `internal/protocol/decoder.go` — wire format reader (name compression, pointer following, cycle detection)
3. `internal/protocol/encoder.go` — wire format writer
4. `internal/protocol/*_test.go` — unit tests for every record type + fuzz test setup
5. `internal/logger/logger.go` — structured slog logger with context propagation
6. `internal/cache/` — TTL LRU cache + negative cache + stale-while-revalidate
7. `internal/security/` — rate limiter, RRL, port randomizer, query ID randomizer, case randomizer
8. `internal/resolver/hints.go` — root server hints (all 13, both IPv4 and IPv6)
9. `internal/resolver/bailiwick.go` — glue record validation
10. `internal/resolver/qname_minimization.go` — QNAME minimization
11. `internal/resolver/circuit_breaker.go` — per-upstream circuit breaker
12. `internal/resolver/iterative.go` — single-hop query with all security mitigations applied
13. `internal/resolver/recursive.go` — full resolution walk with CNAME chain following
14. `internal/resolver/pipeline.go` — event emission for real-time tracing
15. `internal/metrics/` — metrics collection + Prometheus exporter
16. `internal/telemetry/` — OpenTelemetry setup (no-op when disabled)
17. `internal/server/udp.go` — UDP listener with goroutine pool + graceful drain
18. `internal/server/tcp.go` — TCP listener with connection limits + graceful drain
19. `internal/server/dot.go` — DNS over TLS
20. `internal/api/health.go` — `/health/live` + `/health/ready` split endpoints
21. `internal/api/handlers.go` + `websocket.go` + `middleware.go` — full API
22. `config/config.go` — config with validation
23. `cmd/server/main.go` — wire everything together, signal handling, ordered startup/shutdown
24. SvelteKit frontend — all pages, all components, all stores, error/loading states
25. Security headers middleware for static file serving
26. Integration tests in `test/integration/`
27. `Dockerfile` (multi-stage, distroless)
28. `docker-compose.yml` with Prometheus + Grafana
29. Kubernetes manifests (`deploy/kubernetes/`)
30. GitHub Actions workflows (`.github/workflows/`)
31. `README.md` with ASCII architecture diagram, full API reference, quick start

---

## ACCEPTANCE CRITERIA

The project is done when **every single item** is checked:

**Functional DNS:**
- [ ] `dig @localhost google.com A` returns a real answer
- [ ] `dig @localhost google.com AAAA` returns IPv6 addresses
- [ ] `dig @localhost _smtp._tcp.gmail.com SRV` returns SRV records
- [ ] `dig @localhost nonexistent-xyz-123.com A` returns NXDOMAIN
- [ ] You can set your OS DNS to `127.0.0.1` and browse the web normally
- [ ] `dig @localhost ads.example.com A` (if in blocklist) returns NXDOMAIN immediately

**Frontend:**
- [ ] Opening `http://localhost:8080` shows the full dashboard
- [ ] Resolving a domain shows the full hop-by-hop trace in real time via WebSocket
- [ ] The packet inspector shows hex bytes with field annotations for each hop
- [ ] Cache page shows live TTL countdowns ticking every second
- [ ] Metrics page shows live charts updating every second via WebSocket
- [ ] Comparing `google.com` against 4 public resolvers works, diffs highlighted
- [ ] Bulk resolving 50 domains simultaneously shows per-domain results
- [ ] All pages have skeleton loaders, inline error states, and empty states
- [ ] WebSocket disconnect shows a reconnecting banner — does not blank the page
- [ ] All interactive elements are keyboard-navigable and have ARIA labels

**Security:**
- [ ] `go test -race ./...` — zero data race conditions
- [ ] `go test -fuzz=FuzzDecode -fuzztime=60s ./internal/protocol/` — no panics
- [ ] Sending 1000 UDP packets/sec from a single IP triggers rate limiting (verify via metrics)
- [ ] Crafting a response with out-of-zone glue is rejected and logged as bailiwick violation
- [ ] Queries to root servers use QNAME minimization (verify at DEBUG log level)
- [ ] Response query IDs are cryptographically random (no sequential IDs)

**Observability:**
- [ ] `curl http://localhost:8080/metrics` returns valid Prometheus exposition format
- [ ] Every log line in JSON format includes: `timestamp`, `level`, `request_id`, `domain`, `type`, `rcode`, `duration_ms`, `cached`
- [ ] `curl http://localhost:8080/api/v1/health/live` → 200 always
- [ ] `curl http://localhost:8080/api/v1/health/ready` → 503 before DNS port bound, 200 after

**DoH:**
- [ ] `curl 'http://localhost:8080/dns-query?dns=<base64url>'` returns valid binary DNS response
- [ ] Browser can be configured to use `http://localhost:8080/dns-query` as DoH provider

**Build & Ops:**
- [ ] `make build` produces a single Go binary under 30MB
- [ ] `make test` passes with >80% coverage
- [ ] `make lint` passes with zero warnings
- [ ] `docker-compose up` starts DNS resolver + Prometheus + Grafana
- [ ] `curl http://localhost:8080/api/v1/health/ready` returns 200 within 5s of `docker-compose up`
- [ ] Kubernetes manifests apply cleanly: `kubectl apply -f deploy/kubernetes/`
- [ ] `kubectl drain <node>` gracefully terminates the pod without dropping in-flight queries
- [ ] GitHub Actions CI passes on a clean PR (test, race, fuzz, lint, build)
- [ ] Zero `go vet` warnings, zero `svelte-check` errors, zero TypeScript errors in strict mode
- [ ] Docker image uses distroless base, runs as non-root user