# DNS Resolver

Production-focused DNS resolver implemented in Go with manual RFC1035 wire parsing, recursive resolution, cache, security hardening, DNS servers (UDP/TCP/DoT), DoH, REST API, WebSocket streams, metrics, and deployment assets.

## Architecture

```text
Clients (UDP/TCP/DoH/DoT)
        |
        v
+------------------------+
|  server.Handler        |
|  - decode/validate     |
|  - rate-limit + RRL    |
|  - truncation rules    |
+-----------+------------+
            |
            v
+------------------------+
|  resolver.Resolver     |
|  - cache lookup        |
|  - recursive walk      |
|  - cname follow        |
|  - bailiwick checks    |
|  - qname minimization  |
|  - circuit breakers    |
+-----------+------------+
            |
            v
+------------------------+
|  protocol (manual DNS) |
|  - encoder/decoder     |
|  - compression/pointers|
|  - record parsers      |
+------------------------+
```

## Quick Start

```bash
make build
make test
make run
```

Default ports:
- DNS UDP/TCP: `53`
- DoT: `853` (when `TLS_ENABLED=true`)
- HTTP/API/DoH: `8080`

Health checks:
- `GET /api/v1/health/live`
- `GET /api/v1/health/ready`

## Key Endpoints

- `GET /api/v1/resolve?q=example.com&type=A&trace=true`
- `GET /api/v1/cache`
- `GET /api/v1/cache/stats`
- `DELETE /api/v1/cache`
- `GET /api/v1/history`
- `GET /api/v1/history/:id`
- `GET /api/v1/metrics`
- `GET /metrics`
- `GET /api/v1/rootservers`
- `GET|POST /api/v1/settings`
- `GET /api/v1/security/stats`
- `GET|POST /dns-query` (DoH, RFC8484)
- `WS /ws/trace`
- `WS /ws/metrics`
- `WS /ws/queries`

## Test Commands

```bash
make test
make test-race
make fuzz
make bench
```

## Ops

```bash
docker-compose up --build
kubectl apply -f deploy/kubernetes/
```

## Notes

- Core DNS protocol logic is implemented from scratch in `internal/protocol` (no DNS library for encode/decode/resolve logic).
- Integration tests are included under `test/integration` and automatically skip when the environment blocks socket binding.
