package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"dnsresolver/internal/logger"
)

func (a *API) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		setCORSHeaders(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if a.requiresControlPlaneAuth(r.URL.Path) && !a.authorizeControlPlaneRequest(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		reqID := newRequestID()
		ctx := logger.WithRequestID(r.Context(), reqID)
		if traceID := extractTraceID(r.Header.Get("traceparent")); traceID != "" {
			ctx = logger.WithTraceID(ctx, traceID)
		}
		start := time.Now()
		next.ServeHTTP(w, r.WithContext(ctx))
		if a.deps.Logger != nil {
			logger.FromCtx(ctx, a.deps.Logger).Info("http request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("remote_addr", r.RemoteAddr),
				slog.Int64("duration_ms", time.Since(start).Milliseconds()),
			)
		}
	})
}

func (a *API) requiresControlPlaneAuth(path string) bool {
	token := strings.TrimSpace(a.deps.ControlPlaneToken)
	if token == "" {
		return false
	}
	switch path {
	case "/api/v1/health/live", "/api/v1/health/ready":
		return false
	}
	if strings.HasPrefix(path, "/api/") {
		return true
	}
	if strings.HasPrefix(path, "/ws/") {
		return true
	}
	if path == "/metrics" || path == "/dns-query" {
		return true
	}
	return strings.HasPrefix(path, "/debug/")
}

func (a *API) authorizeControlPlaneRequest(r *http.Request) bool {
	expected := strings.TrimSpace(a.deps.ControlPlaneToken)
	if expected == "" {
		return true
	}
	candidates := []string{
		strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")),
		strings.TrimSpace(r.Header.Get("X-API-Token")),
		strings.TrimSpace(r.URL.Query().Get("token")),
	}
	for _, candidate := range candidates {
		if secureTokenMatch(expected, candidate) {
			return true
		}
	}
	return false
}

func secureTokenMatch(expected, actual string) bool {
	expected = strings.TrimSpace(expected)
	actual = strings.TrimSpace(actual)
	if expected == "" || actual == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}

func extractTraceID(traceparent string) string {
	traceparent = strings.TrimSpace(traceparent)
	if traceparent == "" {
		return ""
	}
	parts := strings.Split(traceparent, "-")
	if len(parts) != 4 {
		return ""
	}
	traceID := strings.ToLower(strings.TrimSpace(parts[1]))
	if len(traceID) != 32 {
		return ""
	}
	for _, r := range traceID {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return ""
		}
	}
	if traceID == "00000000000000000000000000000000" {
		return ""
	}
	return traceID
}

func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Traceparent, Tracestate")
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; img-src 'self' data:; font-src 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strings.ReplaceAll(time.Now().UTC().Format(time.RFC3339Nano), ":", "")
	}
	return hex.EncodeToString(b[:])
}
