package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DNSPort  int
	HTTPPort int
	DoTPort  int

	CacheMaxEntries  int
	CacheMinTTL      time.Duration
	CacheMaxTTL      time.Duration
	CacheStaleWindow time.Duration
	CacheStaleMaxAge time.Duration
	CachePersistPath string

	LogLevel  string
	LogFormat string

	BlocklistPath      string
	RateLimitQPS       float64
	RateLimitBurst     int
	RRLEnabled         bool
	RRLResponsesPerSec int
	RRLSlip            int
	QNAMEMinimization  bool
	CaseRandomization  bool

	UpstreamTimeout time.Duration
	MaxCNAMEDepth   int
	EDNSEnabled     bool
	MaxUDPSize      int

	CBFailureThreshold int
	CBSuccessThreshold int
	CBOpenTimeout      time.Duration

	TLSEnabled      bool
	TLSCertPath     string
	TLSKeyPath      string
	TLSAutoGenerate bool

	AllowRecursive    bool
	MaxRecursionDepth int

	PPROFEnabled      bool
	OTELEnabled       bool
	OTLPEndpoint      string
	OTELServiceName   string
	PrometheusEnabled bool

	ShutdownDrainTimeout time.Duration
	GoroutinePoolSize    int
	MaxTCPConnections    int
}

func Default() Config {
	return Config{
		DNSPort:              53,
		HTTPPort:             8080,
		DoTPort:              853,
		CacheMaxEntries:      10000,
		CacheMinTTL:          30 * time.Second,
		CacheMaxTTL:          86400 * time.Second,
		CacheStaleWindow:     300 * time.Second,
		CacheStaleMaxAge:     3600 * time.Second,
		CachePersistPath:     "./cache.json",
		LogLevel:             "info",
		LogFormat:            "json",
		BlocklistPath:        "./blocklist.txt",
		RateLimitQPS:         100,
		RateLimitBurst:       200,
		RRLEnabled:           true,
		RRLResponsesPerSec:   10,
		RRLSlip:              2,
		QNAMEMinimization:    true,
		CaseRandomization:    true,
		UpstreamTimeout:      5 * time.Second,
		MaxCNAMEDepth:        10,
		EDNSEnabled:          true,
		MaxUDPSize:           4096,
		CBFailureThreshold:   5,
		CBSuccessThreshold:   2,
		CBOpenTimeout:        30 * time.Second,
		TLSEnabled:           false,
		TLSCertPath:          "./cert.pem",
		TLSKeyPath:           "./key.pem",
		TLSAutoGenerate:      true,
		AllowRecursive:       true,
		MaxRecursionDepth:    10,
		PPROFEnabled:         false,
		OTELEnabled:          false,
		OTLPEndpoint:         "http://localhost:4317",
		OTELServiceName:      "dns-resolver",
		PrometheusEnabled:    true,
		ShutdownDrainTimeout: 30 * time.Second,
		GoroutinePoolSize:    1000,
		MaxTCPConnections:    500,
	}
}

func LoadFromEnv() (Config, error) {
	cfg := Default()

	cfg.DNSPort = intEnv("DNS_PORT", cfg.DNSPort)
	cfg.HTTPPort = intEnv("HTTP_PORT", cfg.HTTPPort)
	cfg.DoTPort = intEnv("DOT_PORT", cfg.DoTPort)

	cfg.CacheMaxEntries = intEnv("CACHE_MAX_ENTRIES", cfg.CacheMaxEntries)
	cfg.CacheMinTTL = durationOrSecondsEnv("CACHE_MIN_TTL", cfg.CacheMinTTL)
	cfg.CacheMaxTTL = durationOrSecondsEnv("CACHE_MAX_TTL", cfg.CacheMaxTTL)
	cfg.CacheStaleWindow = durationOrSecondsEnv("CACHE_STALE_WINDOW", cfg.CacheStaleWindow)
	cfg.CacheStaleMaxAge = durationOrSecondsEnv("CACHE_STALE_MAX_AGE", cfg.CacheStaleMaxAge)
	cfg.CachePersistPath = stringEnv("CACHE_PERSIST_PATH", cfg.CachePersistPath)

	cfg.LogLevel = stringEnv("LOG_LEVEL", cfg.LogLevel)
	cfg.LogFormat = stringEnv("LOG_FORMAT", cfg.LogFormat)

	cfg.BlocklistPath = stringEnv("BLOCKLIST_PATH", cfg.BlocklistPath)
	cfg.RateLimitQPS = floatEnv("RATE_LIMIT_QPS", cfg.RateLimitQPS)
	cfg.RateLimitBurst = intEnv("RATE_LIMIT_BURST", cfg.RateLimitBurst)
	cfg.RRLEnabled = boolEnv("RRL_ENABLED", cfg.RRLEnabled)
	cfg.RRLResponsesPerSec = intEnv("RRL_RESPONSES_PER_SEC", cfg.RRLResponsesPerSec)
	cfg.RRLSlip = intEnv("RRL_SLIP", cfg.RRLSlip)
	cfg.QNAMEMinimization = boolEnv("QNAME_MINIMIZATION", cfg.QNAMEMinimization)
	cfg.CaseRandomization = boolEnv("CASE_RANDOMIZATION", cfg.CaseRandomization)

	cfg.UpstreamTimeout = durationEnv("UPSTREAM_TIMEOUT", cfg.UpstreamTimeout)
	cfg.MaxCNAMEDepth = intEnv("MAX_CNAME_DEPTH", cfg.MaxCNAMEDepth)
	cfg.EDNSEnabled = boolEnv("EDNS_ENABLED", cfg.EDNSEnabled)
	cfg.MaxUDPSize = intEnv("MAX_UDP_SIZE", cfg.MaxUDPSize)

	cfg.CBFailureThreshold = intEnv("CB_FAILURE_THRESHOLD", cfg.CBFailureThreshold)
	cfg.CBSuccessThreshold = intEnv("CB_SUCCESS_THRESHOLD", cfg.CBSuccessThreshold)
	cfg.CBOpenTimeout = durationEnv("CB_OPEN_TIMEOUT", cfg.CBOpenTimeout)

	cfg.TLSEnabled = boolEnv("TLS_ENABLED", cfg.TLSEnabled)
	cfg.TLSCertPath = stringEnv("TLS_CERT_PATH", cfg.TLSCertPath)
	cfg.TLSKeyPath = stringEnv("TLS_KEY_PATH", cfg.TLSKeyPath)
	cfg.TLSAutoGenerate = boolEnv("TLS_AUTO_GENERATE", cfg.TLSAutoGenerate)

	cfg.AllowRecursive = boolEnv("ALLOW_RECURSIVE", cfg.AllowRecursive)
	cfg.MaxRecursionDepth = intEnv("MAX_RECURSION_DEPTH", cfg.MaxRecursionDepth)

	cfg.PPROFEnabled = boolEnv("PPROF_ENABLED", cfg.PPROFEnabled)
	cfg.OTELEnabled = boolEnv("OTEL_ENABLED", cfg.OTELEnabled)
	cfg.OTLPEndpoint = stringEnv("OTEL_EXPORTER_OTLP_ENDPOINT", cfg.OTLPEndpoint)
	cfg.OTELServiceName = stringEnv("OTEL_SERVICE_NAME", cfg.OTELServiceName)
	cfg.PrometheusEnabled = boolEnv("PROMETHEUS_ENABLED", cfg.PrometheusEnabled)

	cfg.ShutdownDrainTimeout = durationEnv("SHUTDOWN_DRAIN_TIMEOUT", cfg.ShutdownDrainTimeout)
	cfg.GoroutinePoolSize = intEnv("GOROUTINE_POOL_SIZE", cfg.GoroutinePoolSize)
	cfg.MaxTCPConnections = intEnv("MAX_TCP_CONNECTIONS", cfg.MaxTCPConnections)

	return cfg, cfg.Validate()
}

func (c Config) Validate() error {
	var errs []error

	validatePort := func(name string, value int) {
		if value < 1 || value > 65535 {
			errs = append(errs, fmt.Errorf("%s must be between 1 and 65535", name))
		}
	}
	validatePort("DNS_PORT", c.DNSPort)
	validatePort("HTTP_PORT", c.HTTPPort)
	validatePort("DOT_PORT", c.DoTPort)

	if c.CacheMaxEntries < 1 {
		errs = append(errs, errors.New("CACHE_MAX_ENTRIES must be > 0"))
	}
	if c.CacheMinTTL < 0 || c.CacheMaxTTL < c.CacheMinTTL {
		errs = append(errs, errors.New("CACHE_MIN_TTL/CACHE_MAX_TTL invalid"))
	}
	if c.CacheStaleWindow < 0 || c.CacheStaleMaxAge < c.CacheStaleWindow {
		errs = append(errs, errors.New("CACHE_STALE_WINDOW/CACHE_STALE_MAX_AGE invalid"))
	}

	if c.RateLimitQPS <= 0 || c.RateLimitBurst <= 0 {
		errs = append(errs, errors.New("RATE_LIMIT_QPS and RATE_LIMIT_BURST must be > 0"))
	}
	if c.RRLResponsesPerSec <= 0 || c.RRLSlip <= 0 {
		errs = append(errs, errors.New("RRL_RESPONSES_PER_SEC and RRL_SLIP must be > 0"))
	}

	if c.UpstreamTimeout <= 0 {
		errs = append(errs, errors.New("UPSTREAM_TIMEOUT must be > 0"))
	}
	if c.MaxCNAMEDepth < 1 || c.MaxRecursionDepth < 1 {
		errs = append(errs, errors.New("MAX_CNAME_DEPTH and MAX_RECURSION_DEPTH must be >= 1"))
	}
	if c.MaxUDPSize < 512 || c.MaxUDPSize > 4096 {
		errs = append(errs, errors.New("MAX_UDP_SIZE must be in [512,4096]"))
	}

	if c.CBFailureThreshold < 1 || c.CBSuccessThreshold < 1 || c.CBOpenTimeout <= 0 {
		errs = append(errs, errors.New("circuit breaker values invalid"))
	}
	if c.ShutdownDrainTimeout <= 0 {
		errs = append(errs, errors.New("SHUTDOWN_DRAIN_TIMEOUT must be > 0"))
	}
	if c.GoroutinePoolSize < 1 || c.MaxTCPConnections < 1 {
		errs = append(errs, errors.New("GOROUTINE_POOL_SIZE and MAX_TCP_CONNECTIONS must be > 0"))
	}

	if c.TLSEnabled && !c.TLSAutoGenerate {
		if _, err := os.Stat(c.TLSCertPath); err != nil {
			errs = append(errs, fmt.Errorf("TLS cert path: %w", err))
		}
		if _, err := os.Stat(c.TLSKeyPath); err != nil {
			errs = append(errs, fmt.Errorf("TLS key path: %w", err))
		}
	}

	if dir := filepath.Dir(c.CachePersistPath); dir != "" && dir != "." {
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			errs = append(errs, fmt.Errorf("cache persist directory not accessible: %s", dir))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	parts := make([]string, 0, len(errs))
	for _, err := range errs {
		parts = append(parts, err.Error())
	}
	return fmt.Errorf("config validation failed: %s", strings.Join(parts, "; "))
}

func stringEnv(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func boolEnv(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return parsed
}

func intEnv(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return parsed
}

func floatEnv(key string, fallback float64) float64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return parsed
}

func durationOrSecondsEnv(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	seconds, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}
