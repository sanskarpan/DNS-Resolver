package config

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfigValues(t *testing.T) {
	cfg := Default()
	if cfg.DNSPort != 53 {
		t.Fatalf("DNSPort=%d want=53", cfg.DNSPort)
	}
	if cfg.HTTPPort != 8080 {
		t.Fatalf("HTTPPort=%d want=8080", cfg.HTTPPort)
	}
	if cfg.CacheMaxEntries != 10000 {
		t.Fatalf("CacheMaxEntries=%d want=10000", cfg.CacheMaxEntries)
	}
	if cfg.CacheMinTTL != 30*time.Second {
		t.Fatalf("CacheMinTTL=%v want=30s", cfg.CacheMinTTL)
	}
	if cfg.CacheMaxTTL != 86400*time.Second {
		t.Fatalf("CacheMaxTTL=%v want=86400s", cfg.CacheMaxTTL)
	}
	if cfg.RateLimitQPS != 100 {
		t.Fatalf("RateLimitQPS=%f want=100", cfg.RateLimitQPS)
	}
	if cfg.RateLimitBurst != 200 {
		t.Fatalf("RateLimitBurst=%d want=200", cfg.RateLimitBurst)
	}
	if !cfg.QNAMEMinimization {
		t.Fatalf("QNAMEMinimization=%v want=true", cfg.QNAMEMinimization)
	}
	if !cfg.CaseRandomization {
		t.Fatalf("CaseRandomization=%v want=true", cfg.CaseRandomization)
	}
	if cfg.MaxCNAMEDepth != 10 {
		t.Fatalf("MaxCNAMEDepth=%d want=10", cfg.MaxCNAMEDepth)
	}
	if cfg.MaxRecursionDepth != 10 {
		t.Fatalf("MaxRecursionDepth=%d want=10", cfg.MaxRecursionDepth)
	}
	if cfg.EDNSEnabled != true {
		t.Fatalf("EDNSEnabled=%v want=true", cfg.EDNSEnabled)
	}
	if cfg.MaxUDPSize != 4096 {
		t.Fatalf("MaxUDPSize=%d want=4096", cfg.MaxUDPSize)
	}
	if cfg.GoroutinePoolSize != 1000 {
		t.Fatalf("GoroutinePoolSize=%d want=1000", cfg.GoroutinePoolSize)
	}
	if cfg.MaxTCPConnections != 500 {
		t.Fatalf("MaxTCPConnections=%d want=500", cfg.MaxTCPConnections)
	}
	if cfg.ShutdownDrainTimeout != 30*time.Second {
		t.Fatalf("ShutdownDrainTimeout=%v want=30s", cfg.ShutdownDrainTimeout)
	}
}

func TestLoadFromEnvDefaults(t *testing.T) {
	os.Setenv("DNS_PORT", "5353")
	os.Setenv("DOT_PORT", "8531")
	os.Setenv("BLOCKLIST_PATH", "/dev/null")
	defer func() {
		os.Unsetenv("DNS_PORT")
		os.Unsetenv("DOT_PORT")
		os.Unsetenv("BLOCKLIST_PATH")
	}()
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if cfg.DNSPort != 5353 {
		t.Fatalf("DNSPort=%d want=5353", cfg.DNSPort)
	}
	if cfg.HTTPPort != 8080 {
		t.Fatalf("HTTPPort=%d want=8080", cfg.HTTPPort)
	}
	if cfg.LogLevel != "info" {
		t.Fatalf("LogLevel=%s want=info", cfg.LogLevel)
	}
	if cfg.LogFormat != "json" {
		t.Fatalf("LogFormat=%s want=json", cfg.LogFormat)
	}
}

func TestLoadFromEnvCustom(t *testing.T) {
	os.Setenv("DNS_PORT", "5353")
	os.Setenv("HTTP_PORT", "8888")
	os.Setenv("DOT_PORT", "8531")
	os.Setenv("LOG_LEVEL", "debug")
	os.Setenv("LOG_FORMAT", "text")
	os.Setenv("CACHE_MAX_ENTRIES", "5000")
	os.Setenv("CACHE_MIN_TTL", "60")
	os.Setenv("CACHE_MAX_TTL", "43200")
	os.Setenv("RATE_LIMIT_QPS", "50")
	os.Setenv("RATE_LIMIT_BURST", "100")
	os.Setenv("QNAME_MINIMIZATION", "false")
	os.Setenv("CASE_RANDOMIZATION", "false")
	os.Setenv("MAX_UDP_SIZE", "2048")
	os.Setenv("MAX_CNAME_DEPTH", "5")
	os.Setenv("MAX_RECURSION_DEPTH", "8")
	os.Setenv("RRL_ENABLED", "false")
	os.Setenv("RRL_RESPONSES_PER_SEC", "5")
	os.Setenv("RRL_SLIP", "3")
	os.Setenv("PPROF_ENABLED", "true")
	os.Setenv("PROMETHEUS_ENABLED", "false")
	os.Setenv("BLOCKLIST_PATH", "/dev/null")
	defer func() {
		os.Unsetenv("DNS_PORT")
		os.Unsetenv("HTTP_PORT")
		os.Unsetenv("DOT_PORT")
		os.Unsetenv("LOG_LEVEL")
		os.Unsetenv("LOG_FORMAT")
		os.Unsetenv("CACHE_MAX_ENTRIES")
		os.Unsetenv("CACHE_MIN_TTL")
		os.Unsetenv("CACHE_MAX_TTL")
		os.Unsetenv("RATE_LIMIT_QPS")
		os.Unsetenv("RATE_LIMIT_BURST")
		os.Unsetenv("QNAME_MINIMIZATION")
		os.Unsetenv("CASE_RANDOMIZATION")
		os.Unsetenv("MAX_UDP_SIZE")
		os.Unsetenv("MAX_CNAME_DEPTH")
		os.Unsetenv("MAX_RECURSION_DEPTH")
		os.Unsetenv("RRL_ENABLED")
		os.Unsetenv("RRL_RESPONSES_PER_SEC")
		os.Unsetenv("RRL_SLIP")
		os.Unsetenv("PPROF_ENABLED")
		os.Unsetenv("PROMETHEUS_ENABLED")
		os.Unsetenv("BLOCKLIST_PATH")
	}()

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if cfg.DNSPort != 5353 {
		t.Fatalf("DNSPort=%d want=5353", cfg.DNSPort)
	}
	if cfg.HTTPPort != 8888 {
		t.Fatalf("HTTPPort=%d want=8888", cfg.HTTPPort)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("LogLevel=%s want=debug", cfg.LogLevel)
	}
	if cfg.LogFormat != "text" {
		t.Fatalf("LogFormat=%s want=text", cfg.LogFormat)
	}
	if cfg.CacheMaxEntries != 5000 {
		t.Fatalf("CacheMaxEntries=%d want=5000", cfg.CacheMaxEntries)
	}
	if cfg.CacheMinTTL != 60*time.Second {
		t.Fatalf("CacheMinTTL=%v want=60s", cfg.CacheMinTTL)
	}
	if cfg.CacheMaxTTL != 43200*time.Second {
		t.Fatalf("CacheMaxTTL=%v want=43200s", cfg.CacheMaxTTL)
	}
	if cfg.RateLimitQPS != 50 {
		t.Fatalf("RateLimitQPS=%f want=50", cfg.RateLimitQPS)
	}
	if cfg.RateLimitBurst != 100 {
		t.Fatalf("RateLimitBurst=%d want=100", cfg.RateLimitBurst)
	}
	if cfg.QNAMEMinimization {
		t.Fatalf("QNAMEMinimization=%v want=false", cfg.QNAMEMinimization)
	}
	if cfg.CaseRandomization {
		t.Fatalf("CaseRandomization=%v want=false", cfg.CaseRandomization)
	}
	if cfg.MaxUDPSize != 2048 {
		t.Fatalf("MaxUDPSize=%d want=2048", cfg.MaxUDPSize)
	}
	if cfg.MaxCNAMEDepth != 5 {
		t.Fatalf("MaxCNAMEDepth=%d want=5", cfg.MaxCNAMEDepth)
	}
	if cfg.MaxRecursionDepth != 8 {
		t.Fatalf("MaxRecursionDepth=%d want=8", cfg.MaxRecursionDepth)
	}
	if cfg.RRLEnabled {
		t.Fatalf("RRLEnabled=%v want=false", cfg.RRLEnabled)
	}
	if cfg.RRLResponsesPerSec != 5 {
		t.Fatalf("RRLResponsesPerSec=%d want=5", cfg.RRLResponsesPerSec)
	}
	if cfg.RRLSlip != 3 {
		t.Fatalf("RRLSlip=%d want=3", cfg.RRLSlip)
	}
	if !cfg.PPROFEnabled {
		t.Fatalf("PPROFEnabled=%v want=true", cfg.PPROFEnabled)
	}
	if cfg.PrometheusEnabled {
		t.Fatalf("PrometheusEnabled=%v want=false", cfg.PrometheusEnabled)
	}
}

func TestValidatePortOutOfRange(t *testing.T) {
	cfg := Default()
	cfg.DNSPort = 0
	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for DNSPort=0")
	}
	cfg = Default()
	cfg.HTTPPort = 70000
	err = cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for HTTPPort=70000")
	}
}

func TestValidateCacheEntriesInvalid(t *testing.T) {
	cfg := Default()
	cfg.CacheMaxEntries = 0
	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for CacheMaxEntries=0")
	}
}

func TestValidateDoesNotRequireExistingBlocklist(t *testing.T) {
	cfg := Default()
	cfg.BlocklistPath = filepath.Join(t.TempDir(), "missing-blocklist.txt")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected missing blocklist path to be non-fatal, got %v", err)
	}
}

func TestValidateDoesNotProbePortAvailability(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	cfg := Default()
	cfg.DNSPort = ln.Addr().(*net.TCPAddr).Port
	cfg.BlocklistPath = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected occupied port to be non-fatal during config validation, got %v", err)
	}
}

func TestValidateCacheTTLInvalid(t *testing.T) {
	cfg := Default()
	cfg.CacheMinTTL = 100 * time.Second
	cfg.CacheMaxTTL = 50 * time.Second
	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for CacheMaxTTL < CacheMinTTL")
	}
}

func TestValidateRateLimitInvalid(t *testing.T) {
	cfg := Default()
	cfg.RateLimitQPS = 0
	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for RateLimitQPS=0")
	}
	cfg = Default()
	cfg.RateLimitBurst = 0
	err = cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for RateLimitBurst=0")
	}
}

func TestValidateRRLInvalid(t *testing.T) {
	cfg := Default()
	cfg.RRLResponsesPerSec = 0
	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for RRLResponsesPerSec=0")
	}
	cfg = Default()
	cfg.RRLSlip = 0
	err = cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for RRLSlip=0")
	}
}

func TestValidateUpstreamTimeoutInvalid(t *testing.T) {
	cfg := Default()
	cfg.UpstreamTimeout = 0
	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for UpstreamTimeout=0")
	}
}

func TestValidateMaxUDPSizeInvalid(t *testing.T) {
	cfg := Default()
	cfg.MaxUDPSize = 256
	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for MaxUDPSize=256")
	}
	cfg = Default()
	cfg.MaxUDPSize = 8192
	err = cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for MaxUDPSize=8192")
	}
}

func TestValidateCircuitBreakerInvalid(t *testing.T) {
	cfg := Default()
	cfg.CBFailureThreshold = 0
	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for CBFailureThreshold=0")
	}
	cfg = Default()
	cfg.CBOpenTimeout = 0
	err = cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for CBOpenTimeout=0")
	}
}

func TestValidatePoolSizeInvalid(t *testing.T) {
	cfg := Default()
	cfg.GoroutinePoolSize = 0
	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for GoroutinePoolSize=0")
	}
	cfg = Default()
	cfg.MaxTCPConnections = 0
	err = cfg.Validate()
	if err == nil {
		t.Fatalf("expected validation error for MaxTCPConnections=0")
	}
}

func TestDurationEnvParsing(t *testing.T) {
	os.Setenv("UPSTREAM_TIMEOUT", "10s")
	os.Setenv("DNS_PORT", "5353")
	os.Setenv("DOT_PORT", "8531")
	os.Setenv("BLOCKLIST_PATH", "/dev/null")
	defer func() {
		os.Unsetenv("UPSTREAM_TIMEOUT")
		os.Unsetenv("DNS_PORT")
		os.Unsetenv("DOT_PORT")
		os.Unsetenv("BLOCKLIST_PATH")
	}()
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if cfg.UpstreamTimeout != 10*time.Second {
		t.Fatalf("UpstreamTimeout=%v want=10s", cfg.UpstreamTimeout)
	}
}

func TestDurationEnvParsingSecondsOnly(t *testing.T) {
	os.Setenv("CACHE_MIN_TTL", "45")
	os.Setenv("DNS_PORT", "5353")
	os.Setenv("DOT_PORT", "8531")
	os.Setenv("BLOCKLIST_PATH", "/dev/null")
	defer func() {
		os.Unsetenv("CACHE_MIN_TTL")
		os.Unsetenv("DNS_PORT")
		os.Unsetenv("DOT_PORT")
		os.Unsetenv("BLOCKLIST_PATH")
	}()
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if cfg.CacheMinTTL != 45*time.Second {
		t.Fatalf("CacheMinTTL=%v want=45s", cfg.CacheMinTTL)
	}
}

func TestBoolEnvParsing(t *testing.T) {
	os.Setenv("EDNS_ENABLED", "false")
	os.Setenv("DNS_PORT", "5353")
	os.Setenv("DOT_PORT", "8531")
	os.Setenv("BLOCKLIST_PATH", "/dev/null")
	defer func() {
		os.Unsetenv("EDNS_ENABLED")
		os.Unsetenv("DNS_PORT")
		os.Unsetenv("DOT_PORT")
		os.Unsetenv("BLOCKLIST_PATH")
	}()
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if cfg.EDNSEnabled {
		t.Fatalf("EDNSEnabled=%v want=false", cfg.EDNSEnabled)
	}
}
