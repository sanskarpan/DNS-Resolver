package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"dnsresolver/config"
	"dnsresolver/internal/api"
	"dnsresolver/internal/cache"
	"dnsresolver/internal/logger"
	"dnsresolver/internal/metrics"
	"dnsresolver/internal/resolver"
	"dnsresolver/internal/security"
	"dnsresolver/internal/server"
	"dnsresolver/internal/telemetry"
)

var version = "dev"

func main() {
	healthcheck := flag.Bool("healthcheck", false, "run healthcheck and exit")
	flag.Parse()

	if *healthcheck {
		os.Exit(runHealthcheck())
	}

	cfg, err := config.LoadFromEnv()
	if err != nil {
		logger.LogError(nil, "configuration error", err)
		os.Exit(1)
	}

	log := logger.New(cfg.LogLevel, cfg.LogFormat)
	log.Info("starting dns-resolver", slog.String("version", version))

	rootCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	shutdownTrace, err := telemetry.Setup(rootCtx, telemetry.Config{Enabled: cfg.OTELEnabled, Endpoint: cfg.OTLPEndpoint, ServiceName: cfg.OTELServiceName})
	if err != nil {
		logger.LogError(log, "telemetry setup failed", err)
		os.Exit(1)
	}
	defer func() {
		_ = shutdownTrace(context.Background())
	}()

	cacheStore := cache.New(cache.Options{
		MaxEntries:  cfg.CacheMaxEntries,
		MinTTL:      cfg.CacheMinTTL,
		MaxTTL:      cfg.CacheMaxTTL,
		StaleWindow: cfg.CacheStaleWindow,
		StaleMaxAge: cfg.CacheStaleMaxAge,
		PersistPath: cfg.CachePersistPath,
	})
	var cacheLoaded atomic.Bool
	if err := cacheStore.Load(); err != nil {
		log.Warn("cache load failed", slog.Any("error", err))
		cacheLoaded.Store(false)
	} else {
		cacheLoaded.Store(true)
	}

	resolverCfg := resolver.Config{
		UpstreamTimeout:    cfg.UpstreamTimeout,
		Retries:            3,
		MaxCNAMEDepth:      cfg.MaxCNAMEDepth,
		MaxRecursionDepth:  cfg.MaxRecursionDepth,
		QNAMEMinimization:  cfg.QNAMEMinimization,
		CaseRandomization:  cfg.CaseRandomization,
		EDNSEnabled:        cfg.EDNSEnabled,
		MaxUDPSize:         cfg.MaxUDPSize,
		CBFailureThreshold: cfg.CBFailureThreshold,
		CBSuccessThreshold: cfg.CBSuccessThreshold,
		CBOpenTimeout:      cfg.CBOpenTimeout,
	}
	res := resolver.New(resolverCfg, cacheStore)
	if err := res.LoadBlocklist(cfg.BlocklistPath); err != nil {
		log.Warn("blocklist load failed", slog.Any("error", err), slog.String("path", cfg.BlocklistPath))
	}
	metricStore := metrics.New()
	var prom *metrics.PromMetrics
	if cfg.PrometheusEnabled {
		prom = metrics.NewPrometheus()
	}
	limiter := security.NewRateLimiter(cfg.RateLimitQPS, cfg.RateLimitBurst)
	rrl := security.NewRRL(cfg.RRLResponsesPerSec, cfg.RRLSlip)
	dnsHandler := server.NewHandler(server.Options{
		Resolver:       res,
		RateLimiter:    limiter,
		RRL:            rrl,
		MaxUDPSize:     cfg.MaxUDPSize,
		Metrics:        metricStore,
		Prometheus:     prom,
		RRLEnabled:     cfg.RRLEnabled,
		AllowRecursive: &cfg.AllowRecursive,
		Logger:         log,
	})

	dnsAddr := fmt.Sprintf(":%d", cfg.DNSPort)
	udpSrv := server.NewUDPServer(dnsAddr, dnsHandler, cfg.GoroutinePoolSize)
	tcpSrv := server.NewTCPServer(dnsAddr, dnsHandler, cfg.MaxTCPConnections)
	var dnsReady atomic.Bool
	dnsReady.Store(false)

	apiHandler := api.New(api.Deps{
		Resolver:   res,
		Cache:      cacheStore,
		DNSHandler: dnsHandler,
		Metrics:    metricStore,
		Prometheus: prom,
		ReadyCheck: func() bool {
			return dnsReady.Load() && cacheLoaded.Load()
		},
		Settings: api.NewRuntimeSettings(map[string]any{
			"version":        version,
			"blocklist_path": cfg.BlocklistPath,
		}),
		Logger:       log,
		PPROFEnabled: cfg.PPROFEnabled,
	})

	httpSrv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:           apiHandler.Router(rootCtx),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.LogError(log, "http server failed", err)
			cancel()
		}
	}()

	if err := udpSrv.Start(rootCtx); err != nil {
		logger.LogError(log, "udp server start failed", err)
		os.Exit(1)
	}
	if err := tcpSrv.Start(rootCtx); err != nil {
		logger.LogError(log, "tcp server start failed", err)
		os.Exit(1)
	}

	var dotSrv *server.DoTServer
	if cfg.TLSEnabled {
		dotAddr := fmt.Sprintf(":%d", cfg.DoTPort)
		dotSrv, err = server.NewDoTServer(dotAddr, dnsHandler, cfg.MaxTCPConnections, cfg.TLSCertPath, cfg.TLSKeyPath, cfg.TLSAutoGenerate)
		if err != nil {
			logger.LogError(log, "dot server init failed", err)
			os.Exit(1)
		}
		if err := dotSrv.Start(rootCtx); err != nil {
			logger.LogError(log, "dot server start failed", err)
			os.Exit(1)
		}
	}
	dnsReady.Store(true)

	log.Info("servers started",
		slog.String("dns_addr", dnsAddr),
		slog.Int("http_port", cfg.HTTPPort),
		slog.Bool("dot_enabled", cfg.TLSEnabled),
	)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	dnsReady.Store(false)
	cancel()
	log.Info("shutdown signal received")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownDrainTimeout)
	defer shutdownCancel()

	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Warn("http shutdown error", "error", err)
	}
	if err := udpSrv.Shutdown(shutdownCtx); err != nil {
		log.Warn("udp shutdown error", "error", err)
	}
	if err := tcpSrv.Shutdown(shutdownCtx); err != nil {
		log.Warn("tcp shutdown error", "error", err)
	}
	if dotSrv != nil {
		if err := dotSrv.Shutdown(shutdownCtx); err != nil {
			log.Warn("dot shutdown error", "error", err)
		}
	}
	if err := cacheStore.Persist(); err != nil {
		log.Warn("cache persist failed", "error", err)
	}
	log.Info("shutdown complete")
}

func runHealthcheck() int {
	port := config.Default().HTTPPort
	if envPort := strings.TrimSpace(os.Getenv("HTTP_PORT")); envPort != "" {
		if parsed, err := strconv.Atoi(envPort); err == nil && parsed > 0 {
			port = parsed
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/api/v1/health/ready", port), nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck request build failed: %v\n", err)
		return 1
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck request failed: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck status=%d\n", resp.StatusCode)
		return 1
	}
	return 0
}
