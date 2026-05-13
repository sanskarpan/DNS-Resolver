package telemetry

import (
	"context"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

type Config struct {
	Enabled     bool
	Endpoint    string
	ServiceName string
}

func Setup(ctx context.Context, cfg Config) (func(context.Context) error, error) {
	if !cfg.Enabled {
		return func(context.Context) error { return nil }, nil
	}

	serviceName := strings.TrimSpace(cfg.ServiceName)
	if serviceName == "" {
		serviceName = "dns-resolver"
	}

	res, err := resource.New(ctx, resource.WithAttributes(semconv.ServiceName(serviceName)))
	if err != nil {
		return nil, err
	}

	options := []sdktrace.TracerProviderOption{sdktrace.WithResource(res)}
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint != "" {
		endpoint = strings.TrimPrefix(endpoint, "http://")
		endpoint = strings.TrimPrefix(endpoint, "https://")
		exporter, err := otlptracegrpc.New(ctx,
			otlptracegrpc.WithEndpoint(endpoint),
			otlptracegrpc.WithInsecure(),
		)
		if err != nil {
			return nil, err
		}
		options = append(options, sdktrace.WithBatcher(exporter))
	}

	provider := sdktrace.NewTracerProvider(options...)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	return provider.Shutdown, nil
}
