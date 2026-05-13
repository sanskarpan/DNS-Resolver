package telemetry

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type Span interface {
	End()
}

type noOpSpan struct{}

func (noOpSpan) End() {}

type otelSpan struct {
	span trace.Span
}

func (s otelSpan) End() {
	s.span.End()
}

func StartResolveSpan(ctx context.Context, domain string, qtype string) (context.Context, Span) {
	tracer := otel.Tracer("dnsresolver/resolver")
	ctx, span := tracer.Start(ctx, "resolver.resolve",
		trace.WithAttributes(
			attribute.String("dns.question.name", domain),
			attribute.String("dns.question.type", qtype),
		),
	)
	return ctx, otelSpan{span: span}
}

func AddStepAttributes(span Span, step string, server string) {
	if realSpan, ok := span.(otelSpan); ok {
		realSpan.span.AddEvent("resolver.step",
			trace.WithAttributes(
				attribute.String("resolver.step.type", step),
				attribute.String("resolver.step.server", server),
			),
		)
	}
}
