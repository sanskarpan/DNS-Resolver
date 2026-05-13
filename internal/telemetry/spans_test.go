package telemetry

import (
	"context"
	"testing"
)

func TestStartResolveSpan(t *testing.T) {
	ctx := context.Background()
	newCtx, span := StartResolveSpan(ctx, "example.com", "A")
	if newCtx == nil {
		t.Fatalf("expected context")
	}
	if span == nil {
		t.Fatalf("expected span")
	}
	span.End()
}

func TestAddStepAttributes(t *testing.T) {
	_, span := StartResolveSpan(context.Background(), "example.com", "A")
	AddStepAttributes(span, "root_query", "198.41.0.4")
	span.End()
}

func TestNoOpSpanEnd(t *testing.T) {
	span := noOpSpan{}
	span.End()
}
