package telemetry

import (
	"context"
	"testing"
)

func TestSetupDisabled(t *testing.T) {
	cfg := Config{
		Enabled:     false,
		Endpoint:    "",
		ServiceName: "test",
	}
	shutdown, err := Setup(context.Background(), cfg)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	if shutdown == nil {
		t.Fatalf("expected shutdown function")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
}

func TestSetupEnabledNoEndpoint(t *testing.T) {
	cfg := Config{
		Enabled:     true,
		Endpoint:    "",
		ServiceName: "test",
	}
	shutdown, err := Setup(context.Background(), cfg)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	if shutdown == nil {
		t.Fatalf("expected shutdown function")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
}

func TestSetupEnabledWithEndpoint(t *testing.T) {
	cfg := Config{
		Enabled:     true,
		Endpoint:    "http://localhost:4317",
		ServiceName: "dns-resolver",
	}
	shutdown, err := Setup(context.Background(), cfg)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	if shutdown == nil {
		t.Fatalf("expected shutdown function")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
}
