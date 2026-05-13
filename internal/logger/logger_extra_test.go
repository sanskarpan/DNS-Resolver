package logger

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestNewUsesRequestedFormatAndLevel(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	l := NewWithWriter(&buf, "debug", "text")
	l.Debug("debug line")
	if !strings.Contains(buf.String(), "level=DEBUG") {
		t.Fatalf("expected text debug logger output, got %s", buf.String())
	}
}

func TestFromCtxFallsBackToDefaultLogger(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	if got := FromCtx(ctx, nil); got == nil {
		t.Fatal("expected default logger fallback")
	}
}

func TestLogQueryIncludesErrorAndStackTraceAtErrorLevel(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	l := NewWithWriter(&buf, "debug", "json")
	LogQuery(l, slog.LevelError, QueryLogFields{
		RequestID:  "req-1",
		QueryID:    "qry-1",
		TraceID:    "trace-1",
		Domain:     "example.com.",
		QType:      "A",
		RCode:      "SERVFAIL",
		DurationMS: 12,
		ClientIP:   "127.0.0.1",
		Protocol:   "udp",
		Steps:      2,
		Err:        context.DeadlineExceeded,
	})

	out := buf.String()
	for _, want := range []string{
		`"request_id":"req-1"`,
		`"query_id":"qry-1"`,
		`"trace_id":"trace-1"`,
		`"domain":"example.com."`,
		`"error":"context deadline exceeded"`,
		`"stack_trace":"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %s in output: %s", want, out)
		}
	}
}
