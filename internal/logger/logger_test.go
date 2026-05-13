package logger

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestFromCtxAddsIDs(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := NewWithWriter(&buf, "info", "json")
	ctx := context.Background()
	ctx = WithRequestID(ctx, "req-1")
	ctx = WithQueryID(ctx, "qry-1")
	ctx = WithTraceID(ctx, "trace-1")

	FromCtx(ctx, l).Info("ctx log")
	out := buf.String()
	if !strings.Contains(out, `"request_id":"req-1"`) {
		t.Fatalf("missing request_id: %s", out)
	}
	if !strings.Contains(out, `"query_id":"qry-1"`) {
		t.Fatalf("missing query_id: %s", out)
	}
	if !strings.Contains(out, `"trace_id":"trace-1"`) {
		t.Fatalf("missing trace_id: %s", out)
	}
}

func TestLogErrorIncludesStackTrace(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := NewWithWriter(&buf, "error", "json")
	LogError(l, "boom", context.DeadlineExceeded)
	out := buf.String()
	if !strings.Contains(out, `"stack_trace":"`) {
		t.Fatalf("missing stack_trace: %s", out)
	}
	if !strings.Contains(out, `"error":"context deadline exceeded"`) {
		t.Fatalf("missing error field: %s", out)
	}
}

func TestFromCtxWithExistingLogger(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := NewWithWriter(&buf, "info", "json")
	ctx := context.Background()
	ctx = WithRequestID(ctx, "req-123")

	result := FromCtx(ctx, l)
	if result == nil {
		t.Fatalf("expected non-nil logger")
	}
}

func TestLogErrorWithNilLogger(t *testing.T) {
}

func TestLogErrorWithNilError(t *testing.T) {
	var buf bytes.Buffer
	l := NewWithWriter(&buf, "error", "json")
	LogError(l, "boom", nil)
}
