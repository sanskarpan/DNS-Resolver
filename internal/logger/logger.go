package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"runtime/debug"
	"strings"
	"time"
)

type ctxKey string

const (
	requestIDKey ctxKey = "request_id"
	queryIDKey   ctxKey = "query_id"
	traceIDKey   ctxKey = "trace_id"
)

const (
	FieldTimestamp  = "timestamp"
	FieldRequestID  = "request_id"
	FieldQueryID    = "query_id"
	FieldTraceID    = "trace_id"
	FieldDomain     = "domain"
	FieldType       = "type"
	FieldRCode      = "rcode"
	FieldDurationMS = "duration_ms"
	FieldCached     = "cached"
	FieldStale      = "stale"
	FieldClientIP   = "client_ip"
	FieldProtocol   = "protocol"
	FieldSteps      = "steps"
	FieldError      = "error"
	FieldStackTrace = "stack_trace"
)

func New(level, format string) *slog.Logger {
	lvl := parseLevel(level)
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	if strings.EqualFold(format, "text") {
		h = slog.NewTextHandler(os.Stdout, opts)
	} else {
		h = slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.New(h)
}

func NewWithWriter(w io.Writer, level, format string) *slog.Logger {
	lvl := parseLevel(level)
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	if strings.EqualFold(format, "text") {
		h = slog.NewTextHandler(w, opts)
	} else {
		h = slog.NewJSONHandler(w, opts)
	}
	return slog.New(h)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

func WithQueryID(ctx context.Context, queryID string) context.Context {
	return context.WithValue(ctx, queryIDKey, queryID)
}

func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, traceIDKey, traceID)
}

func RequestIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(requestIDKey).(string)
	return v
}

func QueryIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(queryIDKey).(string)
	return v
}

func TraceIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(traceIDKey).(string)
	return v
}

func FromCtx(ctx context.Context, base *slog.Logger) *slog.Logger {
	if base == nil {
		base = slog.Default()
	}
	attrs := make([]any, 0, 3)
	if rid := RequestIDFromContext(ctx); rid != "" {
		attrs = append(attrs, slog.String(FieldRequestID, rid))
	}
	if qid := QueryIDFromContext(ctx); qid != "" {
		attrs = append(attrs, slog.String(FieldQueryID, qid))
	}
	if tid := TraceIDFromContext(ctx); tid != "" {
		attrs = append(attrs, slog.String(FieldTraceID, tid))
	}
	if len(attrs) == 0 {
		return base
	}
	return base.With(attrs...)
}

type QueryLogFields struct {
	RequestID  string
	QueryID    string
	TraceID    string
	Domain     string
	QType      string
	RCode      string
	DurationMS int64
	Cached     bool
	Stale      bool
	ClientIP   string
	Protocol   string
	Steps      int
	Err        error
}

func LogQuery(l *slog.Logger, level slog.Level, fields QueryLogFields) {
	errMsg := any(nil)
	if fields.Err != nil {
		errMsg = fields.Err.Error()
	}
	attrs := []any{
		slog.String(FieldTimestamp, time.Now().UTC().Format(time.RFC3339Nano)),
		slog.String(FieldRequestID, fields.RequestID),
		slog.String(FieldQueryID, fields.QueryID),
		slog.String(FieldTraceID, fields.TraceID),
		slog.String(FieldDomain, fields.Domain),
		slog.String(FieldType, fields.QType),
		slog.String(FieldRCode, fields.RCode),
		slog.Int64(FieldDurationMS, fields.DurationMS),
		slog.Bool(FieldCached, fields.Cached),
		slog.Bool(FieldStale, fields.Stale),
		slog.String(FieldClientIP, fields.ClientIP),
		slog.String(FieldProtocol, fields.Protocol),
		slog.Int(FieldSteps, fields.Steps),
		slog.Any(FieldError, errMsg),
	}
	if fields.Err != nil && level >= slog.LevelError {
		attrs = append(attrs, slog.String(FieldStackTrace, string(debug.Stack())))
	}
	l.Log(context.Background(), level, "dns query", attrs...)
}

func LogError(l *slog.Logger, msg string, err error, attrs ...any) {
	if l == nil {
		l = slog.Default()
	}
	base := []any{
		slog.Any(FieldError, err),
		slog.String(FieldStackTrace, string(debug.Stack())),
	}
	base = append(base, attrs...)
	l.Log(context.Background(), slog.LevelError, msg, base...)
}
