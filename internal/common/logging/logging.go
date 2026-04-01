// Copyright (c) 2026, Circle Internet Group, Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package logging provides structured logging helpers with context tags and error field expansion.
package logging

import (
	"context"
	"log/slog"
	"os"
	"sync"

	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/status"
)

const (
	// RequestTimeLoggingKey stores request latency in milliseconds.
	RequestTimeLoggingKey = "requestTimeMS"
	// ErrorCodeLoggingKey stores gRPC status code.
	ErrorCodeLoggingKey = "errorCode"
	// ErrorMessageLoggingKey stores error message.
	ErrorMessageLoggingKey = "errorMessage"
)

// Entries are key/value pairs attached to logs.
type Entries map[string]any

// Logger is a structured logger wrapper.
type Logger struct {
	logger *slog.Logger
}

var (
	loggerRegistry sync.Map
)

// Get returns a package-scoped logger by name.
func Get(name string) *Logger {
	if v, ok := loggerRegistry.Load(name); ok {
		return v.(*Logger)
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	cl := &Logger{logger: slog.New(handler).With("logger", name)}
	loggerRegistry.Store(name, cl)
	return cl
}

// Write implements io.Writer.
func (l *Logger) Write(p []byte) (n int, err error) {
	l.Info(context.Background(), string(p), nil)
	return len(p), nil
}

// Error logs an error-level message.
func (l *Logger) Error(ctx context.Context, message string, entries Entries) {
	l.log(ctx, slog.LevelError, message, nil, entries)
}

// ErrorErr logs an error-level message with attached error.
func (l *Logger) ErrorErr(ctx context.Context, message string, err error, entries Entries) {
	l.log(ctx, slog.LevelError, message, err, entries)
}

// Warn logs a warn-level message.
func (l *Logger) Warn(ctx context.Context, message string, entries Entries) {
	l.log(ctx, slog.LevelWarn, message, nil, entries)
}

// WarnErr logs a warn-level message with attached error.
func (l *Logger) WarnErr(ctx context.Context, message string, err error, entries Entries) {
	l.log(ctx, slog.LevelWarn, message, err, entries)
}

// Info logs an info-level message.
func (l *Logger) Info(ctx context.Context, message string, entries Entries) {
	l.log(ctx, slog.LevelInfo, message, nil, entries)
}

// InfoErr logs an info-level message with attached error.
func (l *Logger) InfoErr(ctx context.Context, message string, err error, entries Entries) {
	l.log(ctx, slog.LevelInfo, message, err, entries)
}

// Debug logs a debug-level message.
func (l *Logger) Debug(ctx context.Context, message string, entries Entries) {
	l.log(ctx, slog.LevelDebug, message, nil, entries)
}

// DebugErr logs a debug-level message with attached error.
func (l *Logger) DebugErr(ctx context.Context, message string, err error, entries Entries) {
	l.log(ctx, slog.LevelDebug, message, err, entries)
}

func (l *Logger) log(ctx context.Context, level slog.Level, message string, err error, entries Entries) {
	merged := make(map[string]any)
	if vv := Extract(ctx).Values(); vv != nil {
		for k, v := range vv {
			merged[k] = v
		}
	}
	for k, v := range entries {
		merged[k] = v
	}

	mdc := make(map[string]any, len(merged)+2)
	for k, v := range merged {
		mdc[k] = v
	}
	if spanCtx := trace.SpanContextFromContext(ctx); spanCtx.IsValid() {
		mdc["trace_id"] = spanCtx.TraceID().String()
		mdc["span_id"] = spanCtx.SpanID().String()
	}

	attrs := make([]slog.Attr, 0, len(merged)+5)
	for k, v := range merged {
		attrs = append(attrs, slog.Any(k, v))
	}
	attrs = append(attrs, slog.Any("mdc", mdc))

	if err != nil {
		attrs = append(attrs, slog.Any("error", err))
		if s, ok := status.FromError(err); ok {
			attrs = append(attrs, slog.String(ErrorCodeLoggingKey, s.Code().String()))
			attrs = append(attrs, slog.String(ErrorMessageLoggingKey, s.Message()))
		}
	}

	l.logger.LogAttrs(ctx, level, message, attrs...)
}
