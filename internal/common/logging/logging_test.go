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

package logging

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type capturedRecord struct {
	message string
	attrs   map[string]any
}

type recordStore struct {
	mu      sync.Mutex
	records []capturedRecord
}

type captureHandler struct {
	level   slog.Level
	base    []slog.Attr
	records *recordStore
}

func newCaptureHandler(level slog.Level) *captureHandler {
	return &captureHandler{
		level:   level,
		records: &recordStore{},
	}
}

func (h *captureHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	attrs := h.collectAttrs(r)

	h.records.mu.Lock()
	defer h.records.mu.Unlock()
	h.records.records = append(h.records.records, capturedRecord{
		message: r.Message,
		attrs:   attrs,
	})
	return nil
}

func (h *captureHandler) collectAttrs(r slog.Record) map[string]any {
	attrs := map[string]any{}
	for _, a := range h.base {
		attrs[a.Key] = a.Value.Any()
	}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})
	return attrs
}

func (h *captureHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &captureHandler{
		level:   h.level,
		base:    append(append([]slog.Attr{}, h.base...), attrs...),
		records: h.records,
	}
}

func (h *captureHandler) WithGroup(_ string) slog.Handler {
	return h
}

func (h *captureHandler) all() []capturedRecord {
	h.records.mu.Lock()
	defer h.records.mu.Unlock()
	out := make([]capturedRecord, len(h.records.records))
	copy(out, h.records.records)
	return out
}

func newObservedLogger(level slog.Level) (*Logger, *captureHandler) {
	handler := newCaptureHandler(level)
	return &Logger{logger: slog.New(handler)}, handler
}

func requireRecordCount(t *testing.T, observed *captureHandler, want int) []capturedRecord {
	t.Helper()
	records := observed.all()
	require.Len(t, records, want, "unexpected number of log records")
	return records
}

func requireAttr(t *testing.T, attrs map[string]any, key string) any {
	t.Helper()
	value, ok := attrs[key]
	require.Truef(t, ok, "expected %q field, got map: %v", key, attrs)
	return value
}

func clearObservedRecords(observed *captureHandler) {
	observed.records.mu.Lock()
	observed.records.records = nil
	observed.records.mu.Unlock()
}

func buildContextWithTagsAndTrace() context.Context {
	ctx := SetInContext(context.Background(), NewTags())
	AddLoggerEntry(ctx, map[string]interface{}{"fromCtx": "ctxVal"})

	traceID := trace.TraceID{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	spanID := trace.SpanID{2, 2, 2, 2, 2, 2, 2, 2}
	ctx = trace.ContextWithSpanContext(ctx, trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID,
		SpanID:  spanID,
	}))
	return ctx
}

func requireMDCIncludesTraceAndSpan(t *testing.T, attrs map[string]any) {
	t.Helper()
	mdcVal := requireAttr(t, attrs, "mdc")
	mdcMap, ok := mdcVal.(map[string]any)
	require.Truef(t, ok, "expected mdc to be map[string]interface{}, got %T", mdcVal)
	require.NotNilf(t, mdcMap["trace_id"], "expected mdc to include trace_id, got %v", mdcMap)
	require.NotNilf(t, mdcMap["span_id"], "expected mdc to include span_id, got %v", mdcMap)
}

func TestGet_ReturnsCachedInstance(t *testing.T) {
	l1 := Get("unit-test-logger")
	l2 := Get("unit-test-logger")
	require.Same(t, l1, l2)
}

func TestGet_ReturnsDifferentInstanceForDifferentName(t *testing.T) {
	l1 := Get("unit-test-logger-a")
	l2 := Get("unit-test-logger-b")
	require.NotSame(t, l1, l2)
}

func TestWrite_LogsInfoAndReturnsByteCount(t *testing.T) {
	l, observed := newObservedLogger(slog.LevelInfo)
	payload := "hello from writer"

	n, err := l.Write([]byte(payload))
	require.NoError(t, err)
	require.Equal(t, len(payload), n)

	records := requireRecordCount(t, observed, 1)
	require.Equal(t, payload, records[0].message)
}

func TestInfoWarnError_PreserveFieldsAndMDC(t *testing.T) {
	l, observed := newObservedLogger(slog.LevelDebug)
	ctx := buildContextWithTagsAndTrace()

	l.Info(ctx, "info-msg", Entries{"k": "v"})
	l.Warn(ctx, "warn-msg", Entries{"wk": "wv"})
	l.Error(ctx, "err-msg", Entries{"ek": "ev"})

	records := requireRecordCount(t, observed, 3)

	require.Equal(t, "info-msg", records[0].message)
	require.Equal(t, "ctxVal", records[0].attrs["fromCtx"])
	requireMDCIncludesTraceAndSpan(t, records[0].attrs)
}

func TestErrWrappers_AttachErrorField(t *testing.T) {
	l, observed := newObservedLogger(slog.LevelDebug)
	testErr := errors.New("boom")

	tests := []struct {
		name    string
		message string
		logFn   func(context.Context, string, error, Entries)
	}{
		{name: "info", message: "info-err", logFn: l.InfoErr},
		{name: "warn", message: "warn-err", logFn: l.WarnErr},
		{name: "error", message: "error-err", logFn: l.ErrorErr},
		{name: "debug", message: "debug-err", logFn: l.DebugErr},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			clearObservedRecords(observed)
			tc.logFn(context.Background(), tc.message, testErr, Entries{"source": tc.name})

			records := requireRecordCount(t, observed, 1)
			require.Equal(t, tc.message, records[0].message)
			require.NotNil(t, records[0].attrs["error"])
		})
	}
}

func TestErrorErr_ExpandsGrpcStatusFields(t *testing.T) {
	l, observed := newObservedLogger(slog.LevelDebug)
	appErr := status.Error(codes.Internal, "db down")

	l.ErrorErr(context.Background(), "service failed", appErr, nil)

	records := requireRecordCount(t, observed, 1)

	m := maps.Clone(records[0].attrs)
	requireAttr(t, m, ErrorCodeLoggingKey)
	requireAttr(t, m, ErrorMessageLoggingKey)
}

func TestLoggerLevels_EmitMessageAndEntries(t *testing.T) {
	l, observed := newObservedLogger(slog.LevelDebug)
	tests := []struct {
		levelName string
		message   string
		logFn     func(context.Context, string, Entries)
		entries   Entries
	}{
		{levelName: "info", message: "info message", logFn: l.Info, entries: Entries{"a": 1}},
		{levelName: "warn", message: "warn message", logFn: l.Warn, entries: Entries{"b": 2}},
		{levelName: "error", message: "error message", logFn: l.Error, entries: Entries{"c": 3}},
		{levelName: "debug", message: "debug message", logFn: l.Debug, entries: Entries{"d": 4}},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.levelName, func(t *testing.T) {
			clearObservedRecords(observed)
			tc.logFn(context.Background(), tc.message, tc.entries)

			records := requireRecordCount(t, observed, 1)
			require.Equal(t, tc.message, records[0].message)
			for k := range tc.entries {
				require.Contains(t, records[0].attrs, k)
			}
		})
	}
}
