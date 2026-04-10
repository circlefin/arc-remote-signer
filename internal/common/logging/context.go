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
	"fmt"
	"sync"
)

type ctxMarker struct{}

var (
	ctxMarkerKey = &ctxMarker{}
	// NoopTags is a no-op implementation of Tags.
	NoopTags = &noopTags{}
)

// Tags stores request-scoped logging metadata.
type Tags interface {
	Set(key string, value interface{}) Tags
	Has(key string) bool
	Values() map[string]interface{}
}

type mapTags struct {
	values sync.Map
}

func (t *mapTags) Set(key string, value interface{}) Tags {
	t.values.Store(key, value)
	return t
}

func (t *mapTags) Has(key string) bool {
	_, ok := t.values.Load(key)
	return ok
}

func (t *mapTags) Values() map[string]interface{} {
	res := make(map[string]interface{})
	t.values.Range(func(key, value interface{}) bool {
		res[fmt.Sprint(key)] = value
		return true
	})
	return res
}

type noopTags struct{}

func (t *noopTags) Set(_ string, _ interface{}) Tags { return t }
func (t *noopTags) Has(_ string) bool                { return false }
func (t *noopTags) Values() map[string]interface{}   { return nil }

// Extract returns a pre-existing Tags object in context, or NoopTags.
func Extract(ctx context.Context) Tags {
	t, ok := ctx.Value(ctxMarkerKey).(Tags)
	if !ok {
		return NoopTags
	}
	return t
}

// SetInContext returns a context with the given tags.
func SetInContext(ctx context.Context, tags Tags) context.Context {
	return context.WithValue(ctx, ctxMarkerKey, tags)
}

// NewTags returns a mutable Tags implementation.
func NewTags() Tags {
	return &mapTags{values: sync.Map{}}
}

// AddLoggerEntry adds entries into context tags.
func AddLoggerEntry(ctx context.Context, entries map[string]interface{}) {
	tags := Extract(ctx)
	for k, v := range entries {
		tags.Set(k, v)
	}
}
