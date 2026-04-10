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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtract_ReturnsNoopWhenMissing(t *testing.T) {
	tags := Extract(context.Background())
	require.NotNil(t, tags)
	require.False(t, tags.Has("k"))
	require.Nil(t, tags.Values())
}

func TestSetInContextAndExtract_PreservesKeys(t *testing.T) {
	ctx := context.Background()
	tags := NewTags()
	tags.Set("k1", "v1")
	tags.Set("k2", 2)

	ctx = SetInContext(ctx, tags)
	extracted := Extract(ctx)
	require.True(t, extracted.Has("k1"))
	require.True(t, extracted.Has("k2"))

	values := extracted.Values()
	require.Equal(t, "v1", values["k1"])
	require.Equal(t, 2, values["k2"])
}

func TestAddLoggerEntry_AddsEntriesToContext(t *testing.T) {
	ctx := SetInContext(context.Background(), NewTags())
	AddLoggerEntry(ctx, map[string]interface{}{
		"a": "b",
		"x": 1,
	})

	tags := Extract(ctx)
	require.True(t, tags.Has("a"))
	require.True(t, tags.Has("x"))
}
