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

package rand

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateRandomBytes(t *testing.T) {
	t.Run("returns requested length", func(t *testing.T) {
		n := 32
		b, err := GenerateRandomBytes(n)
		require.NoError(t, err)
		require.Len(t, b, n)
	})

	t.Run("returns empty bytes when n is zero", func(t *testing.T) {
		b, err := GenerateRandomBytes(0)
		require.NoError(t, err)
		require.Empty(t, b)
	})

	t.Run("returns error when n is negative", func(t *testing.T) {
		b, err := GenerateRandomBytes(-1)
		require.Error(t, err)
		require.Nil(t, b)
	})
}

func TestGenerateFixedSizeRandomBytes_ReturnsFixedLength(t *testing.T) {
	b, err := GenerateFixedSizeRandomBytes()
	require.NoError(t, err)
	require.Len(t, b, saltSize)
}

func TestMustGenerateRandomBytes(t *testing.T) {
	t.Run("returns requested length", func(t *testing.T) {
		n := 16
		b := MustGenerateRandomBytes(n)
		require.Len(t, b, n)
	})

	t.Run("panics when length is invalid", func(t *testing.T) {
		require.PanicsWithError(t, "invalid length: -1", func() {
			MustGenerateRandomBytes(-1)
		})
	})
}

func TestMustGenerateFixedSizeRandomBytes_ReturnsFixedLength(t *testing.T) {
	b := MustGenerateFixedSizeRandomBytes()
	require.Len(t, b, saltSize)
}

func TestGenerateRandomString(t *testing.T) {
	t.Run("returns requested length", func(t *testing.T) {
		lengths := []int{1, 10, 32, 100}
		for _, length := range lengths {
			result, err := GenerateRandomString(length)
			require.NoError(t, err)
			assert.Len(t, result, length)
		}
	})

	t.Run("returns empty string for zero length", func(t *testing.T) {
		result, err := GenerateRandomString(0)
		require.NoError(t, err)
		require.Empty(t, result)
	})

	t.Run("returns error for negative length", func(t *testing.T) {
		result, err := GenerateRandomString(-1)
		require.Error(t, err)
		require.Empty(t, result)
	})

	t.Run("contains only valid charset characters", func(t *testing.T) {
		result, err := GenerateRandomString(100)
		require.NoError(t, err)
		for _, char := range result {
			assert.True(t, strings.ContainsRune(randStringCharset, char), "found invalid character %q in result", char)
		}
	})

	t.Run("generates different strings", func(t *testing.T) {
		length := 20
		results := make(map[string]bool)
		iterations := 10

		for range iterations {
			result, err := GenerateRandomString(length)
			require.NoError(t, err)
			assert.False(t, results[result], "duplicate string generated: %q", result)
			results[result] = true
		}

		assert.Len(t, results, iterations)
	})

	t.Run("uses all character types", func(t *testing.T) {
		// Generate a long string to increase probability of all char types appearing.
		result, err := GenerateRandomString(1000)
		require.NoError(t, err)

		hasLower := false
		hasUpper := false
		hasDigit := false

		for _, char := range result {
			if char >= 'a' && char <= 'z' {
				hasLower = true
			} else if char >= 'A' && char <= 'Z' {
				hasUpper = true
			} else if char >= '0' && char <= '9' {
				hasDigit = true
			}

			if hasLower && hasUpper && hasDigit {
				break
			}
		}

		assert.True(t, hasLower, "expected lowercase characters in result")
		assert.True(t, hasUpper, "expected uppercase characters in result")
		assert.True(t, hasDigit, "expected digit characters in result")
	})
}

func TestMustGenerateRandomString(t *testing.T) {
	t.Run("returns requested length", func(t *testing.T) {
		length := 20
		result := MustGenerateRandomString(length)
		require.Len(t, result, length)
	})

	t.Run("generates different strings", func(t *testing.T) {
		length := 20
		results := make(map[string]bool)
		iterations := 10

		for range iterations {
			result := MustGenerateRandomString(length)
			assert.False(t, results[result], "duplicate string generated: %q", result)
			results[result] = true
		}

		assert.Len(t, results, iterations)
	})
}
