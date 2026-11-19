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

// Package replica defines the caller-provided identity of a validator replica.
package replica

import (
	"context"
	"errors"
)

const maxNameLength = 255

// ErrInvalidName indicates that a name cannot identify a replica.
var ErrInvalidName = errors.New("invalid replica name")

// ID is the stable name of a validator replica.
type ID struct {
	name string
}

// NewID creates an ID from a printable ASCII name.
// Keep these limits in sync with SignRequest.replica_name in
// proto/arc/signer/v2/signer.proto.
func NewID(name string) (ID, error) {
	if len(name) == 0 || len(name) > maxNameLength {
		return ID{}, ErrInvalidName
	}
	for i := range len(name) {
		if name[i] < '!' || name[i] > '~' {
			return ID{}, ErrInvalidName
		}
	}
	return ID{name: name}, nil
}

// String returns the stable replica name.
func (id ID) String() string {
	return id.name
}

type contextKey struct{}

// NewContext returns a context that contains a replica ID.
func NewContext(ctx context.Context, id ID) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// FromContext returns the replica ID in ctx.
func FromContext(ctx context.Context) (ID, bool) {
	id, ok := ctx.Value(contextKey{}).(ID)
	return id, ok && id.name != ""
}
