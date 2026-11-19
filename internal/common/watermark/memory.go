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

package watermark

import (
	"context"
	"sync"
)

var _ Repository = (*MemoryRepository)(nil)

// MemoryRepository stores one process-local aggregate watermark state.
type MemoryRepository struct {
	mu    sync.Mutex
	state State
}

// NewMemoryRepository creates an empty in-memory repository for one validator.
func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{state: make(State)}
}

// CompareAndAdvance applies the enclave watermark rule atomically.
func (r *MemoryRepository) CompareAndAdvance(_ context.Context, namespace Namespace, candidate Watermark) (Outcome, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	next, outcome, err := AdvanceState(r.state, namespace, candidate, CrossKindEnclave)
	if err != nil {
		return 0, err
	}
	r.state = next
	return outcome, nil
}
