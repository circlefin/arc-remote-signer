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

package lifecycle

import (
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
)

func TestNewManager_NotNil(t *testing.T) {
	mgr := NewManager()
	require.NotNil(t, mgr)
	require.NotNil(t, mgr.runnables)
	require.Empty(t, mgr.runnables)
}

func TestManager_Manage_AppendsRunnables(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mgr := NewManager()

	mock1 := NewMockRunnable(ctrl)
	mock2 := NewMockRunnable(ctrl)

	mgr.Manage(mock1)
	require.Len(t, mgr.runnables, 1)

	mgr.Manage(mock2)
	require.Len(t, mgr.runnables, 2)
}

func TestManager_Run(t *testing.T) {
	t.Run("single runnable", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mgr := NewManager()
		mock := NewMockRunnable(ctrl)

		// Expect Run to be called
		mock.EXPECT().Run().Return(nil)
		// Expect Shutdown to be called
		mock.EXPECT().Shutdown(gomock.Any()).Return(nil)

		mgr.Manage(mock)

		// Run manager in goroutine since it blocks on signal
		done := make(chan struct{})
		go func() {
			mgr.Run()
			close(done)
		}()

		// Give it a moment to start
		time.Sleep(50 * time.Millisecond)

		// Send SIGTERM to trigger shutdown
		p, _ := os.FindProcess(os.Getpid())
		_ = p.Signal(syscall.SIGTERM)

		// Wait for shutdown to complete
		select {
		case <-done:
			// Success - expectations verified by gomock
		case <-time.After(2 * time.Second):
			require.Fail(t, "Manager.Run() did not complete shutdown in time")
		}
	})

	t.Run("multiple runnables", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mgr := NewManager()
		mock1 := NewMockRunnable(ctrl)
		mock2 := NewMockRunnable(ctrl)
		mock3 := NewMockRunnable(ctrl)

		// Expect Run to be called on all mocks
		mock1.EXPECT().Run().Return(nil)
		mock2.EXPECT().Run().Return(nil)
		mock3.EXPECT().Run().Return(nil)

		// Expect Shutdown to be called on all mocks
		mock1.EXPECT().Shutdown(gomock.Any()).Return(nil)
		mock2.EXPECT().Shutdown(gomock.Any()).Return(nil)
		mock3.EXPECT().Shutdown(gomock.Any()).Return(nil)

		mgr.Manage(mock1)
		mgr.Manage(mock2)
		mgr.Manage(mock3)

		// Run manager in goroutine
		done := make(chan struct{})
		go func() {
			mgr.Run()
			close(done)
		}()

		// Give it a moment to start all runnables
		time.Sleep(50 * time.Millisecond)

		// Send SIGTERM to trigger shutdown
		p, _ := os.FindProcess(os.Getpid())
		_ = p.Signal(syscall.SIGTERM)

		// Wait for shutdown to complete
		select {
		case <-done:
			// Success - expectations verified by gomock
		case <-time.After(2 * time.Second):
			require.Fail(t, "Manager.Run() did not complete shutdown in time")
		}
	})
}
