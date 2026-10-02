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

package main

import (
	"os/exec"
	"strings"
	"testing"

	commonConfig "github.com/circlefin/arc-remote-signer/internal/common/config"
	"github.com/circlefin/arc-remote-signer/internal/enclave"
	"github.com/stretchr/testify/require"
)

func TestRun(t *testing.T) {
	t.Run("loads selected config and starts enclave", func(t *testing.T) {
		var loadedConfig commonConfig.ApplicationConfig
		var loadedPath string
		var startedConfig *enclave.Config

		err := run(
			[]string{"--enclave-config", "/tmp/enclave.yaml"},
			func(cfg commonConfig.ApplicationConfig, path string) {
				loadedConfig = cfg
				loadedPath = path
			},
			func(cfg *enclave.Config) error {
				startedConfig = cfg
				return nil
			},
		)

		require.NoError(t, err)
		require.Equal(t, "/tmp/enclave.yaml", loadedPath)
		require.Same(t, loadedConfig, startedConfig)
	})

	t.Run("rejects legacy cobra subcommand", func(t *testing.T) {
		called := false
		err := run(
			[]string{"run-enclave"},
			func(commonConfig.ApplicationConfig, string) { called = true },
			func(*enclave.Config) error {
				called = true
				return nil
			},
		)

		require.ErrorContains(t, err, "unexpected arguments")
		require.False(t, called)
	})

	t.Run("prints help without starting enclave", func(t *testing.T) {
		called := false
		err := run(
			[]string{"--help"},
			func(commonConfig.ApplicationConfig, string) { called = true },
			func(*enclave.Config) error {
				called = true
				return nil
			},
		)

		require.NoError(t, err)
		require.False(t, called)
	})
}

func TestEnclaveDependencyBoundary(t *testing.T) {
	output, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	require.NoError(t, err, string(output))

	for _, dependency := range strings.Fields(string(output)) {
		require.Falsef(t, isForbiddenDependency(dependency), "enclave entrypoint imports forbidden dependency %s", dependency)
	}
}

func isForbiddenDependency(dependency string) bool {
	for _, exact := range []string{
		"github.com/circlefin/arc-remote-signer/cmd",
		"github.com/spf13/cobra",
	} {
		if dependency == exact {
			return true
		}
	}

	for _, subtree := range []string{
		"github.com/circlefin/arc-remote-signer/internal/app",
		"github.com/circlefin/arc-remote-signer/internal/vsockproxy",
		"github.com/aws/aws-sdk-go-v2/service/secretsmanager",
	} {
		if dependency == subtree || strings.HasPrefix(dependency, subtree+"/") {
			return true
		}
	}

	return false
}
