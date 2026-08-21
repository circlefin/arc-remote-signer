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

package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// testAppConfig implements ApplicationConfig for testing LoadConfig.
type testAppConfig struct {
	*BaseConfig `mapstructure:",squash"`
	TestField   string `mapstructure:"test_field"`
}

func (c *testAppConfig) GetName() string {
	return "test-app"
}

func TestLoadConfig(t *testing.T) {
	t.Run("loads values from explicit config file", func(t *testing.T) {
		t.Setenv("APP_ENV", "")
		t.Setenv("APP_TEST_FIELD", "")

		tmpDir := t.TempDir()
		configFile := writeTestConfigFile(
			t,
			tmpDir,
			"test-config.yaml",
			`env: qa
test_field: "test-value"
`,
		)

		cfg := newTestAppConfig()
		LoadConfig(cfg, configFile)

		assertLoadedConfig(t, cfg, QA, "test-value")
	})

	t.Run("environment variables override config file values", func(t *testing.T) {
		t.Setenv("APP_ENV", "stg")
		t.Setenv("APP_TEST_FIELD", "env-value")

		tmpDir := t.TempDir()
		configFile := writeTestConfigFile(
			t,
			tmpDir,
			"test-config.yaml",
			`env: dev
test_field: "file-value"
`,
		)

		cfg := newTestAppConfig()
		LoadConfig(cfg, configFile)

		assertLoadedConfig(t, cfg, Stg, "env-value")
	})

	t.Run("environment variables override struct defaults when key absent from config file", func(t *testing.T) {
		t.Setenv("APP_ENV", "stg")
		t.Setenv("APP_TEST_FIELD", "")

		tmpDir := t.TempDir()
		configFile := writeTestConfigFile(
			t,
			tmpDir,
			"test-config.yaml",
			`test_field: "file-value"
`,
		)

		cfg := newTestAppConfig()
		LoadConfig(cfg, configFile)

		assertLoadedConfig(t, cfg, Stg, "file-value")
	})

	t.Run("uses default config path when file argument is empty", func(t *testing.T) {
		t.Setenv("APP_ENV", "stg")
		t.Setenv("APP_TEST_FIELD", "")

		tmpDir := t.TempDir()
		configsDir := filepath.Join(tmpDir, "configs")
		require.NoError(t, os.MkdirAll(configsDir, 0o755))

		writeTestConfigFile(
			t,
			configsDir,
			"config.yaml",
			`env: prod
test_field: "default-value"
`,
		)
		setWorkingDirectory(t, tmpDir)

		cfg := newTestAppConfig()
		LoadConfig(cfg, "")

		assertLoadedConfig(t, cfg, Stg, "default-value")
	})

	t.Run("uses file values when env vars are unset", func(t *testing.T) {
		t.Setenv("APP_ENV", "")
		t.Setenv("APP_TEST_FIELD", "")

		tmpDir := t.TempDir()
		configsDir := filepath.Join(tmpDir, "configs")
		require.NoError(t, os.MkdirAll(configsDir, 0o755))

		writeTestConfigFile(
			t,
			configsDir,
			"config.yaml",
			`env: dev
test_field: "file-value"
`,
		)
		setWorkingDirectory(t, tmpDir)

		cfg := newTestAppConfig()
		LoadConfig(cfg, "")

		assertLoadedConfig(t, cfg, Dev, "file-value")
	})

	t.Run("keeps initial values when default config path has no config file", func(t *testing.T) {
		t.Setenv("APP_ENV", "")
		t.Setenv("APP_TEST_FIELD", "")

		tmpDir := t.TempDir()
		setWorkingDirectory(t, tmpDir)

		cfg := newTestAppConfig()
		LoadConfig(cfg, "")

		assertLoadedConfig(t, cfg, Dev, "")
	})
}

func TestLoadConfig_ExitsWhenExplicitConfigFileMissing(t *testing.T) {
	const (
		helperEnv = "TEST_LOAD_CONFIG_FATAL"
		pathEnv   = "TEST_LOAD_CONFIG_PATH"
	)

	if os.Getenv(helperEnv) == "1" {
		LoadConfig(newTestAppConfig(), os.Getenv(pathEnv))
		return
	}

	missingPath := filepath.Join(t.TempDir(), "missing.yaml")
	cmd := exec.Command(os.Args[0], "-test.run=^TestLoadConfig_ExitsWhenExplicitConfigFileMissing$")
	cmd.Env = append(os.Environ(), helperEnv+"=1", pathEnv+"="+missingPath)
	output, err := cmd.CombinedOutput()

	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	require.Equal(t, 1, exitErr.ExitCode())
	require.Contains(t, string(output), "Specified config file could not be loaded:")
	require.Contains(t, string(output), missingPath)
}

func newTestAppConfig() *testAppConfig {
	return &testAppConfig{
		BaseConfig: NewBaseConfig(),
	}
}

func writeTestConfigFile(t *testing.T, dir, fileName, content string) string {
	t.Helper()

	configFile := filepath.Join(dir, fileName)
	err := os.WriteFile(configFile, []byte(content), 0o644)
	require.NoError(t, err)

	return configFile
}

func setWorkingDirectory(t *testing.T, dir string) {
	t.Helper()

	originalWd, err := os.Getwd()
	require.NoError(t, err)

	err = os.Chdir(dir)
	require.NoError(t, err)

	t.Cleanup(func() {
		if err := os.Chdir(originalWd); err != nil {
			t.Errorf("failed to restore working directory: %v", err)
		}
	})
}

func assertLoadedConfig(
	t *testing.T,
	cfg *testAppConfig,
	wantEnv Environment,
	wantTestField string,
) {
	t.Helper()

	require.NotNil(t, cfg)
	require.Equal(t, wantEnv, cfg.Env)
	require.Equal(t, wantTestField, cfg.TestField)
}
