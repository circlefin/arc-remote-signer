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

package cmd

import (
	"github.com/circlefin/arc-remote-signer/internal/common/config"
	"github.com/circlefin/arc-remote-signer/internal/vsockproxy"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(runVsockproxyCmd)
}

var runVsockproxyCmd = &cobra.Command{
	Use:   "run-vsockproxy",
	Short: "Run the standalone vsockproxy bridge process.",
	// Startup failures are reported once by Execute() as a single stderr
	// line with exit code 1; silence cobra's default usage dump and
	// duplicate error print so they match the lifecycle.Manager path.
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		vsockproxyCfg := vsockproxy.NewConfig()
		config.LoadConfig(vsockproxyCfg, cfgFile)
		return vsockproxy.Run(vsockproxyCfg)
	},
}
