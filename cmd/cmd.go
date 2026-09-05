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

// Package cmd contains the app commands.
package cmd

import (
	"fmt"
	"os"

	"github.com/circlefin/arc-remote-signer/internal/app"
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	cfg     *app.Config

	rootCmd = &cobra.Command{
		Use:   "app",
		Short: "Arc Remote Signer service",
		Long:  `arc-remote-signer is a signing service that isolates key operations inside an AWS Nitro Enclave, communicating with the host application over gRPC.`,
		Run: func(_ *cobra.Command, _ []string) {
			// Do stuff here
		},
	}
)

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: config.yaml in . or ./configs)")
}

// Execute is the primary entrypoint for the app.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
