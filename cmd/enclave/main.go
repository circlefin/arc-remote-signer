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

// Package main starts only the enclave service.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	commonConfig "github.com/circlefin/arc-remote-signer/internal/common/config"
	"github.com/circlefin/arc-remote-signer/internal/enclave"
)

type loadConfigFunc func(commonConfig.ApplicationConfig, string)
type runEnclaveFunc func(*enclave.Config) error

func main() {
	if err := run(os.Args[1:], commonConfig.LoadConfig, runConfiguredEnclave); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, loadConfig loadConfigFunc, runEnclave runEnclaveFunc) error {
	flags := flag.NewFlagSet("enclave", flag.ContinueOnError)
	configFile := flags.String("enclave-config", "", "enclave config file")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}

	cfg := enclave.NewConfig()
	loadConfig(cfg, *configFile)
	return runEnclave(cfg)
}
