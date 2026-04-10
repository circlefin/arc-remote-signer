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
	"bytes"
	"log"
	"strings"

	"github.com/spf13/viper"
	"sigs.k8s.io/yaml"
)

// LoadConfig loads configuration from file and environment variables.
func LoadConfig(cfg ApplicationConfig, cfgFile string) {
	v := viper.New()
	v.SetConfigType("yaml")

	// Marshal struct defaults into Viper first so AutomaticEnv can override
	// any key — including ones absent from the config file.
	// Note: sigs.k8s.io/yaml marshals via encoding/json (json tags or Go field
	// name fallback). Fields with snake_case mapstructure tags but no json tags
	// will be registered under their lowercased Go name (e.g. "myfield" not
	// "my_field"), so env var overrides would not work for such fields when
	// absent from the config file. Current config structs avoid this by using
	// single-word or camelCase field names that match their mapstructure tags
	// after lowercasing.
	b, err := yaml.Marshal(cfg)
	if err != nil {
		log.Fatalf("Unable to marshal default config: %v", err)
	}
	if err := v.MergeConfig(bytes.NewReader(b)); err != nil {
		log.Fatalf("Unable to merge default config: %v", err)
	}

	// Load config file if provided
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("./configs")
	}

	// Merge config file on top of defaults (non-fatal if missing from default paths)
	if err := v.MergeInConfig(); err != nil {
		if _, ok := err.(viper.ConfigParseError); ok {
			log.Fatalf("Unable to parse config file: %v", err)
		}
		if cfgFile != "" {
			log.Printf("Warning: specified config file not found: %v", err)
		}
	}

	// Set environment variable prefix — applied after merging so env vars win
	v.SetEnvPrefix("app")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Unmarshal into config struct
	if err := v.Unmarshal(cfg); err != nil {
		log.Fatalf("Unable to decode config: %v", err)
	}

	log.Printf("Configuration loaded for service: %s", cfg.GetName())
}
