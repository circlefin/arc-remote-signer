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

package awskms

// Config ...
type Config struct {
	Localstack     *LocalstackConfig
	Arns           []string `json:"arns"` // example: arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab
	ConnectTimeout int      `json:"connectTimeout"`
}

// LocalstackConfig represents the configuration for the localstack secrets provider.
type LocalstackConfig struct {
	Enabled  bool
	Endpoint string
	Region   string
}

// NewProviderConfig returns a new Config with defaults.
func NewProviderConfig() *Config {
	return &Config{
		Localstack: &LocalstackConfig{
			Enabled:  true,
			Endpoint: "http://localhost:4566",
			Region:   "us-east-1",
		},
		Arns:           []string{"arn:aws:kms:us-east-1:000000000000:alias/dev-multi-region-crypto", "arn:aws:kms:us-west-2:000000000000:alias/dev-multi-region-crypto"},
		ConnectTimeout: 1500,
	}
}
