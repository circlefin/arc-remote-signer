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

package client

import "google.golang.org/grpc/codes"

const (
	defaultRequestTimeoutMS = 5000
	defaultMaxAttempts      = 1
)

var defaultRetryCodes = []codes.Code{
	codes.Unavailable,
	codes.DeadlineExceeded,
	codes.Internal,
}

// Config contains outbound gRPC settings.
type Config struct {
	Name             string
	BaseURL          string
	RequestTimeoutMS int
	Retry            *RetryConfig
}

// RetryConfig contains outbound gRPC retry settings.
type RetryConfig struct {
	MaxAttempts uint
	RetryCodes  []codes.Code
}

// NewClientConfig creates a gRPC client config with sane defaults.
func NewClientConfig(name, baseURL string) *Config {
	return &Config{
		Name:             name,
		BaseURL:          baseURL,
		RequestTimeoutMS: defaultRequestTimeoutMS,
		Retry: &RetryConfig{
			MaxAttempts: defaultMaxAttempts,
			RetryCodes:  append([]codes.Code(nil), defaultRetryCodes...),
		},
	}
}
