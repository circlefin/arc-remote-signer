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

// Package config provides configuration types for the application.
package config

// Environment represents the deployment environment.
type Environment string

const (
	// Dev is the development environment.
	Dev Environment = "dev"
	// QA is the quality assurance environment.
	QA Environment = "qa"
	// Stg is the stg environment.
	Stg Environment = "stg"
	// Prod is the production environment.
	Prod Environment = "prod"
)
