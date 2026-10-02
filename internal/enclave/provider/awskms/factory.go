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

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// Factory builds an ephemeral Provider for one Initialize call.
// The runtime selects NewWithAttestation or NewForDevelopment and captures
// configuration via a closure. Tests inject fakes. The ctx is the per-call
// request context so construction-time work observes the caller's deadline.
type Factory func(ctx context.Context, awsCfg aws.Config, arns []string) (Provider, error)
