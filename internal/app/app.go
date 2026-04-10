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

// Package app contains the source code for the app service.
package app

import (
	"context"
	"fmt"

	"github.com/circlefin/arc-remote-signer/internal/app/provider/awskms"
	enclaveProvider "github.com/circlefin/arc-remote-signer/internal/app/provider/enclave"
	"github.com/circlefin/arc-remote-signer/internal/app/provider/secrets"
	"github.com/circlefin/arc-remote-signer/internal/app/public"
	"github.com/circlefin/arc-remote-signer/internal/app/service/signer"
	"github.com/circlefin/arc-remote-signer/internal/common/lifecycle"
	"github.com/circlefin/arc-remote-signer/internal/common/logging"
	"github.com/circlefin/arc-remote-signer/internal/common/metric"
	"github.com/circlefin/arc-remote-signer/internal/common/telemetry"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"gopkg.in/DataDog/dd-trace-go.v1/profiler"
)

type metricProviders struct {
	stats metric.StatsService
	api   metric.APIStatsService
}

var _logger *logging.Logger

func getLogger() *logging.Logger {
	if _logger != nil {
		return _logger
	}
	_logger = logging.Get("nitro-enclave-signer")
	return _logger
}

// Run the application.
func Run(cfg *Config) {
	ctx := context.Background()
	logger := getLogger()

	// setting up tracer before DB and client libraries as it modifies trace provider which is a global singleton
	cleanUpTracer, err := telemetry.InitTracer(cfg.GetName(), *cfg.Telemetry)
	if err != nil {
		logger.ErrorErr(ctx, "failed to initialize tracer", err, nil)
		panic(err)
	}
	defer cleanUpTracer()

	// Enable profiling based on flag
	if cfg.Profiler.Enabled {
		err := profiler.Start(
			profiler.WithProfileTypes(
				profiler.CPUProfile,
				profiler.HeapProfile,
				profiler.GoroutineProfile,
				profiler.MutexProfile,
			),
		)
		if err != nil {
			logger.Error(ctx, "failed enable the profiler", logging.Entries{"error": err})
			panic(err)
		}
		defer profiler.Stop()
	} else {
		logger.Info(ctx, "Profiler is not enabled", nil)
	}

	logger.Info(ctx, "initializing the providers...", nil)
	enclavePvd, conn, err := enclaveProvider.New(cfg.Provider.Enclave)
	if err != nil {
		logger.ErrorErr(ctx, "failed to initialize the enclave provider", err, nil)
		panic(err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			logger.ErrorErr(ctx, "failed to close enclave connection", err, nil)
		}
	}()

	logger.Info(ctx, "getting the attestation document from the enclave...", nil)
	attestationDocument, err := getAttestationDocument(ctx, enclavePvd, cfg)
	if err != nil {
		logger.ErrorErr(ctx, "failed to get attestation document", err, nil)
		panic(err)
	}

	logger.Info(ctx, "initializing the AWS providers...", nil)
	awsConfig, err := retrieveAWSConfig(ctx, cfg, getLogger())
	if err != nil {
		logger.ErrorErr(ctx, "failed to retrieve the AWS config", err, nil)
		panic(err)
	}
	secretPvd := secrets.New(awsConfig)
	awskmsPvd, err := awskms.New(ctx, cfg.Provider.AWSKMS, awsConfig, attestationDocument)
	if err != nil {
		logger.ErrorErr(ctx, "failed to initialize the aws kms provider", err, nil)
		panic(err)
	}

	logger.Info(ctx, "initializing the services...", nil)
	signerSvc, err := signer.New(ctx, cfg.Provider.Enclave.NitroEnclave.Enabled, cfg.Service.Signer, secretPvd, enclavePvd, awskmsPvd)
	if err != nil {
		logger.ErrorErr(ctx, "failed to initialize the signer service", err, nil)
		panic(err)
	}

	logger.Info(ctx, "initializing the metric services...", nil)
	// init metrics here
	appMetricProviders := initializeMetricsProviders(ctx, cfg.Metrics)

	lc := lifecycle.NewManager()

	logger.Info(ctx, "initializing the server...", nil)
	publicServer, err := public.New(cfg.Public.Server, public.CreateServerParams{
		ServiceName: cfg.GetName(),
		Env:         cfg.Env,
		APIStatsSvc: appMetricProviders.api,
		SignerSvc:   signerSvc,
	})
	if err != nil {
		logger.ErrorErr(ctx, "failed to initialize the public server", err, nil)
		panic(err)
	}

	lc.Manage(publicServer)

	logger.Info(ctx, "run all runnable", nil)
	lc.Run()
}

func initializeMetricsProviders(ctx context.Context, metricsCfg *metric.Config) metricProviders {
	if metricsCfg == nil {
		panic("metrics config unavailable")
	}

	statsService, err := metric.NewDatadogStatsD(metricsCfg.Statsd)
	if err != nil {
		getLogger().Error(ctx, "failed to initialize the metric service", logging.Entries{"error": err})
		panic(err)
	}

	return metricProviders{
		stats: statsService,
		api:   metric.NewAPIStatsServiceImpl(statsService, metric.WithDistributionsOption(metric.DistributionsEnabled)),
	}
}

func getAttestationDocument(ctx context.Context, enclavePvd pb.EnclaveServiceClient, cfg *Config) ([]byte, error) {
	if cfg.Provider.Enclave.NitroEnclave.Enabled {
		resp, err := enclavePvd.GetAttestation(ctx, &pb.GetAttestationRequest{})
		if err != nil {
			return nil, fmt.Errorf("failed to get attestation document: %w", err)
		}
		return resp.AttestationDocument, nil
	}
	return nil, nil
}
