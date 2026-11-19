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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/circlefin/arc-remote-signer/internal/app/metrics"
	enclaveProvider "github.com/circlefin/arc-remote-signer/internal/app/provider/enclave"
	"github.com/circlefin/arc-remote-signer/internal/app/provider/secrets"
	"github.com/circlefin/arc-remote-signer/internal/app/public"
	watermarkrepository "github.com/circlefin/arc-remote-signer/internal/app/repository/watermark"
	signerv1 "github.com/circlefin/arc-remote-signer/internal/app/service/signer/v1"
	signerv2service "github.com/circlefin/arc-remote-signer/internal/app/service/signer/v2"
	"github.com/circlefin/arc-remote-signer/internal/common/lifecycle"
	"github.com/circlefin/arc-remote-signer/internal/common/logging"
	"github.com/circlefin/arc-remote-signer/internal/common/metric"
	"github.com/circlefin/arc-remote-signer/internal/common/telemetry"
	"github.com/circlefin/arc-remote-signer/internal/common/watermark"
	"github.com/circlefin/arc-remote-signer/proto/pb"
	"gopkg.in/DataDog/dd-trace-go.v1/profiler"
)

type metricProviders struct {
	stats      metric.StatsService
	api        metric.APIStatsService
	prometheus *metric.Prometheus
}

type watermarkRepositoryFactory func(aws.Config, []byte) (watermark.OwnedAdvancer, error)

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
	applyBuildPolicy(cfg)
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
	enclavePvd, conn, err := newRuntimeEnclave(cfg.Provider.Enclave)
	if err != nil {
		logger.ErrorErr(ctx, "failed to initialize the enclave provider", err, nil)
		panic(err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			logger.ErrorErr(ctx, "failed to close enclave connection", err, nil)
		}
	}()

	logger.Info(ctx, "initializing the AWS providers...", nil)
	awsConfig, err := loadRuntimeAWSConfig(ctx, cfg, getLogger())
	if err != nil {
		logger.ErrorErr(ctx, "failed to retrieve the AWS config", err, nil)
		panic(err)
	}

	// The host reads Secrets Manager before it initializes the enclave. The
	// stored envelope or configured algorithm selects the initialization path.
	secretPvd := secrets.New(awsConfig)

	logger.Info(ctx, "initializing the services...", nil)
	initializeKey := newInitializeKeyFunc(
		cfg.Provider.Enclave,
		enclavePvd,
		awsConfig,
		cfg.Provider.AWSKMS.Arns,
		cfg.Provider.AWSKMS.Localstack.Enabled,
		logger,
	)
	signerSvc, err := signerv1.New(
		ctx,
		cfg.Service.Signer,
		secretPvd,
		enclavePvd,
		initializeKey,
	)
	if err != nil {
		logger.ErrorErr(ctx, "failed to initialize the signer service", err, nil)
		panic(err)
	}
	validatorPublicKey, err := signerSvc.ValidatorPublicKey()
	if err != nil {
		logger.ErrorErr(ctx, "failed to get the validator public key", err, nil)
		panic(err)
	}
	signerV2Svc, err := newSignerV2Service(
		signerSvc,
		awsConfig,
		validatorPublicKey,
		newWatermarkRepository,
	)
	if err != nil {
		logger.ErrorErr(ctx, "failed to initialize the signer v2 service", err, nil)
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
		SignerV2Svc: signerV2Svc,
		Prometheus:  appMetricProviders.prometheus,
	})
	if err != nil {
		logger.ErrorErr(ctx, "failed to initialize the public server", err, nil)
		panic(err)
	}

	lc.Manage(publicServer)

	metricsServer, err := metrics.New(cfg.Metrics, appMetricProviders.prometheus)
	if err != nil {
		logger.ErrorErr(ctx, "failed to initialize the metrics server", err, nil)
		panic(err)
	}
	if metricsServer != nil {
		lc.Manage(metricsServer)
	}

	logger.Info(ctx, "run all runnable", nil)
	lc.Run()
}

func newInitializeKeyFunc(
	enclaveCfg *enclaveProvider.ProviderConfig,
	enclavePvd pb.EnclaveServiceClient,
	awsConfig aws.Config,
	kmsKeyArns []string,
	kmsLocalstackEnabled bool,
	logger *logging.Logger,
) signerv1.InitializeKeyFunc {
	return func(
		ctx context.Context,
		existingKey *pb.SecretEnvelope,
		generateNew pb.Algorithm,
	) (*pb.InitializeResponse, error) {
		initCtx, cancel := context.WithTimeout(ctx, enclaveCfg.StartupTimeout())
		defer cancel()

		logger.Info(initCtx, "initializing the enclave via Initialize RPC...", nil)
		return initializeEnclave(
			initCtx,
			enclavePvd,
			awsConfig,
			kmsKeyArns,
			kmsLocalstackEnabled,
			enclaveKeySource{
				existingKey: existingKey,
				generateNew: generateNew,
			},
			logger,
		)
	}
}

func newWatermarkRepository(cfg aws.Config, validatorPublicKey []byte) (watermark.OwnedAdvancer, error) {
	return watermarkrepository.New(cfg, validatorPublicKey)
}

func newSignerV2Service(
	base signerv2service.BaseSigner,
	awsConfig aws.Config,
	validatorPublicKey []byte,
	repositoryFactory watermarkRepositoryFactory,
) (*signerv2service.Service, error) {
	repository, err := repositoryFactory(awsConfig, validatorPublicKey)
	if err != nil {
		return nil, fmt.Errorf("create watermark repository: %w", err)
	}
	service, err := signerv2service.New(base, repository)
	if err != nil {
		return nil, fmt.Errorf("create signer v2 service: %w", err)
	}
	return service, nil
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

	var prometheusProvider *metric.Prometheus
	if metricsCfg.IsPrometheusEnabled() {
		prometheusProvider = metric.NewPrometheus()
	}

	return metricProviders{
		stats:      statsService,
		api:        metric.NewAPIStatsServiceImpl(statsService, metric.WithDistributionsOption(metric.DistributionsEnabled)),
		prometheus: prometheusProvider,
	}
}
