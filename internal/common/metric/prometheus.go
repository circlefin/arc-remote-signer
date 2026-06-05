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

package metric

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Prometheus is a struct that represents a Prometheus instance.
type Prometheus struct {
	registry *prometheus.Registry
	metrics  map[string]prometheus.Collector
}

// PrometheusMetric is a struct that represents a Prometheus metric.
type PrometheusMetric struct {
	Name      string
	Help      string
	Type      string
	Labels    []string
	Collector prometheus.Collector
}

// NewPrometheus creates a new Prometheus instance.
func NewPrometheus() *Prometheus {
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	registry.MustRegister(collectors.NewGoCollector())
	return &Prometheus{
		registry: registry,
		metrics:  make(map[string]prometheus.Collector),
	}
}

// Register registers a new metric with the Prometheus instance.
func (p *Prometheus) Register(metric PrometheusMetric) {
	var collector prometheus.Collector
	switch metric.Type {
	case "counter":
		collector = prometheus.NewCounter(prometheus.CounterOpts{
			Name: metric.Name,
			Help: metric.Help,
		})
	case "counterVec":
		collector = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metric.Name,
			Help: metric.Help,
		}, metric.Labels)
	}

	p.metrics[metric.Name] = collector
	p.registry.MustRegister(collector)
}

// Registry returns the Prometheus registry.
func (p *Prometheus) Registry() *prometheus.Registry {
	return p.registry
}

// Increment increments a counter metric.
func (p *Prometheus) Increment(name string) {
	collector, ok := p.metrics[name]
	if !ok {
		panic(fmt.Sprintf("metric %s not found", name))
	}
	counter, ok := collector.(prometheus.Counter)
	if !ok {
		panic(fmt.Sprintf("metric %s is not a counter", name))
	}
	counter.Add(1)
}

// IncrementLabel increments a counter metric with a label.
func (p *Prometheus) IncrementLabel(name string, label string) {
	collector, ok := p.metrics[name]
	if !ok {
		panic(fmt.Sprintf("metric %s not found", name))
	}
	counter, ok := collector.(*prometheus.CounterVec)
	if !ok {
		panic(fmt.Sprintf("metric %s is not a counterVec", name))
	}
	counter.WithLabelValues(label).Add(1)
}
