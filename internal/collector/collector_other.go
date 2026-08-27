//go:build !linux

package collector

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/ybbapp/netbpf-exporter/internal/config"
)

type Collector struct{}

func New(config.Config) (*Collector, error) {
	return nil, errors.New("netbpf-exporter requires Linux")
}

func (*Collector) Describe(chan<- *prometheus.Desc) {}
func (*Collector) Collect(chan<- prometheus.Metric) {}
func (*Collector) Close() error                     { return nil }
