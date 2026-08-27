package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/ybbapp/netbpf-exporter/internal/collector"
	"github.com/ybbapp/netbpf-exporter/internal/config"
)

func main() {
	configPath := flag.String("config.file", "", "Optional path to a YAML configuration. NF_* environment variables take precedence.")
	flag.Parse()
	if *configPath == "" {
		*configPath = config.ConfigFilePath()
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("load configuration", "err", err)
		os.Exit(1)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		slog.Error("raise BPF memory limit", "err", err)
		os.Exit(1)
	}

	peerCollector, err := collector.New(cfg)
	if err != nil {
		slog.Error("initialize peer collector", "err", err)
		os.Exit(1)
	}
	defer func() {
		if err := peerCollector.Close(); err != nil {
			slog.Error("close peer collector", "err", err)
		}
	}()

	registry := prometheus.NewRegistry()
	registry.MustRegister(peerCollector)
	registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	registry.MustRegister(prometheus.NewGoCollector())

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("netbpf-exporter\n"))
	})
	server := &http.Server{Addr: cfg.ListenAddress, Handler: mux}

	go func() {
		slog.Info("starting HTTP server", "address", cfg.ListenAddress)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("HTTP server stopped", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		slog.Error("shutdown HTTP server", "err", err)
	}
}
