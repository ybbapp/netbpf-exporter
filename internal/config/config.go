package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultListenAddress = ":9101"
	DefaultTopN          = 500
	DefaultPeerIdleTTL   = 15 * time.Minute

	EnvConfigFile    = "NF_CONFIG_FILE"
	EnvListenAddress = "NF_LISTEN_ADDRESS"
	EnvInterfaces    = "NF_INTERFACES"
	EnvTopNPeers     = "NF_TOP_N_PEERS"
	EnvPeerIdleTTL   = "NF_PEER_IDLE_TTL"
)

type Config struct {
	ListenAddress string        `yaml:"listen_address"`
	Interfaces    []string      `yaml:"interfaces"`
	TopNPeers     int           `yaml:"top_n_peers"`
	PeerIdleTTL   time.Duration `yaml:"peer_idle_ttl"`
}

func Default() Config {
	return Config{
		ListenAddress: DefaultListenAddress,
		TopNPeers:     DefaultTopN,
		PeerIdleTTL:   DefaultPeerIdleTTL,
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			return cfg, fmt.Errorf("parse config: %w", err)
		}
	}
	if err := applyEnvironment(&cfg); err != nil {
		return cfg, err
	}
	for i := range cfg.Interfaces {
		cfg.Interfaces[i] = strings.TrimSpace(cfg.Interfaces[i])
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// ConfigFilePath returns the optional YAML path from the environment.
func ConfigFilePath() string {
	return os.Getenv(EnvConfigFile)
}

func applyEnvironment(cfg *Config) error {
	if value, ok := os.LookupEnv(EnvListenAddress); ok {
		cfg.ListenAddress = value
	}
	if value, ok := os.LookupEnv(EnvInterfaces); ok {
		cfg.Interfaces = strings.Split(value, ",")
	}
	if value, ok := os.LookupEnv(EnvTopNPeers); ok {
		topN, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("parse %s: %w", EnvTopNPeers, err)
		}
		cfg.TopNPeers = topN
	}
	if value, ok := os.LookupEnv(EnvPeerIdleTTL); ok {
		ttl, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("parse %s: %w", EnvPeerIdleTTL, err)
		}
		cfg.PeerIdleTTL = ttl
	}
	return nil
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.ListenAddress) == "" {
		return errors.New("listen_address must not be empty")
	}
	if len(c.Interfaces) == 0 {
		return errors.New("interfaces must contain at least one interface")
	}
	seen := make(map[string]struct{}, len(c.Interfaces))
	for _, name := range c.Interfaces {
		name = strings.TrimSpace(name)
		if name == "" {
			return errors.New("interfaces must not contain an empty name")
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("duplicate interface %q", name)
		}
		seen[name] = struct{}{}
	}
	if c.TopNPeers <= 0 {
		return errors.New("top_n_peers must be greater than zero")
	}
	if c.PeerIdleTTL <= 0 {
		return errors.New("peer_idle_ttl must be greater than zero")
	}
	return nil
}
