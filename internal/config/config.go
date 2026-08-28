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
	DefaultListenAddress             = ":9101"
	DefaultTopN                      = 500
	DefaultPeerIdleTTL               = 15 * time.Minute
	DefaultMinPeerBandwidth ByteRate = 10_000

	EnvConfigFile       = "NF_CONFIG_FILE"
	EnvListenAddress    = "NF_LISTEN_ADDRESS"
	EnvInterfaces       = "NF_INTERFACES"
	EnvTopNPeers        = "NF_TOP_N_PEERS"
	EnvPeerIdleTTL      = "NF_PEER_IDLE_TTL"
	EnvMinPeerBandwidth = "NF_MIN_PEER_BANDWIDTH"
)

type ByteRate uint64

var byteRateUnits = []struct {
	suffix     string
	multiplier uint64
}{
	{suffix: "gib", multiplier: 1 << 30},
	{suffix: "mib", multiplier: 1 << 20},
	{suffix: "kib", multiplier: 1 << 10},
	{suffix: "gb", multiplier: 1_000_000_000},
	{suffix: "mb", multiplier: 1_000_000},
	{suffix: "kb", multiplier: 1_000},
	{suffix: "b", multiplier: 1},
}

type Config struct {
	ListenAddress    string        `yaml:"listen_address"`
	Interfaces       []string      `yaml:"interfaces"`
	TopNPeers        int           `yaml:"top_n_peers"`
	PeerIdleTTL      time.Duration `yaml:"peer_idle_ttl"`
	MinPeerBandwidth ByteRate      `yaml:"min_peer_bandwidth"`
}

func Default() Config {
	return Config{
		ListenAddress:    DefaultListenAddress,
		TopNPeers:        DefaultTopN,
		PeerIdleTTL:      DefaultPeerIdleTTL,
		MinPeerBandwidth: DefaultMinPeerBandwidth,
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
	if value, ok := os.LookupEnv(EnvMinPeerBandwidth); ok {
		bandwidth, err := ParseByteRate(value)
		if err != nil {
			return fmt.Errorf("parse %s: %w", EnvMinPeerBandwidth, err)
		}
		cfg.MinPeerBandwidth = bandwidth
	}
	return nil
}

func ParseByteRate(value string) (ByteRate, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return 0, errors.New("byte rate must not be empty")
	}

	multiplier := uint64(1)
	number := normalized
	for _, unit := range byteRateUnits {
		if strings.HasSuffix(normalized, unit.suffix) {
			number = strings.TrimSuffix(normalized, unit.suffix)
			multiplier = unit.multiplier
			break
		}
	}
	if number == "" {
		return 0, fmt.Errorf("invalid byte rate %q", value)
	}
	for _, char := range number {
		if char < '0' || char > '9' {
			return 0, fmt.Errorf("invalid byte rate %q", value)
		}
	}
	amount, err := strconv.ParseUint(number, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid byte rate %q: %w", value, err)
	}
	if amount > ^uint64(0)/multiplier {
		return 0, fmt.Errorf("byte rate %q overflows uint64", value)
	}
	return ByteRate(amount * multiplier), nil
}

func (r *ByteRate) UnmarshalYAML(value *yaml.Node) error {
	parsed, err := ParseByteRate(value.Value)
	if err != nil {
		return err
	}
	*r = parsed
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
