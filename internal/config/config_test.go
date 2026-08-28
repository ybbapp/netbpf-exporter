package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDurationAndInterfaceAllowlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte("listen_address: ':9200'\ninterfaces: [eth0, eth1]\ntop_n_peers: 7\npeer_idle_ttl: 15m\nmin_peer_bandwidth: 20kb\n")
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddress != ":9200" || cfg.TopNPeers != 7 || cfg.PeerIdleTTL != 15*time.Minute || cfg.MinPeerBandwidth != 20_000 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if len(cfg.Interfaces) != 2 || cfg.Interfaces[0] != "eth0" || cfg.Interfaces[1] != "eth1" {
		t.Fatalf("unexpected interfaces: %v", cfg.Interfaces)
	}
}

func TestValidateRequiresExplicitInterfaces(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an explicit interface allowlist to be required")
	}
}

func TestEnvironmentOverridesYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte("listen_address: ':9200'\ninterfaces: [eth0]\ntop_n_peers: 7\npeer_idle_ttl: 15m\n")
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv(EnvListenAddress, ":9300")
	t.Setenv(EnvInterfaces, "eth2, eth3")
	t.Setenv(EnvTopNPeers, "11")
	t.Setenv(EnvPeerIdleTTL, "30m")
	t.Setenv(EnvMinPeerBandwidth, "100mb")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddress != ":9300" || cfg.TopNPeers != 11 || cfg.PeerIdleTTL != 30*time.Minute || cfg.MinPeerBandwidth != 100_000_000 {
		t.Fatalf("environment did not override YAML: %+v", cfg)
	}
	if len(cfg.Interfaces) != 2 || cfg.Interfaces[0] != "eth2" || cfg.Interfaces[1] != "eth3" {
		t.Fatalf("environment interfaces were not applied: %v", cfg.Interfaces)
	}
}

func TestYAMLIsOptionalWithEnvironment(t *testing.T) {
	t.Setenv(EnvInterfaces, "eth0")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddress != DefaultListenAddress || len(cfg.Interfaces) != 1 || cfg.Interfaces[0] != "eth0" || cfg.MinPeerBandwidth != DefaultMinPeerBandwidth {
		t.Fatalf("unexpected config without YAML: %+v", cfg)
	}
}

func TestInvalidEnvironmentValue(t *testing.T) {
	t.Setenv(EnvInterfaces, "eth0")
	t.Setenv(EnvTopNPeers, "not-a-number")
	if _, err := Load(""); err == nil {
		t.Fatal("expected invalid environment value to fail")
	}
}

func TestParseByteRate(t *testing.T) {
	tests := map[string]ByteRate{
		"100b":  100,
		"100kb": 100_000,
		"100MB": 100_000_000,
		"1gib":  1 << 30,
		"0":     0,
	}
	for input, want := range tests {
		got, err := ParseByteRate(input)
		if err != nil {
			t.Fatalf("ParseByteRate(%q): %v", input, err)
		}
		if got != want {
			t.Errorf("ParseByteRate(%q) = %d, want %d", input, got, want)
		}
	}
	for _, input := range []string{"100kb/s", "100kbit", "1.5mb", "-1kb", ""} {
		if _, err := ParseByteRate(input); err == nil {
			t.Errorf("ParseByteRate(%q) succeeded, want error", input)
		}
	}
}
