# netbpf-exporter

`netbpf-exporter` is a standalone Linux Prometheus exporter. It uses eBPF TC
programs on configured network interfaces to count TCP and UDP traffic by
peer IP and direction. It does not include the standard node_exporter
collectors; run it alongside node_exporter when both are needed.

## Configuration

Configuration is environment-first. YAML is optional and can be used as a
base configuration; `NF_*` environment variables always override
the YAML values. The interface list remains a required explicit allowlist.
This is intentional for Docker hosts, where discovering every interface can
create unnecessary TC programs and high-cardinality metrics.

```sh
export NF_LISTEN_ADDRESS=:9101
export NF_INTERFACES=eth0,eth1
export NF_TOP_N_PEERS=500
export NF_PEER_IDLE_TTL=15m
export NF_MIN_PEER_BANDWIDTH=10kb
./bin/netbpf-exporter
```

Supported variables are `NF_LISTEN_ADDRESS`, `NF_INTERFACES` (comma-separated),
`NF_TOP_N_PEERS`, `NF_PEER_IDLE_TTL`, and `NF_MIN_PEER_BANDWIDTH`.
`NF_CONFIG_FILE` optionally supplies the YAML path when `-config.file` is not
set.

```yaml
listen_address: ":9101"
interfaces:
  - eth0
  - eth1
top_n_peers: 500
peer_idle_ttl: 15m
min_peer_bandwidth: 10kb
```

`top_n_peers` is ranked globally by unique peer IP. Bytes from all configured
interfaces, protocols, and directions are combined for ranking, so one IP can
occupy only one Top-N slot. Once selected, all of that IP's interface,
protocol, and direction series are exported.

Ranking uses the byte increase since the previous scrape. The exported values
remain cumulative counters from the eBPF map. A peer that has not changed for
`peer_idle_ttl` is deleted from the map and disappears from metrics on the
next scrape.

`min_peer_bandwidth` defaults to `10kb` and accepts byte-rate values such as
`10kb`, `100mb`, and `1gib`. The value is interpreted as bytes per second even
though `/s` is omitted. `kb`, `mb`, and `gb` use decimal multipliers; `kib`,
`mib`, and `gib` use binary multipliers. Bit units and a `/s` suffix are not
accepted.

The threshold is calculated globally per peer IP across all configured
interfaces, protocols, and directions. Traffic from peers below the threshold
is aggregated under `peer_ip="other"` during each scrape interval. The
`other` series retains `interface`, `protocol`, and `direction` labels and is
not counted as a real peer for `top_n_peers`.

The exporter exposes:

```text
node_network_peer_bytes_total{interface,protocol,peer_ip,direction}
node_network_peer_packets_total{interface,protocol,peer_ip,direction}
```

The TC program uses `src_ip` for ingress/rx and `dst_ip` for egress/tx. It
supports IPv4 and IPv6, and ignores non-TCP/UDP packets. Bytes are the TC skb
length; packets count skbs, so GRO/GSO can make these differ from physical
wire-packet counters.

## Build and run

Linux eBPF objects are generated with `bpf2go`. A Linux build environment needs
clang, LLVM, libbpf headers, and Linux headers:

```sh
make generate
make build
NF_INTERFACES=eth0 NF_MIN_PEER_BANDWIDTH=10kb ./bin/netbpf-exporter
```

`GOPROXY` defaults to `https://proxy.golang.org,direct` and can be changed
for local or Docker builds, for example `make GOPROXY=https://goproxy.cn,direct
docker-build`.

Loading programs requires Linux capabilities for BPF and network
administration. The process must be able to manage TC and eBPF maps, commonly
via root or `CAP_BPF` plus `CAP_NET_ADMIN` (and `CAP_SYS_RESOURCE` on older
kernels).

The Docker image builds the eBPF objects inside a Linux environment:

```sh
docker build -t netbpf-exporter .
docker run --rm --privileged --network host \
  -e NF_INTERFACES=eth0 \
  -e NF_MIN_PEER_BANDWIDTH=10kb \
  netbpf-exporter
```

With host networking, `interfaces` names refer to the host network namespace.
Without host networking, the exporter only sees and instruments interfaces in
the container's own network namespace.

An example Compose file is provided at `docker-compose.yml`. It uses
the public GHCR image and passes configuration through `NF_*` variables:

```sh
NF_INTERFACES=eth0,eth1 docker compose -f docker-compose.yml up -d
docker compose -f docker-compose.yml logs -f
docker compose -f docker-compose.yml down
```

## Grafana

The dashboard example at `grafana/netbpf-exporter-dashboard.json` can be
imported into Grafana with a Prometheus data source. It includes filters for
interface, protocol, direction, and the displayed Top peers count. The
dashboard uses `rate()` over the cumulative exporter counters, so the selected
Prometheus scrape interval should be stable. Its `Period Top Peers` section
uses `increase()` over the selected dashboard time range to rank peers by
total bytes during that period. The peer ranking is shown as a traffic-share
pie chart alongside a table containing the peer label and exact byte total.

Unit tests run without BPF privileges:

```sh
make test
make docker-test
```

## Prometheus DNS Targets

The deployment-local script
`/Users/evlic/docker.data/remotedocker/derper/generate-derp-file-sd.py`
resolves the DERP hostnames and generates Prometheus file-based service
discovery targets for ports 9100 and 9101. The generated targets contain only
`IP:port` values and no hostname label:

```sh
/Users/evlic/docker.data/remotedocker/derper/generate-derp-file-sd.py \
  /etc/prometheus/file_sd/derp.yml
```

Configure Prometheus to watch the generated file:

```yaml
scrape_configs:
  - job_name: derp
    file_sd_configs:
      - files:
          - /etc/prometheus/file_sd/derp.yml
        refresh_interval: 1m
```

Run the script periodically with cron or a systemd timer. Prometheus reloads
the file automatically when its contents change.
