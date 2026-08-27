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
./bin/netbpf-exporter
```

Supported variables are `NF_LISTEN_ADDRESS`, `NF_INTERFACES` (comma-separated),
`NF_TOP_N_PEERS`, and `NF_PEER_IDLE_TTL`.
`NF_CONFIG_FILE` optionally supplies the YAML path when `-config.file` is not
set.

```yaml
listen_address: ":9101"
interfaces:
  - eth0
  - eth1
top_n_peers: 500
peer_idle_ttl: 15m
```

`top_n_peers` is ranked globally by unique peer IP. Bytes from all configured
interfaces, protocols, and directions are combined for ranking, so one IP can
occupy only one Top-N slot. Once selected, all of that IP's interface,
protocol, and direction series are exported.

Ranking uses the byte increase since the previous scrape. The exported values
remain cumulative counters from the eBPF map. A peer that has not changed for
`peer_idle_ttl` is deleted from the map and disappears from metrics on the
next scrape.

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
NF_INTERFACES=eth0 ./bin/netbpf-exporter
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
  netbpf-exporter
```

With host networking, `interfaces` names refer to the host network namespace.
Without host networking, the exporter only sees and instruments interfaces in
the container's own network namespace.

Unit tests run without BPF privileges:

```sh
make test
make docker-test
```
