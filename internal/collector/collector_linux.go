//go:build linux

package collector

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/mdlayher/netlink"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/ybbapp/netbpf-exporter/internal/bpf"
	"github.com/ybbapp/netbpf-exporter/internal/config"
	"github.com/ybbapp/netbpf-exporter/internal/peers"
	"golang.org/x/sys/unix"
)

const (
	filterPriority = 49152
	ingressHandle  = 1
	egressHandle   = 2
)

type attachment struct {
	ifindex    uint32
	qdisc      tc.Object
	ingress    tc.Object
	egress     tc.Object
	addedQdisc bool
}

type otherKey struct {
	Ifindex   uint32
	Protocol  uint8
	Direction uint8
}

type observedSample struct {
	key           peers.Key
	interfaceName string
	peer          netip.Addr
	current       peers.Value
	delta         peers.Value
	lastSeen      time.Time
}

type Collector struct {
	mu sync.Mutex

	objects       bpf.BpfObjects
	objectsLoaded bool
	nodeName      string
	tc            *tc.Tc
	attachments   []attachment
	interfaces    map[uint32]string

	topN             int
	idleTTL          time.Duration
	minPeerBandwidth uint64
	previous         map[peers.Key]peers.Value
	exported         map[peers.Key]peers.Value
	lastSeen         map[peers.Key]time.Time
	other            map[otherKey]peers.Value
	otherSeen        map[otherKey]time.Time
	lastSnapshot     time.Time
	scrapeErr        prometheus.Counter

	bytesDesc   *prometheus.Desc
	packetsDesc *prometheus.Desc
}

func New(cfg config.Config) (*Collector, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	nodeName, err := readNodeName()
	if err != nil {
		return nil, fmt.Errorf("read node name: %w", err)
	}

	c := &Collector{
		interfaces:       make(map[uint32]string, len(cfg.Interfaces)),
		nodeName:         nodeName,
		topN:             cfg.TopNPeers,
		idleTTL:          cfg.PeerIdleTTL,
		minPeerBandwidth: uint64(cfg.MinPeerBandwidth),
		previous:         make(map[peers.Key]peers.Value),
		exported:         make(map[peers.Key]peers.Value),
		lastSeen:         make(map[peers.Key]time.Time),
		other:            make(map[otherKey]peers.Value),
		otherSeen:        make(map[otherKey]time.Time),
		bytesDesc: prometheus.NewDesc(
			"node_network_peer_bytes_total",
			"Total bytes observed for a TCP or UDP peer.",
			[]string{"nodename", "interface", "protocol", "peer_ip", "direction"}, nil,
		),
		packetsDesc: prometheus.NewDesc(
			"node_network_peer_packets_total",
			"Total packets observed for a TCP or UDP peer.",
			[]string{"nodename", "interface", "protocol", "peer_ip", "direction"}, nil,
		),
		scrapeErr: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netbpf_exporter_scrape_errors_total",
			Help: "Total number of peer map scrape errors.",
		}),
	}

	for _, name := range cfg.Interfaces {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("resolve interface %q: %w", name, err)
		}
		c.interfaces[uint32(iface.Index)] = iface.Name
	}

	if err := bpf.LoadBpfObjects(&c.objects, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}
	c.objectsLoaded = true

	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		c.objects.Close()
		return nil, fmt.Errorf("open TC netlink: %w", err)
	}
	c.tc = tcnl
	if err := tcnl.SetOption(netlink.ExtendedAcknowledge, true); err != nil && !errors.Is(err, unix.ENOPROTOOPT) {
		c.Close()
		return nil, fmt.Errorf("enable TC extended acknowledgement: %w", err)
	}

	for ifindex, name := range c.interfaces {
		if err := c.attachInterface(ifindex, name); err != nil {
			c.Close()
			return nil, err
		}
	}

	slog.Info("attached eBPF TC peer collector", "interfaces", cfg.Interfaces, "top_n_peers", cfg.TopNPeers, "peer_idle_ttl", cfg.PeerIdleTTL, "min_peer_bandwidth_bytes_per_second", cfg.MinPeerBandwidth)
	return c, nil
}

func readNodeName() (string, error) {
	var utsname unix.Utsname
	if err := unix.Uname(&utsname); err != nil {
		return "", err
	}
	return unix.ByteSliceToString(utsname.Nodename[:]), nil
}

func (c *Collector) attachInterface(ifindex uint32, name string) error {
	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: ifindex,
			Handle:  core.BuildHandle(tc.HandleRoot, 0),
			Parent:  tc.HandleIngress,
		},
		Attribute: tc.Attribute{Kind: "clsact"},
	}
	addedQdisc, err := c.ensureClsact(ifindex, &qdisc)
	if err != nil {
		return fmt.Errorf("ensure clsact on %s: %w", name, err)
	}

	ingress := makeBPFfilter(ifindex, core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress), ingressHandle, c.objects.NetbpfIngress, "netbpf_ingress")
	if err := c.addOwnedFilter(&ingress, "netbpf_ingress"); err != nil {
		if addedQdisc {
			_ = c.tc.Qdisc().Delete(&qdisc)
		}
		return fmt.Errorf("attach ingress filter on %s: %w", name, err)
	}

	egress := makeBPFfilter(ifindex, core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress), egressHandle, c.objects.NetbpfEgress, "netbpf_egress")
	if err := c.addOwnedFilter(&egress, "netbpf_egress"); err != nil {
		_ = c.tc.Filter().Delete(&ingress)
		if addedQdisc {
			_ = c.tc.Qdisc().Delete(&qdisc)
		}
		return fmt.Errorf("attach egress filter on %s: %w", name, err)
	}

	c.attachments = append(c.attachments, attachment{
		ifindex: ifindex,
		qdisc:   qdisc, ingress: ingress, egress: egress,
		addedQdisc: addedQdisc,
	})
	return nil
}

func (c *Collector) addOwnedFilter(filter *tc.Object, name string) error {
	query := &tc.Msg{
		Family:  filter.Family,
		Ifindex: filter.Ifindex,
		Parent:  filter.Parent,
	}
	filters, err := c.tc.Filter().Get(query)
	if err != nil {
		return fmt.Errorf("list existing %s filters: %w", name, err)
	}
	for _, existing := range filters {
		if existing.Kind != "bpf" || existing.BPF == nil || existing.BPF.Name == nil || *existing.BPF.Name != name {
			continue
		}
		stale := tc.Object{Msg: existing.Msg, Attribute: tc.Attribute{Kind: "bpf"}}
		if err := c.tc.Filter().Delete(&stale); err != nil {
			return fmt.Errorf("remove existing %s filter: %w", name, err)
		}
	}
	return c.tc.Filter().Add(filter)
}

func (c *Collector) ensureClsact(ifindex uint32, qdisc *tc.Object) (bool, error) {
	qdiscs, err := c.tc.Qdisc().Get()
	if err != nil {
		return false, err
	}
	for _, existing := range qdiscs {
		if existing.Ifindex == ifindex && existing.Kind == "clsact" {
			return false, nil
		}
	}
	if err := c.tc.Qdisc().Add(qdisc); err != nil {
		return false, err
	}
	return true, nil
}

func makeBPFfilter(ifindex, parent, handle uint32, program *ebpf.Program, name string) tc.Object {
	fd := uint32(program.FD())
	flags := uint32(tc.BpfActDirect)
	return tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: ifindex,
			Handle:  core.BuildHandle(tc.HandleRoot, handle),
			Parent:  parent,
			Info:    core.FilterInfo(filterPriority, unix.ETH_P_ALL),
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF:  &tc.Bpf{FD: &fd, Flags: &flags, Name: &name},
		},
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.bytesDesc
	ch <- c.packetsDesc
	ch <- c.scrapeErr.Desc()
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()

	samples, err := c.snapshot(time.Now())
	if err != nil {
		slog.Error("read peer map", "err", err)
		c.scrapeErr.Inc()
		ch <- c.scrapeErr
		return
	}
	for _, sample := range samples {
		protocol := peers.ProtocolName(sample.Protocol)
		direction := peers.DirectionName(sample.Direction)
		peerIP := peers.OtherPeerLabel
		if sample.Peer.IsValid() {
			peerIP = sample.Peer.String()
		}
		ch <- prometheus.MustNewConstMetric(c.bytesDesc, prometheus.CounterValue, float64(sample.Bytes), c.nodeName, sample.Interface, protocol, peerIP, direction)
		ch <- prometheus.MustNewConstMetric(c.packetsDesc, prometheus.CounterValue, float64(sample.Packets), c.nodeName, sample.Interface, protocol, peerIP, direction)
	}
	ch <- c.scrapeErr
}

func (c *Collector) snapshot(now time.Time) ([]peers.Sample, error) {
	iterator := c.objects.PeerCounters.Iterate()
	observed := make([]observedSample, 0)
	byKey := make(map[peers.Key]observedSample)
	seen := make(map[peers.Key]struct{})
	expired := make([]peers.Key, 0)
	var key peers.Key
	var values []peers.Value
	for iterator.Next(&key, &values) {
		interfaceName, ok := c.interfaces[key.Ifindex]
		if !ok {
			continue
		}
		peerIP, ok := peerIP(key)
		if !ok {
			continue
		}

		current := sumValues(values)
		previous, hadPrevious := c.previous[key]
		delta := deltaValues(current, previous, hadPrevious)
		changed := !hadPrevious || current != previous
		lastSeen := c.lastSeen[key]
		if !hadPrevious || changed {
			lastSeen = now
		}
		c.previous[key] = current
		c.lastSeen[key] = lastSeen
		seen[key] = struct{}{}

		if now.Sub(lastSeen) >= c.idleTTL {
			expired = append(expired, key)
			continue
		}
		item := observedSample{
			key: key, interfaceName: interfaceName, peer: peerIP,
			current: current, delta: delta, lastSeen: lastSeen,
		}
		observed = append(observed, item)
		byKey[key] = item
	}
	if err := iterator.Err(); err != nil {
		return nil, fmt.Errorf("iterate peer map: %w", err)
	}
	for oldKey := range c.previous {
		if _, ok := seen[oldKey]; !ok {
			delete(c.previous, oldKey)
			delete(c.lastSeen, oldKey)
			delete(c.exported, oldKey)
		}
	}
	for _, oldKey := range expired {
		if err := c.objects.PeerCounters.Delete(&oldKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, fmt.Errorf("delete idle peer from map: %w", err)
		}
		delete(c.previous, oldKey)
		delete(c.lastSeen, oldKey)
		delete(c.exported, oldKey)
	}

	firstSnapshot := c.lastSnapshot.IsZero()
	if firstSnapshot {
		c.lastSnapshot = now
	}
	if c.minPeerBandwidth == 0 {
		samples := make([]peers.Sample, 0, len(observed))
		for _, item := range observed {
			rankBytes := item.delta.Bytes
			if firstSnapshot {
				rankBytes = item.current.Bytes
			}
			samples = append(samples, peers.Sample{
				Key: item.key, Interface: item.interfaceName, Peer: item.peer,
				Bytes: item.current.Bytes, Packets: item.current.Packets,
				RankBytes: rankBytes, LastSeen: item.lastSeen,
			})
		}
		if !firstSnapshot {
			c.lastSnapshot = now
		}
		selected, _ := peers.SelectTopPeers(samples, c.topN, now, c.idleTTL)
		return selected, nil
	}
	if firstSnapshot {
		return nil, nil
	}

	elapsed := now.Sub(c.lastSnapshot)
	windowSamples := make([]peers.Sample, 0, len(observed))
	for _, item := range observed {
		windowSamples = append(windowSamples, peers.Sample{
			Key: item.key, Interface: item.interfaceName, Peer: item.peer,
			RankBytes: item.delta.Bytes, LastSeen: item.lastSeen,
		})
	}
	above, below := peers.SplitByBandwidth(windowSamples, elapsed, c.minPeerBandwidth)
	for _, sample := range below {
		item := byKey[sample.Key]
		if item.delta.Bytes == 0 && item.delta.Packets == 0 {
			continue
		}
		key := otherKey{Ifindex: item.key.Ifindex, Protocol: item.key.Protocol, Direction: item.key.Direction}
		other := c.other[key]
		other.Bytes += item.delta.Bytes
		other.Packets += item.delta.Packets
		c.other[key] = other
		c.otherSeen[key] = now
	}

	highSamples := make([]peers.Sample, 0, len(above))
	for _, sample := range above {
		item := byKey[sample.Key]
		exported := c.exported[item.key]
		exported.Bytes += item.delta.Bytes
		exported.Packets += item.delta.Packets
		c.exported[item.key] = exported
		sample.Bytes = exported.Bytes
		sample.Packets = exported.Packets
		highSamples = append(highSamples, sample)
	}

	selected, _ := peers.SelectTopPeers(highSamples, c.topN, now, c.idleTTL)
	selected = append(selected, c.otherSamples(now)...)
	c.lastSnapshot = now
	return selected, nil
}

func deltaValues(current, previous peers.Value, hadPrevious bool) peers.Value {
	if !hadPrevious {
		return current
	}
	delta := peers.Value{}
	if current.Bytes >= previous.Bytes {
		delta.Bytes = current.Bytes - previous.Bytes
	} else {
		delta.Bytes = current.Bytes
	}
	if current.Packets >= previous.Packets {
		delta.Packets = current.Packets - previous.Packets
	} else {
		delta.Packets = current.Packets
	}
	return delta
}

func (c *Collector) otherSamples(now time.Time) []peers.Sample {
	samples := make([]peers.Sample, 0, len(c.other))
	for key, value := range c.other {
		lastSeen := c.otherSeen[key]
		if lastSeen.IsZero() || now.Sub(lastSeen) >= c.idleTTL {
			delete(c.other, key)
			delete(c.otherSeen, key)
			continue
		}
		samples = append(samples, peers.Sample{
			Key:       peers.Key{Ifindex: key.Ifindex, Protocol: key.Protocol, Direction: key.Direction},
			Interface: c.interfaces[key.Ifindex], Bytes: value.Bytes, Packets: value.Packets,
			Peer: netip.Addr{}, LastSeen: lastSeen,
		})
	}
	return samples
}

func sumValues(values []peers.Value) peers.Value {
	var total peers.Value
	for _, value := range values {
		total.Bytes += value.Bytes
		total.Packets += value.Packets
	}
	return total
}

func peerIP(key peers.Key) (netip.Addr, bool) {
	switch key.Family {
	case unix.AF_INET:
		return netip.AddrFrom4([4]byte{key.Peer[0], key.Peer[1], key.Peer[2], key.Peer[3]}), true
	case unix.AF_INET6:
		return netip.AddrFrom16(key.Peer), true
	default:
		return netip.Addr{}, false
	}
}

func (c *Collector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var closeErr error
	for i := len(c.attachments) - 1; i >= 0; i-- {
		item := c.attachments[i]
		if err := c.tc.Filter().Delete(&item.egress); err != nil && closeErr == nil {
			closeErr = fmt.Errorf("detach egress filter from ifindex %d: %w", item.ifindex, err)
		}
		if err := c.tc.Filter().Delete(&item.ingress); err != nil && closeErr == nil {
			closeErr = fmt.Errorf("detach ingress filter from ifindex %d: %w", item.ifindex, err)
		}
		if item.addedQdisc {
			if err := c.tc.Qdisc().Delete(&item.qdisc); err != nil && closeErr == nil {
				closeErr = fmt.Errorf("delete clsact from ifindex %d: %w", item.ifindex, err)
			}
		}
	}
	c.attachments = nil
	if c.tc != nil {
		if err := c.tc.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
		c.tc = nil
	}
	if c.objectsLoaded {
		if err := c.objects.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
		c.objectsLoaded = false
	}
	return closeErr
}
