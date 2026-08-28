package peers

import (
	"net/netip"
	"testing"
	"time"
)

func TestSelectTopPeersDeduplicatesIPGlobally(t *testing.T) {
	now := time.Unix(100, 0)
	peerA := netip.MustParseAddr("192.0.2.1")
	peerB := netip.MustParseAddr("192.0.2.2")
	samples := []Sample{
		{Key: Key{Ifindex: 1, Protocol: ProtocolTCP, Direction: DirectionRX}, Interface: "eth0", Peer: peerA, Bytes: 60, RankBytes: 60, LastSeen: now},
		{Key: Key{Ifindex: 1, Protocol: ProtocolTCP, Direction: DirectionTX}, Interface: "eth0", Peer: peerA, Bytes: 50, RankBytes: 50, LastSeen: now},
		{Key: Key{Ifindex: 2, Protocol: ProtocolUDP, Direction: DirectionRX}, Interface: "eth1", Peer: peerA, Bytes: 40, RankBytes: 40, LastSeen: now},
		{Key: Key{Ifindex: 1, Protocol: ProtocolUDP, Direction: DirectionRX}, Interface: "eth0", Peer: peerB, Bytes: 100, RankBytes: 100, LastSeen: now},
	}

	selected, _ := SelectTopPeers(samples, 1, now, time.Minute)
	if len(selected) != 3 {
		t.Fatalf("selected %d samples, want all 3 samples for one peer", len(selected))
	}
	for _, sample := range selected {
		if sample.Peer != peerA {
			t.Fatalf("selected peer %s, want %s", sample.Peer, peerA)
		}
	}
}

func TestSelectTopPeersDropsIdleSamples(t *testing.T) {
	now := time.Unix(100, 0)
	samples := []Sample{
		{Key: Key{Protocol: ProtocolTCP, Direction: DirectionRX}, Peer: netip.MustParseAddr("192.0.2.1"), Bytes: 1, LastSeen: now.Add(-time.Minute)},
		{Key: Key{Protocol: ProtocolUDP, Direction: DirectionRX}, Peer: netip.MustParseAddr("192.0.2.2"), Bytes: 2, LastSeen: now.Add(-time.Second)},
	}

	selected, active := SelectTopPeers(samples, 10, now, time.Minute)
	if len(active) != 1 || len(selected) != 1 || selected[0].Peer.String() != "192.0.2.2" {
		t.Fatalf("got selected=%v active=%v, want only recent sample", selected, active)
	}
}

func TestSelectTopPeersRanksByRefreshBytes(t *testing.T) {
	now := time.Unix(100, 0)
	samples := []Sample{
		{Key: Key{Protocol: ProtocolTCP, Direction: DirectionRX}, Peer: netip.MustParseAddr("192.0.2.1"), Bytes: 1000, RankBytes: 10, LastSeen: now},
		{Key: Key{Protocol: ProtocolTCP, Direction: DirectionRX}, Peer: netip.MustParseAddr("192.0.2.2"), Bytes: 20, RankBytes: 20, LastSeen: now},
	}

	selected, _ := SelectTopPeers(samples, 1, now, time.Minute)
	if len(selected) != 1 || selected[0].Peer.String() != "192.0.2.2" {
		t.Fatalf("got selected=%v, want peer 192.0.2.2 by refresh bytes", selected)
	}
}

func TestSplitByBandwidthAggregatesPeerIPGlobally(t *testing.T) {
	now := time.Unix(100, 0)
	peerA := netip.MustParseAddr("192.0.2.1")
	peerB := netip.MustParseAddr("192.0.2.2")
	samples := []Sample{
		{Key: Key{Ifindex: 1, Protocol: ProtocolTCP, Direction: DirectionRX}, Peer: peerA, RankBytes: 60, LastSeen: now},
		{Key: Key{Ifindex: 2, Protocol: ProtocolUDP, Direction: DirectionTX}, Peer: peerA, RankBytes: 50, LastSeen: now},
		{Key: Key{Ifindex: 1, Protocol: ProtocolTCP, Direction: DirectionRX}, Peer: peerB, RankBytes: 99, LastSeen: now},
	}

	above, below := SplitByBandwidth(samples, time.Second, 100)
	if len(above) != 2 || len(below) != 1 || above[0].Peer != peerA || above[1].Peer != peerA || below[0].Peer != peerB {
		t.Fatalf("got above=%v below=%v, want peer A above and peer B below", above, below)
	}
}

func TestProtocolAndDirectionNames(t *testing.T) {
	if got := ProtocolName(ProtocolTCP); got != "tcp" {
		t.Fatalf("protocol name = %q", got)
	}
	if got := DirectionName(DirectionTX); got != "tx" {
		t.Fatalf("direction name = %q", got)
	}
}
