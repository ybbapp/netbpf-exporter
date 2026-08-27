package peers

import (
	"net/netip"
	"sort"
	"time"
)

const (
	ProtocolTCP = 6
	ProtocolUDP = 17
	DirectionRX = 0
	DirectionTX = 1
)

// Key is the eBPF map key. Ifindex is used in the kernel because interface
// names can change; userspace resolves it to a name when exporting metrics.
type Key struct {
	Ifindex   uint32
	Protocol  uint8
	Direction uint8
	Family    uint8
	Pad       uint8
	Peer      [16]byte
}

type Value struct {
	Bytes   uint64
	Packets uint64
}

type Sample struct {
	Key
	Interface string
	Peer      netip.Addr
	Bytes     uint64
	Packets   uint64
	RankBytes uint64
	LastSeen  time.Time
}

type PeerTotal struct {
	Peer  netip.Addr
	Bytes uint64
}

// SelectTopPeers selects unique peer IPs globally across interfaces, protocols,
// and directions. All samples belonging to selected peers are returned.
func SelectTopPeers(samples []Sample, n int, now time.Time, idleTTL time.Duration) ([]Sample, []Sample) {
	active := make([]Sample, 0, len(samples))
	byPeer := make(map[netip.Addr]uint64)
	for _, sample := range samples {
		if !sample.Peer.IsValid() || sample.LastSeen.IsZero() || now.Sub(sample.LastSeen) >= idleTTL {
			continue
		}
		active = append(active, sample)
		byPeer[sample.Peer] += sample.RankBytes
	}

	totals := make([]PeerTotal, 0, len(byPeer))
	for peer, bytes := range byPeer {
		totals = append(totals, PeerTotal{Peer: peer, Bytes: bytes})
	}
	sort.Slice(totals, func(i, j int) bool {
		if totals[i].Bytes != totals[j].Bytes {
			return totals[i].Bytes > totals[j].Bytes
		}
		return totals[i].Peer.String() < totals[j].Peer.String()
	})
	if n < len(totals) {
		totals = totals[:n]
	}

	selected := make(map[netip.Addr]struct{}, len(totals))
	for _, total := range totals {
		selected[total.Peer] = struct{}{}
	}
	output := make([]Sample, 0, len(active))
	for _, sample := range active {
		if _, ok := selected[sample.Peer]; ok {
			output = append(output, sample)
		}
	}
	sort.Slice(output, func(i, j int) bool {
		if output[i].Interface != output[j].Interface {
			return output[i].Interface < output[j].Interface
		}
		if output[i].Peer != output[j].Peer {
			return output[i].Peer.String() < output[j].Peer.String()
		}
		if output[i].Protocol != output[j].Protocol {
			return output[i].Protocol < output[j].Protocol
		}
		return output[i].Direction < output[j].Direction
	})
	return output, active
}

func ProtocolName(protocol uint8) string {
	switch protocol {
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	default:
		return "unknown"
	}
}

func DirectionName(direction uint8) string {
	if direction == DirectionTX {
		return "tx"
	}
	return "rx"
}
