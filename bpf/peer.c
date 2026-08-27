//go:build linux

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct peer_key {
	__u32 ifindex;
	__u8 protocol;
	__u8 direction;
	__u8 family;
	__u8 pad;
	__u8 peer[16];
};

struct peer_value {
	__u64 bytes;
	__u64 packets;
};

struct netbpf_vlan_hdr {
	__be16 tci;
	__be16 encapsulated_proto;
};

#define NETBPF_AF_INET 2
#define NETBPF_AF_INET6 10

struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct peer_key);
	__type(value, struct peer_value);
} peer_counters SEC(".maps");

static __always_inline int account_packet(struct __sk_buff *skb, __u8 direction)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	__u16 eth_proto;
	__u32 offset = sizeof(*eth);
	__u8 protocol;
	__u8 family;
	__u8 peer[16] = {};
	struct peer_key key = {};
	struct peer_value *value;

	if (data + sizeof(*eth) > data_end)
		return TC_ACT_OK;

	eth_proto = bpf_ntohs(eth->h_proto);
#pragma unroll
	for (int i = 0; i < 2; i++) {
		if (eth_proto != ETH_P_8021Q && eth_proto != ETH_P_8021AD)
			break;
		struct netbpf_vlan_hdr *vlan = data + offset;
		if (data + offset + sizeof(*vlan) > data_end)
			return TC_ACT_OK;
		eth_proto = bpf_ntohs(vlan->encapsulated_proto);
		offset += sizeof(*vlan);
	}

	if (eth_proto == ETH_P_IP) {
		struct iphdr *iph = data + offset;
		__u32 ip_header_len;

		if (data + offset + sizeof(*iph) > data_end)
			return TC_ACT_OK;
		ip_header_len = (__u32)iph->ihl * 4;
		if (ip_header_len < sizeof(*iph) || data + offset + ip_header_len > data_end)
			return TC_ACT_OK;
		protocol = iph->protocol;
		family = NETBPF_AF_INET;
		__builtin_memcpy(peer, direction == 0 ? &iph->saddr : &iph->daddr, 4);
	} else if (eth_proto == ETH_P_IPV6) {
		struct ipv6hdr *ip6h = data + offset;

		if (data + offset + sizeof(*ip6h) > data_end)
			return TC_ACT_OK;
		protocol = ip6h->nexthdr;
		family = NETBPF_AF_INET6;
		__builtin_memcpy(peer, direction == 0 ? &ip6h->saddr : &ip6h->daddr, 16);
	} else {
		return TC_ACT_OK;
	}

	if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
		return TC_ACT_OK;

	key.ifindex = skb->ifindex;
	key.protocol = protocol;
	key.direction = direction;
	key.family = family;
	__builtin_memcpy(key.peer, peer, sizeof(key.peer));

	value = bpf_map_lookup_elem(&peer_counters, &key);
	if (!value) {
		struct peer_value initial = {
			.bytes = skb->len,
			.packets = 1,
		};
		bpf_map_update_elem(&peer_counters, &key, &initial, BPF_ANY);
		return TC_ACT_OK;
	}
	value->bytes += skb->len;
	value->packets++;
	return TC_ACT_OK;
}

SEC("tc")
int netbpf_ingress(struct __sk_buff *skb)
{
	return account_packet(skb, 0);
}

SEC("tc")
int netbpf_egress(struct __sk_buff *skb)
{
	return account_packet(skb, 1);
}

char LICENSE[] SEC("license") = "GPL";
