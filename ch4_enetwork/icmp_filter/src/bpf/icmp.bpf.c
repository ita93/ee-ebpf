#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_TYPE     12 // EtherType
#define ETH_HLEN     14 // ETH header length 
#define ICMP_LEN     34 // ICMP header start point
#define ETH_P_IP     0x0800 // Internet Protocol packet
#define IPPROTO_ICMP 1 // Echo request

char _license[] SEC("license") = "GPL";

SEC("socket")
int icmp_filter_prog(struct __sk_buff *skb)
{
	__u16 eth_proto = 0;

	if (bpf_skb_load_bytes(skb, ETH_TYPE, &eth_proto,
     		sizeof(eth_proto)) < 0)
		return 0;

	eth_proto = bpf_ntohs(eth_proto);
	if (eth_proto != ETH_P_IP) {
		return 0;
	}

	__u8 ip_version = 0;
	if (bpf_skb_load_bytes(skb, ETH_HLEN,&ip_version,
     		sizeof(ip_version)) < 0)
		return 0;

	ip_version = ip_version >> 4;
	if (ip_version != 4) {
		return 0;
	}
	
	__u8 ip_proto = 0;
	if (bpf_skb_load_bytes(skb, ETH_HLEN + 9, &ip_proto,
     		sizeof(ip_proto)) < 0)
		return 0;
	if (ip_proto != IPPROTO_ICMP) {
		return 0;
	}

	__u8 icmp_type = 0;
	if (bpf_skb_load_bytes(skb, ICMP_LEN, &icmp_type, sizeof(icmp_type)) < 0)
		return 0;

	if (icmp_type != 8) {
		return 0;
	}

	return skb->len;
}
