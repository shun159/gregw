#ifndef __DP_HELPERS__
#define __DP_HELPERS__

#include "vmlinux.h"
#include "uapi/linux/if_ether.h"
#include "uapi/linux/ip.h"

#include <sys/cdefs.h>
#include <bpf/bpf_endian.h>

#ifndef IPPROTO_GRE
#define IPPROTO_GRE 47
#endif

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH 3
#endif

#ifndef ICMP_FRAG_NEEDED
#define ICMP_FRAG_NEEDED 4
#endif

#ifndef GRE_BASE_LEN
#define GRE_BASE_LEN 4
#endif

#ifndef OUTER_ETH_LEN
#define OUTER_ETH_LEN 14
#endif

#ifndef OUTER_IP_LEN
#define OUTER_IP_LEN 20
#endif

#ifndef OUTER_HDR_LEN
#define OUTER_HDR_LEN (OUTER_ETH_LEN + OUTER_IP_LEN + GRE_BASE_LEN)
#endif

#ifndef TUNNEL_L3_OVERHEAD
#define TUNNEL_L3_OVERHEAD (OUTER_IP_LEN + GRE_BASE_LEN)
#endif

#ifndef ICMPV4_MIN_MTU
#define ICMPV4_MIN_MTU 68
#endif

struct vlan_hdr_min {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct gre_hdr_min {
    __be16 flags;
    __be16 proto;
};

struct ipv4_quote {
    struct iphdr iph;
    __u8 data[8];
};

#define ICMP_FRAG_QUOTE_LEN sizeof(struct ipv4_quote)

struct icmp_frag_needed {
    __u8 type;
    __u8 code;
    __u16 checksum;
    __u16 unused;
    __u16 next_mtu;
    struct ipv4_quote quote;
};

#define ICMP_FRAG_REPLY_L3_LEN (OUTER_IP_LEN + sizeof(struct icmp_frag_needed))

static __always_inline __u16
checksum_fold32(__u32 csum)
{
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

static __always_inline __u16
checksum_fold64(__u64 csum)
{
    csum = (csum & 0xffffffffULL) + (csum >> 32);
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

static __always_inline __u16
icmp_checksum(const struct icmp_frag_needed *icmp)
{
    __u32 csum = 0;
    const __u16 *p = (const __u16 *)icmp;

#pragma unroll
    for (int i = 0; i < sizeof(*icmp) / 2; i++)
        csum += (__u32)p[i];

    return checksum_fold32(csum);
}

static __always_inline bool
ipv4_has_df(const struct iphdr *iph)
{
    return (iph->frag_off & bpf_htons(IP_DF)) != 0;
}

static __always_inline void
ipv4_checksum(struct iphdr *iph)
{
    iph->check = 0;

    __u32 acc = 0;
    __u16 *ipw = (__u16 *)iph;

#pragma unroll
    for (int i = 0; i < sizeof(struct iphdr) / 2; i++)
        acc += ipw[i];

    iph->check = checksum_fold32(acc);
}

static __always_inline int
parse_l2_ipv4(void *data, void *data_end, __u64 *l2_len_out, struct iphdr **iph_out)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    __u64 off = sizeof(*eth);
    __be16 proto = eth->h_proto;

#pragma clang loop unroll(full)
    for (int i = 0; i < 2; i++) {
        if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
            struct vlan_hdr_min *vh = data + off;
            if ((void *)(vh + 1) > data_end)
                return -1;
            proto = vh->h_vlan_encapsulated_proto;
            off += sizeof(*vh);
        }
    }

    if (proto != bpf_htons(ETH_P_IP))
        return 0;

    struct iphdr *iph = data + off;
    if ((void *)(iph + 1) > data_end)
        return -1;

    if (iph->version != 4 || iph->ihl != 5)
        return 0;

    __u16 inner_len = bpf_ntohs(iph->tot_len);
    if (inner_len < sizeof(*iph))
        return -1;

    if ((void *)iph + inner_len > data_end)
        return -1;

    *l2_len_out = off;
    *iph_out = iph;
    return 1;
}

static __always_inline void
write_gre_ipv4(struct gre_hdr_min *gre)
{
    gre->flags = 0;
    gre->proto = bpf_htons(ETH_P_IP);
}

static __always_inline void
copy_ipv4_quote(struct ipv4_quote *quote, const struct iphdr *iph)
{
    __builtin_memcpy(quote, iph, sizeof(*quote));
}

static __always_inline void
swap_eth_addrs(struct ethhdr *eth)
{
    __u8 old_src[ETH_ALEN];

    __builtin_memcpy(old_src, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, old_src, ETH_ALEN);
}

static __always_inline void
write_ipv4(struct iphdr *iph, __u8 tos, __u16 tot_len, __u16 frag_off, __u8 ttl,
           __u8 protocol, __u32 src_ip_network_order, __u32 dst_ip_network_order)
{
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = tos;
    iph->tot_len = bpf_htons(tot_len);
    iph->id = 0;
    iph->frag_off = frag_off;
    iph->ttl = ttl;
    iph->protocol = protocol;
    iph->saddr = src_ip_network_order;
    iph->daddr = dst_ip_network_order;
    iph->check = 0;
    ipv4_checksum(iph);
}

static __always_inline void
build_icmp_frag_needed(struct icmp_frag_needed *msg, const struct ipv4_quote *quote,
                       __u16 next_mtu)
{
    __builtin_memset(msg, 0, sizeof(*msg));
    msg->type = ICMP_DEST_UNREACH;
    msg->code = ICMP_FRAG_NEEDED;
    msg->unused = 0;
    msg->next_mtu = bpf_htons(next_mtu);
    msg->quote = *quote;
    msg->checksum = 0;
    msg->checksum = icmp_checksum(msg);
}

static __always_inline void
write_plain_icmp_frag_needed(struct ethhdr *eth, struct iphdr *iph,
                             struct icmp_frag_needed *icmp,
                             const struct ipv4_quote *quote, __u32 icmp_src_ip_host_order,
                             __u16 next_mtu)
{
    struct icmp_frag_needed msg = {};

    swap_eth_addrs(eth);
    write_ipv4(iph, 0, ICMP_FRAG_REPLY_L3_LEN, 0, 64, IPPROTO_ICMP,
               bpf_htonl(icmp_src_ip_host_order), quote->iph.saddr);
    build_icmp_frag_needed(&msg, quote, next_mtu);
    __builtin_memcpy(icmp, &msg, sizeof(msg));
}

static __always_inline void
write_gre_icmp_frag_needed(struct ethhdr *eth, struct iphdr *outer_iph,
                           struct gre_hdr_min *gre, struct iphdr *inner_iph,
                           struct icmp_frag_needed *icmp, const struct ipv4_quote *quote,
                           __u32 outer_src_ip_host_order, __u32 outer_dst_ip_host_order,
                           __u32 icmp_src_ip_host_order, __u16 next_mtu)
{
    struct icmp_frag_needed msg = {};

    swap_eth_addrs(eth);
    eth->h_proto = bpf_htons(ETH_P_IP);

    write_ipv4(outer_iph, 0, TUNNEL_L3_OVERHEAD + ICMP_FRAG_REPLY_L3_LEN,
               bpf_htons(IP_DF), 64, IPPROTO_GRE, bpf_htonl(outer_src_ip_host_order),
               bpf_htonl(outer_dst_ip_host_order));
    write_gre_ipv4(gre);
    write_ipv4(inner_iph, 0, ICMP_FRAG_REPLY_L3_LEN, 0, 64, IPPROTO_ICMP,
               bpf_htonl(icmp_src_ip_host_order), quote->iph.saddr);

    build_icmp_frag_needed(&msg, quote, next_mtu);
    __builtin_memcpy(icmp, &msg, sizeof(msg));
}

#endif // __DP_HELPERS__
