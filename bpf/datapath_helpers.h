#ifndef __DP_HELPERS__
#define __DP_HELPERS__

#include "vmlinux.h"
#include "uapi/linux/if_ether.h"

#include <sys/cdefs.h>
#include <bpf/bpf_endian.h>

struct vlan_hdr_min {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct gre_hdr_min {
    __be16 flags;
    __be16 proto;
};

static __always_inline __u16
checksum_fold(__u32 csum)
{
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
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

    iph->check = checksum_fold(acc);
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

#endif // __DP_HELPERS__
