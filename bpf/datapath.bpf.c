#include "vmlinux.h"

#include "uapi/linux/if_ether.h"
#include "uapi/linux/ip.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "datapath_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_LAN_PORTS 64
#define MAX_TX_PORTS 128

#ifndef IPPROTO_GRE
#define IPPROTO_GRE 47
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

#define CFG_KEY 0
#define CFG_F_FIB_LOOKUP (1U << 0)

#define GRE_BASE_LEN 4
#define OUTER_ETH_LEN 14
#define OUTER_IP_LEN 20
#define OUTER_HDR_LEN (OUTER_ETH_LEN + OUTER_IP_LEN + GRE_BASE_LEN)

struct tunnel_config {
    __u32 outer_src_ip; /* host byte order */
    __u32 outer_dst_ip; /* host byte order */
    __u8 src_mac[ETH_ALEN];
    __u8 dst_mac[ETH_ALEN];
    __u32 wan_ifindex;
    __u32 flags;
};

struct lan_config {
    __u32 gateway_ip; /* host byte order */
    __u16 inner_mtu;
    __u16 flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tunnel_config);
} tunnel_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_LAN_PORTS);
    __type(key, __u32); /* LAN ifindex */
    __type(value, struct lan_config);
} lan_configs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(max_entries, MAX_TX_PORTS);
    __type(key, __u32);   /* ifindex */
    __type(value, __u32); /* ifindex */
} tx_ports SEC(".maps");

enum stat_id {
    STAT_PASS = 0,
    STAT_DROP,
    STAT_ABORT,
    STAT_ENCAP,
    STAT_DECAP,
    STAT_MTU_DROP,
    STAT_NO_CONFIG,
    STAT_NO_LAN_CONFIG,
    STAT_BYPASS,
    STAT_FIB_SUCCESS,
    STAT_FIB_NO_NEIGH,
    STAT_FIB_FAIL,
    STAT_FIB_WRONG_IF,
    STAT_DECAP_PASS,
    STAT_DECAP_NOT_GRE,
    STAT_DECAP_BAD_GRE,
    STAT_DECAP_SLOW,
    STAT_REDIRECT_WAN,
    STAT_REDIRECT_LAN,
    STAT_MAX,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void
increase_stats_count(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v)
        *v += 1;
}

static __always_inline bool
is_local_lan_route(struct xdp_md *ctx, struct iphdr *iph)
{
    struct bpf_fib_lookup fib = {};

    fib.family = AF_INET;
    fib.tos = iph->tos;
    fib.l4_protocol = iph->protocol;
    fib.tot_len = bpf_ntohs(iph->tot_len);
    fib.ipv4_src = iph->saddr;
    fib.ipv4_dst = iph->daddr;
    fib.ifindex = ctx->ingress_ifindex;

    int ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), 0);
    if (ret != BPF_FIB_LKUP_RET_SUCCESS)
        return false;

    struct lan_config *out_lan = bpf_map_lookup_elem(&lan_configs, &fib.ifindex);
    return out_lan != NULL;
}

static __always_inline struct tunnel_config *
get_tunnel_config(void)
{
    __u32 key = CFG_KEY;
    return bpf_map_lookup_elem(&tunnel_config, &key);
}

static __always_inline struct lan_config *
get_lan_config(__u32 ifindex)
{
    return bpf_map_lookup_elem(&lan_configs, &ifindex);
}

static __always_inline bool
is_local_gateway_dst(const struct lan_config *lan, const struct iphdr *iph)
{
    return lan->gateway_ip && iph->daddr == bpf_htonl(lan->gateway_ip);
}

static __always_inline int
redirect_to_ifindex(__u32 ifindex, __u32 stat)
{
    increase_stats_count(stat);
    return bpf_redirect_map(&tx_ports, ifindex, 0);
}

static __always_inline void
fill_tunnel_fib_params(struct bpf_fib_lookup *fib, const struct tunnel_config *cfg,
                       const struct iphdr *inner_iph, __u16 inner_len,
                       __u32 ingress_ifindex)
{
    fib->family = AF_INET;
    fib->tos = inner_iph->tos;
    fib->l4_protocol = IPPROTO_GRE;
    fib->tot_len = OUTER_IP_LEN + GRE_BASE_LEN + inner_len;
    fib->ipv4_src = bpf_htonl(cfg->outer_src_ip);
    fib->ipv4_dst = bpf_htonl(cfg->outer_dst_ip);
    fib->ifindex = ingress_ifindex;
}

static __always_inline int
lookup_tunnel_nexthop(struct xdp_md *ctx, const struct tunnel_config *cfg,
                      const struct iphdr *inner_iph, __u16 inner_len,
                      struct bpf_fib_lookup *fib)
{
    if (!(cfg->flags & CFG_F_FIB_LOOKUP))
        return 0;

    fill_tunnel_fib_params(fib, cfg, inner_iph, inner_len, ctx->ingress_ifindex);

    int ret = bpf_fib_lookup(ctx, fib, sizeof(*fib), 0);
    if (ret == BPF_FIB_LKUP_RET_SUCCESS) {
        if (cfg->wan_ifindex && fib->ifindex != cfg->wan_ifindex) {
            increase_stats_count(STAT_FIB_WRONG_IF);
            return -1;
        }
        increase_stats_count(STAT_FIB_SUCCESS);
        return 1;
    }

    if (ret == BPF_FIB_LKUP_RET_NO_NEIGH) {
        increase_stats_count(STAT_FIB_NO_NEIGH);
        return -1; /* let kernel slow path resolve neighbor */
    }

    increase_stats_count(STAT_FIB_FAIL);
    return -1; /* fall back to configured static MAC */
}

static __always_inline void
write_outer_eth(struct ethhdr *eth, const struct tunnel_config *cfg,
                const struct bpf_fib_lookup *fib, bool fib_ok)
{
    if (fib_ok) {
        __builtin_memcpy(eth->h_dest, fib->dmac, ETH_ALEN);
        __builtin_memcpy(eth->h_source, fib->smac, ETH_ALEN);
    } else {
        __builtin_memcpy(eth->h_dest, cfg->dst_mac, ETH_ALEN);
        __builtin_memcpy(eth->h_source, cfg->src_mac, ETH_ALEN);
    }
    eth->h_proto = bpf_htons(ETH_P_IP);
}

static __always_inline void
write_outer_ipv4(struct iphdr *outer_iph, const struct tunnel_config *cfg,
                 const struct iphdr *inner_iph, __u16 inner_len)
{
    outer_iph->version = 4;
    outer_iph->ihl = 5;
    outer_iph->tos = inner_iph->tos;
    outer_iph->tot_len = bpf_htons(OUTER_IP_LEN + GRE_BASE_LEN + inner_len);
    outer_iph->id = 0;
    outer_iph->frag_off = bpf_htons(IP_DF);
    outer_iph->ttl = 64;
    outer_iph->protocol = IPPROTO_GRE;
    outer_iph->saddr = bpf_htonl(cfg->outer_src_ip);
    outer_iph->daddr = bpf_htonl(cfg->outer_dst_ip);
    ipv4_checksum(outer_iph);
}

static __always_inline void
write_gre_ipv4(struct gre_hdr_min *gre)
{
    gre->flags = 0;
    gre->proto = bpf_htons(ETH_P_IP);
}

static __always_inline int
parse_ipv4_packet_or_pass(__u8 *data, __u8 *data_end, __u64 *l2_len, struct iphdr **iph,
                          __u32 pass_stat)
{
    int parsed = parse_l2_ipv4(data, data_end, l2_len, iph);
    if (parsed < 0) {
        increase_stats_count(STAT_DROP);
        return XDP_DROP;
    }
    if (parsed == 0) {
        increase_stats_count(pass_stat);
        return XDP_PASS;
    }
    return -1;
}

static __always_inline int
check_dev_mtu(struct xdp_md *ctx, __u32 ifindex, __u32 l3_len)
{
    __u32 mtu_len = l3_len;

    int ret = bpf_check_mtu(ctx, ifindex, &mtu_len, 0, 0);
    if (ret == 0)
        return 0;

    if (ret == BPF_MTU_CHK_RET_FRAG_NEEDED) {
        increase_stats_count(STAT_MTU_DROP);
        return -1;
    }

    increase_stats_count(STAT_ABORT);
    return -1;
}

static __always_inline int
check_wan_mtu(struct xdp_md *ctx, struct tunnel_config *cfg, __u16 inner_len)
{
    return check_dev_mtu(ctx, cfg->wan_ifindex, OUTER_IP_LEN + GRE_BASE_LEN + inner_len);
}

static __always_inline int
check_lan_mtu(struct xdp_md *ctx, __u32 ifindex, __u16 inner_len)
{
    return check_dev_mtu(ctx, ifindex, inner_len);
}

SEC("xdp")
int
xdp_gre_encap(struct xdp_md *ctx)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;

    __u64 l2_len = 0;
    struct iphdr *inner_iph = 0;
    int ret = parse_ipv4_packet_or_pass(data, data_end, &l2_len, &inner_iph, STAT_PASS);
    if (ret != -1)
        return ret;

    struct tunnel_config *cfg = get_tunnel_config();
    if (!cfg) {
        increase_stats_count(STAT_NO_CONFIG);
        return XDP_PASS;
    }

    __u32 ingress_ifindex = ctx->ingress_ifindex;
    struct lan_config *lan = get_lan_config(ingress_ifindex);
    if (!lan) {
        increase_stats_count(STAT_NO_LAN_CONFIG);
        return XDP_PASS;
    }

    if (is_local_gateway_dst(lan, inner_iph) || is_local_lan_route(ctx, inner_iph)) {
        increase_stats_count(STAT_BYPASS);
        return XDP_PASS;
    }

    __u16 inner_len = bpf_ntohs(inner_iph->tot_len);
    if (check_wan_mtu(ctx, cfg, inner_len) < 0)
        return XDP_DROP;

    if (inner_iph->ttl <= 1) {
        increase_stats_count(STAT_PASS);
        return XDP_PASS;
    }

    struct bpf_fib_lookup fib = {};
    int fib_state = lookup_tunnel_nexthop(ctx, cfg, inner_iph, inner_len, &fib);
    if (fib_state < 0)
        return XDP_PASS;
    bool fib_ok = fib_state == 1;

    int delta = (int)l2_len - OUTER_HDR_LEN;
    if (bpf_xdp_adjust_head(ctx, delta) < 0) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    data = (__u8 *)(long)ctx->data;
    data_end = (__u8 *)(long)ctx->data_end;

    struct ethhdr *outer_eth = (struct ethhdr *)data;
    struct iphdr *outer_iph = (struct iphdr *)(data + OUTER_ETH_LEN);
    struct gre_hdr_min *gre = (struct gre_hdr_min *)(data + OUTER_ETH_LEN + OUTER_IP_LEN);
    inner_iph = (struct iphdr *)(data + OUTER_HDR_LEN);

    if ((void *)(inner_iph + 1) > data_end) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }
    if ((void *)inner_iph + inner_len > data_end) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    write_outer_eth(outer_eth, cfg, &fib, fib_ok);
    write_outer_ipv4(outer_iph, cfg, inner_iph, inner_len);
    write_gre_ipv4(gre);

    inner_iph->ttl -= 1;
    ipv4_checksum(inner_iph);

    increase_stats_count(STAT_ENCAP);
    return redirect_to_ifindex(cfg->wan_ifindex, STAT_REDIRECT_WAN);
}

static __always_inline bool
is_expected_gre_peer(const struct tunnel_config *cfg, const struct iphdr *outer_iph)
{
    return outer_iph->daddr == bpf_htonl(cfg->outer_src_ip) &&
           outer_iph->saddr == bpf_htonl(cfg->outer_dst_ip);
}

static __always_inline int
validate_gre_ipv4(__u8 *data_end, const struct iphdr *outer_iph, struct iphdr **inner_out,
                  __u16 *inner_len_out)
{
    __u16 outer_len = bpf_ntohs(outer_iph->tot_len);
    if (outer_len < OUTER_IP_LEN + GRE_BASE_LEN + sizeof(struct iphdr)) {
        increase_stats_count(STAT_DECAP_BAD_GRE);
        return XDP_DROP;
    }

    struct gre_hdr_min *gre = (struct gre_hdr_min *)((__u8 *)outer_iph + OUTER_IP_LEN);
    if ((void *)(gre + 1) > data_end) {
        increase_stats_count(STAT_DECAP_BAD_GRE);
        return XDP_DROP;
    }
    if (gre->flags != 0 || gre->proto != bpf_htons(ETH_P_IP)) {
        increase_stats_count(STAT_DECAP_BAD_GRE);
        return XDP_PASS;
    }

    struct iphdr *inner_iph = (struct iphdr *)((__u8 *)gre + GRE_BASE_LEN);
    if ((void *)(inner_iph + 1) > data_end) {
        increase_stats_count(STAT_DECAP_BAD_GRE);
        return XDP_DROP;
    }
    if (inner_iph->version != 4 || inner_iph->ihl != 5) {
        increase_stats_count(STAT_DECAP_BAD_GRE);
        return XDP_PASS;
    }

    __u16 inner_len = bpf_ntohs(inner_iph->tot_len);
    if (inner_len < sizeof(*inner_iph)) {
        increase_stats_count(STAT_DECAP_BAD_GRE);
        return XDP_DROP;
    }
    if ((void *)inner_iph + inner_len > data_end) {
        increase_stats_count(STAT_DECAP_BAD_GRE);
        return XDP_DROP;
    }

    *inner_out = inner_iph;
    *inner_len_out = inner_len;
    return -1;
}

static __always_inline void
fill_inner_fib_params(struct bpf_fib_lookup *fib, const struct iphdr *inner_iph,
                      __u16 inner_len, __u32 ingress_ifindex)
{
    fib->family = AF_INET;
    fib->tos = inner_iph->tos;
    fib->l4_protocol = inner_iph->protocol;
    fib->tot_len = inner_len;
    fib->ipv4_src = inner_iph->saddr;
    fib->ipv4_dst = inner_iph->daddr;
    fib->ifindex = ingress_ifindex;
}

static __always_inline bool
lookup_lan_nexthop(struct xdp_md *ctx, const struct tunnel_config *cfg,
                   const struct iphdr *inner_iph, __u16 inner_len,
                   struct bpf_fib_lookup *fib)
{
    fill_inner_fib_params(fib, inner_iph, inner_len, ctx->ingress_ifindex);

    int ret = bpf_fib_lookup(ctx, fib, sizeof(*fib), 0);
    if (ret == BPF_FIB_LKUP_RET_SUCCESS) {
        if (fib->ifindex == cfg->wan_ifindex) {
            increase_stats_count(STAT_FIB_WRONG_IF);
            return false;
        }
        if (!get_lan_config(fib->ifindex)) {
            increase_stats_count(STAT_NO_LAN_CONFIG);
            return false;
        }
        increase_stats_count(STAT_FIB_SUCCESS);
        return true;
    }

    if (ret == BPF_FIB_LKUP_RET_NO_NEIGH)
        increase_stats_count(STAT_FIB_NO_NEIGH);
    else
        increase_stats_count(STAT_FIB_FAIL);

    return false;
}

static __always_inline int
finish_decap_slow_path(struct ethhdr *eth, const struct ethhdr *old_eth)
{
    *eth = *old_eth;
    eth->h_proto = bpf_htons(ETH_P_IP);
    increase_stats_count(STAT_DECAP_SLOW);
    return XDP_PASS;
}

SEC("xdp")
int
xdp_gre_decap(struct xdp_md *ctx)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;

    __u64 l2_len = 0;
    struct iphdr *outer_iph = 0;
    int ret =
        parse_ipv4_packet_or_pass(data, data_end, &l2_len, &outer_iph, STAT_DECAP_PASS);
    if (ret != -1)
        return ret;

    if (l2_len != OUTER_ETH_LEN) {
        increase_stats_count(STAT_DECAP_PASS);
        return XDP_PASS;
    }

    struct tunnel_config *cfg = get_tunnel_config();
    if (!cfg) {
        increase_stats_count(STAT_NO_CONFIG);
        return XDP_PASS;
    }

    if (outer_iph->protocol != IPPROTO_GRE) {
        increase_stats_count(STAT_DECAP_NOT_GRE);
        return XDP_PASS;
    }

    if (!is_expected_gre_peer(cfg, outer_iph)) {
        increase_stats_count(STAT_DECAP_PASS);
        return XDP_PASS;
    }

    struct iphdr *inner_iph_pre = 0;
    __u16 inner_len = 0;
    ret = validate_gre_ipv4(data_end, outer_iph, &inner_iph_pre, &inner_len);
    if (ret != -1)
        return ret;

    if (inner_iph_pre->ttl <= 1) {
        increase_stats_count(STAT_DECAP_PASS);
        return XDP_PASS;
    }

    struct ethhdr old_eth = *(struct ethhdr *)data;

    struct bpf_fib_lookup fib = {};
    bool fast = lookup_lan_nexthop(ctx, cfg, inner_iph_pre, inner_len, &fib);

    if (fast) {
        if (check_lan_mtu(ctx, fib.ifindex, inner_len) < 0)
            return XDP_DROP;
    }

    if (bpf_xdp_adjust_head(ctx, OUTER_IP_LEN + GRE_BASE_LEN) < 0) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    data = (__u8 *)(long)ctx->data;
    data_end = (__u8 *)(long)ctx->data_end;

    struct ethhdr *eth = (struct ethhdr *)data;
    struct iphdr *inner_iph = (struct iphdr *)(data + OUTER_ETH_LEN);
    if ((void *)(eth + 1) > data_end) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }
    if ((void *)(inner_iph + 1) > data_end) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }
    if ((void *)inner_iph + inner_len > data_end) {
        increase_stats_count(STAT_ABORT);
        return XDP_ABORTED;
    }

    if (!fast)
        return finish_decap_slow_path(eth, &old_eth);

    __builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);
    eth->h_proto = bpf_htons(ETH_P_IP);

    inner_iph->ttl -= 1;
    ipv4_checksum(inner_iph);

    increase_stats_count(STAT_DECAP);
    return redirect_to_ifindex(fib.ifindex, STAT_REDIRECT_LAN);
}
