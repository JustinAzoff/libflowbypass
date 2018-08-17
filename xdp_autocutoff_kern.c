/*  XDP example of parsing TTL value of IP-header.
 *
 *  Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/if_vlan.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/tcp.h>
#include "bpf_helpers.h"

struct flowv4_keys {
    __u32 src;
    __u32 dst;
    union {
        __u32 ports;
        __u16 port16[2];
    };
    __u32 ip_proto;
} __attribute__((__aligned__(8)));

struct pair {
    __u64 time;
    __u64 packets;
    __u64 bytes;
} __attribute__((__aligned__(8)));

struct bpf_map_def SEC("maps") flow_table_v4 = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(struct flowv4_keys),
    .value_size = sizeof(struct pair),
    .max_entries = 32768,
};

static __always_inline int get_sport(void *trans_data, void *data_end,
        __u8 protocol)
{
    struct tcphdr *th;
    struct udphdr *uh;

    switch (protocol) {
        case IPPROTO_TCP:
            th = (struct tcphdr *)trans_data;
            if ((void *)(th + 1) > data_end)
                return -1;
            return th->source;
        case IPPROTO_UDP:
            uh = (struct udphdr *)trans_data;
            if ((void *)(uh + 1) > data_end)
                return -1;
            return uh->dest;
        default:
            return 0;
    }
}

static __always_inline int get_dport(void *trans_data, void *data_end,
        __u8 protocol)
{
    struct tcphdr *th;
    struct udphdr *uh;

    switch (protocol) {
        case IPPROTO_TCP:
            th = (struct tcphdr *)trans_data;
            if ((void *)(th + 1) > data_end)
                return -1;
            return th->dest;
        case IPPROTO_UDP:
            uh = (struct udphdr *)trans_data;
            if ((void *)(uh + 1) > data_end)
                return -1;
            return uh->dest;
        default:
            return 0;
    }
}

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

//#define DEBUG 1
#ifdef  DEBUG
/* Only use this for debug output. Notice output from  bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)                     \
        ({                          \
            char ____fmt[] = fmt;               \
            bpf_trace_printk(____fmt, sizeof(____fmt),  \
                     ##__VA_ARGS__);            \
        })
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif

/* Parse Ethernet layer 2, extract network layer 3 offset and protocol
 *
 * Returns false on error and non-supported ether-type
 */
static __always_inline
bool parse_eth(struct ethhdr *eth, void *data_end,
           u16 *eth_proto, u64 *l3_offset)
{
    u16 eth_type;
    u64 offset;

    offset = sizeof(*eth);
    if ((void *)eth + offset > data_end)
        return false;

    eth_type = eth->h_proto;
    //bpf_debug("Debug: eth_type:0x%x\n", ntohs(eth_type));

    /* Skip non 802.3 Ethertypes */
    if (unlikely(ntohs(eth_type) < ETH_P_802_3_MIN))
        return false;

    /* Handle VLAN tagged packet */
    if (eth_type == htons(ETH_P_8021Q) || eth_type == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vlan_hdr;

        vlan_hdr = (void *)eth + offset;
        offset += sizeof(*vlan_hdr);
        if ((void *)eth + offset > data_end)
            return false;
        eth_type = vlan_hdr->h_vlan_encapsulated_proto;
    }
    /* TODO: Handle double VLAN tagged packet */

    *eth_proto = ntohs(eth_type);
    *l3_offset = offset;
    return true;
}

static __always_inline
u32 parse_ipv4(struct xdp_md *ctx, u64 l3_offset)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct iphdr *iph = data + l3_offset;

    if (iph + 1 > data_end) {
        bpf_debug("Invalid IPv4 packet: L3off:%llu\n", l3_offset);
        return XDP_ABORTED;
    }

    int sport, dport;
    struct flowv4_keys tuple;
    struct pair *value;
    struct pair new_value;

    tuple.ip_proto = (__u32) iph->protocol;
    tuple.src = iph->saddr;
    tuple.dst = iph->daddr;

    dport = get_dport(iph + 1, data_end, iph->protocol);
    if (dport == -1)
        return XDP_PASS;

    sport = get_sport(iph + 1, data_end, iph->protocol);
    if (sport == -1)
        return XDP_PASS;

    tuple.port16[0] = (__u16)sport;
    tuple.port16[1] = (__u16)dport;
    value = bpf_map_lookup_elem(&flow_table_v4, &tuple);

    if(value) {
        //bpf_debug("Found flow v4: %u -> %u %d\n", tuple.src, tuple.dst, dport);
        //bpf_debug("Data: t:%lu p:%lu n:%lu\n", value->time, value->packets, value->bytes);

        value->time = bpf_ktime_get_ns();
        value->packets++;
        value->bytes += data_end - data;
        if (value->packets > 1000 || value->bytes > 128*1024)
            return XDP_DROP;
    } else {
        new_value.time = bpf_ktime_get_ns();
        new_value.packets = 0;
        new_value.bytes = 0;
        bpf_debug("New flow v4: %u -> %u %d\n", tuple.src, tuple.dst, dport);
        bpf_map_update_elem(&flow_table_v4, &tuple, &new_value, BPF_NOEXIST);
    }
    return XDP_PASS;
}

static __always_inline
u32 handle_eth_protocol(struct xdp_md *ctx, u16 eth_proto, u64 l3_offset)
{
    switch (eth_proto) {
    case ETH_P_IP:
        return parse_ipv4(ctx, l3_offset);
        break;
    case ETH_P_IPV6: /* Not handler for IPv6 yet*/
    case ETH_P_ARP:  /* Let OS handle ARP */
        /* Fall-through */
    default:
        //bpf_debug("Not handling eth_proto:0x%x\n", eth_proto);
        return XDP_PASS;
    }
    return XDP_PASS;
}


SEC("xdp_ttl")
int  xdp_ttl_program(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    u16 eth_proto = 0;
    u64 l3_offset = 0;
    u32 action;

    if (!(parse_eth(eth, data_end, &eth_proto, &l3_offset))) {
        bpf_debug("Cannot parse L2: L3off:%llu proto:0x%x\n",
              l3_offset, eth_proto);
        return XDP_PASS; /* Skip */
    }

    //bpf_debug("Reached L3: L3off:%llu proto:0x%x\n", l3_offset, eth_proto);

    action = handle_eth_protocol(ctx, eth_proto, l3_offset);
    return action;
}

char _license[] SEC("license") = "GPL";
